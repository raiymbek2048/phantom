"""PHANTOM Telegram Bot — AI-powered pentesting assistant.

Talk naturally in Telegram, Claude figures out what to do.
"""
import asyncio
import logging
import os

from telegram import Update, BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

from phantom_api import PhantomAPI
from ai_agent import PhantomAgent
from notifier import ScanNotifier
from auth_bridge import AuthBridge

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("phantom_bot")

# --- Config ---
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
PHANTOM_URL = os.environ.get("PHANTOM_URL", "http://backend:8000")
PHANTOM_USER = os.environ.get("PHANTOM_USER", "admin")
PHANTOM_PASS = os.environ.get("PHANTOM_PASS", "changeme")
ALLOWED_USERS = os.environ.get("ALLOWED_USERS", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

# Claude config — bot gets key from PHANTOM's Redis (same as backend)
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")

api = PhantomAPI(PHANTOM_URL, PHANTOM_USER, PHANTOM_PASS)
agent: PhantomAgent | None = None
auth_bridge: AuthBridge | None = None

# Chat IDs that have sent /start — used for notifier
active_chat_ids: set[int] = set()


def _is_allowed(update: Update) -> bool:
    if not ALLOWED_USERS:
        return True
    allowed = {int(uid.strip()) for uid in ALLOWED_USERS.split(",") if uid.strip()}
    return update.effective_user and update.effective_user.id in allowed


def _get_claude_key() -> tuple[str, bool] | None:
    """Get Claude API key from PHANTOM's Redis."""
    try:
        import redis as redis_lib
        r = redis_lib.from_url(REDIS_URL)

        # 1. OAuth token (preferred — free with Max subscription)
        oauth = r.get("phantom:settings:claude_oauth_token")
        if oauth:
            oauth = oauth.decode() if isinstance(oauth, bytes) else oauth
            if oauth.startswith("sk-ant-oat"):
                r.close()
                return (oauth, True)

        # 2. API key from Redis
        key = r.get("phantom:settings:anthropic_api_key")
        if key:
            key = key.decode() if isinstance(key, bytes) else key
            if key.startswith("sk-ant-") and not key.startswith("sk-ant-oat"):
                r.close()
                return (key, False)

        r.close()
    except Exception as e:
        logger.error(f"Redis key lookup failed: {e}")

    # 3. Env fallback
    env_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if env_key and not env_key.startswith("your_"):
        return (env_key, False)

    return None


SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

# Active scan monitors (scan_id -> task)
_monitors: dict[str, asyncio.Task] = {}


async def _monitor_scan_loop(bot, chat_id: int, scan_id: str, interval: int):
    """Background loop: sends scan progress updates, then final summary."""
    prev_phase = None
    prev_vulns = 0
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                scan = await api.get_scan(scan_id)
            except Exception as e:
                await bot.send_message(chat_id, f"⚠️ Не могу получить статус скана: {e}")
                break

            status = scan.get("status", "?").upper()
            phase = scan.get("current_phase", "?")
            progress = scan.get("progress_percent", scan.get("progress", 0)) or 0
            vulns = scan.get("vulns_found", 0) or 0
            target = scan.get("target_name", scan.get("target_domain", scan.get("domain", "?")))

            new_vulns_text = f" (+{vulns - prev_vulns} new)" if vulns > prev_vulns else ""
            changed = "🔄" if (phase != prev_phase or vulns != prev_vulns) else "⏳"
            text = (
                f"{changed} <b>Scan Update</b>\n"
                f"Target: {target}\n"
                f"Phase: <code>{phase}</code> | Progress: {progress}%\n"
                f"Vulns: {vulns}{new_vulns_text}"
            )
            try:
                await bot.send_message(chat_id, text, parse_mode="HTML")
            except Exception:
                pass
            prev_phase = phase
            prev_vulns = vulns

            if status in ("COMPLETED", "FAILED", "STOPPED"):
                # Final summary
                if status == "COMPLETED":
                    # Get vuln breakdown
                    try:
                        all_vulns = await api.list_vulns(limit=100)
                        scan_vulns = [v for v in all_vulns if str(v.get("scan_id", "")) == scan_id]
                        by_sev = {}
                        for v in scan_vulns:
                            s = v.get("severity", "info")
                            by_sev[s] = by_sev.get(s, 0) + 1
                        sev_text = " | ".join(f"{SEVERITY_EMOJI.get(s, '⚪')}{s}: {c}" for s, c in sorted(by_sev.items()))
                        text = (
                            f"✅ <b>Scan Complete!</b>\n\n"
                            f"Target: {target}\n"
                            f"Total vulns: <b>{vulns}</b>\n"
                            f"{sev_text}\n\n"
                            f"Напиши «покажи уязвимости» или «скинь отчёт» для деталей."
                        )
                    except Exception:
                        text = f"✅ <b>Scan Complete!</b>\nTarget: {target}\nVulns: {vulns}"
                elif status == "FAILED":
                    text = f"❌ <b>Scan Failed</b>\nTarget: {target}"
                else:
                    text = f"🛑 <b>Scan Stopped</b>\nTarget: {target}\nVulns found so far: {vulns}"

                try:
                    await bot.send_message(chat_id, text, parse_mode="HTML")
                except Exception:
                    pass
                break
    except asyncio.CancelledError:
        pass
    finally:
        _monitors.pop(scan_id, None)


async def _send_response(update: Update, response: dict):
    """Send a single response item (text or file)."""
    if response["type"] == "text":
        text = response["text"]
        # Split long messages
        for i in range(0, len(text), 4000):
            chunk = text[i:i + 4000]
            try:
                await update.message.reply_text(chunk, parse_mode="HTML")
            except Exception:
                # HTML parse error — send as plain text
                await update.message.reply_text(chunk)
    elif response["type"] == "file":
        path = response.get("path")
        if path and os.path.exists(path):
            caption = response.get("caption", "PHANTOM Report")
            with open(path, "rb") as f:
                if path.endswith(".pdf"):
                    await update.message.reply_document(f, caption=caption, filename="phantom_report.pdf")
                else:
                    await update.message.reply_document(f, caption=caption, filename="phantom_report.html")
            os.unlink(path)  # cleanup
        else:
            await update.message.reply_text("❌ Не удалось скачать файл отчёта.")
    elif response["type"] == "monitor":
        scan_id = response["scan_id"]
        interval = response.get("interval", 30)
        if scan_id in _monitors:
            await update.message.reply_text(f"📡 Мониторинг скана уже запущен.")
        else:
            task = asyncio.create_task(
                _monitor_scan_loop(
                    update.get_bot(),
                    update.effective_chat.id,
                    scan_id,
                    interval,
                )
            )
            _monitors[scan_id] = task
            await update.message.reply_text(f"📡 Мониторинг запущен — обновления каждые {interval}с.")


# --- Handlers ---

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        await update.message.reply_text("⛔ Access denied.")
        return
    active_chat_ids.add(update.effective_chat.id)
    text = (
        "👻 <b>PHANTOM AI Assistant</b>\n\n"
        "Я — ИИ-помощник для управления платформой пентестинга PHANTOM.\n\n"
        "Просто пиши мне на обычном языке:\n"
        "• <i>«Просканируй freelance.kg»</i>\n"
        "• <i>«Покажи уязвимости»</i>\n"
        "• <i>«Что сейчас запущено?»</i>\n"
        "• <i>«Скинь PDF отчёт по последнему скану»</i>\n"
        "• <i>«Какие критические баги нашли?»</i>\n"
        "• <i>«Запусти автопилот»</i>\n"
        "• <i>«Покажи статистику»</i>\n\n"
        "Команды тоже работают: /status /vulns /dashboard /clear\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Clear conversation history."""
    if not _is_allowed(update):
        return
    if agent:
        agent.clear_history(update.effective_chat.id)
    await update.message.reply_text("🧹 История очищена.")


async def handle_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Main handler — all text goes through Claude AI agent."""
    if not _is_allowed(update):
        return
    if not update.message or not update.message.text:
        return

    active_chat_ids.add(update.effective_chat.id)
    user_text = update.message.text.strip()
    if not user_text:
        return

    # Check if this is a response to an auth request
    if auth_bridge and auth_bridge.has_pending:
        if auth_bridge.try_handle_auth_response(update.effective_chat.id, user_text):
            await update.message.reply_text("✅ Данные получены. PHANTOM продолжает работу...")
            return

    if not agent:
        await update.message.reply_text("❌ AI Agent not initialized. Check Claude API key.")
        return

    # Show typing indicator
    await update.message.chat.send_action("typing")

    try:
        responses = await agent.process_message(
            update.effective_chat.id,
            user_text,
            _get_claude_key,
        )
        if not responses:
            await update.message.reply_text("🤔 Нет ответа от AI. Попробуй переформулировать.")
            return

        for resp in responses:
            await _send_response(update, resp)

    except Exception as e:
        logger.error(f"Agent error: {e}", exc_info=True)
        await update.message.reply_text(f"❌ Ошибка: {str(e)[:500]}")


# Quick commands — also go through AI but with preset text
async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    update.message.text = "Покажи текущие запущенные сканы и их прогресс"
    await handle_message(update, ctx)


async def cmd_vulns(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    severity = ctx.args[0] if ctx.args else ""
    update.message.text = f"Покажи последние уязвимости {severity}".strip()
    await handle_message(update, ctx)


async def cmd_dashboard(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    update.message.text = "Покажи общую статистику PHANTOM: цели, сканы, уязвимости"
    await handle_message(update, ctx)


async def cmd_health(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    update.message.text = "Проверь здоровье системы и статус Claude токена"
    await handle_message(update, ctx)


async def post_init(app: Application):
    """Initialize agent and notifier."""
    global agent

    agent = PhantomAgent(api, "https://api.anthropic.com", "", CLAUDE_MODEL, redis_url=REDIS_URL)
    logger.info(f"AI Agent initialized, model: {CLAUDE_MODEL}")

    # Test key availability
    key_info = _get_claude_key()
    if key_info:
        key, is_oauth = key_info
        logger.info(f"Claude key found: {'OAuth' if is_oauth else 'API key'} ({key[:20]}...)")
    else:
        logger.warning("No Claude API key found! Bot will not be able to respond.")

    # Start notifier and auth bridge
    if ALLOWED_USERS:
        chat_ids = {int(uid.strip()) for uid in ALLOWED_USERS.split(",") if uid.strip()}
    else:
        chat_ids = set()

    if chat_ids:
        notifier = ScanNotifier(app.bot, chat_ids, REDIS_URL)
        asyncio.create_task(notifier.start())
        logger.info(f"Notifier started for {chat_ids}")

        global auth_bridge
        auth_bridge = AuthBridge(app.bot, chat_ids, REDIS_URL)
        asyncio.create_task(auth_bridge.start())
        logger.info(f"AuthBridge started for {chat_ids}")

    await app.bot.set_my_commands([
        BotCommand("start", "Start / Help"),
        BotCommand("status", "Running scans"),
        BotCommand("vulns", "Recent vulnerabilities"),
        BotCommand("dashboard", "Stats overview"),
        BotCommand("health", "System health"),
        BotCommand("clear", "Clear conversation"),
    ])
    logger.info("PHANTOM Telegram bot started!")


def main():
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set!")
        return

    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("clear", cmd_clear))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("vulns", cmd_vulns))
    app.add_handler(CommandHandler("dashboard", cmd_dashboard))
    app.add_handler(CommandHandler("health", cmd_health))

    # ALL text goes through AI agent
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info(f"Starting bot, PHANTOM: {PHANTOM_URL}, Model: {CLAUDE_MODEL}")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
