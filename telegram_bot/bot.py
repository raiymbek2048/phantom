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
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-20250514")

api = PhantomAPI(PHANTOM_URL, PHANTOM_USER, PHANTOM_PASS)
agent: PhantomAgent | None = None

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

    agent = PhantomAgent(api, "https://api.anthropic.com", "", CLAUDE_MODEL)
    logger.info(f"AI Agent initialized, model: {CLAUDE_MODEL}")

    # Test key availability
    key_info = _get_claude_key()
    if key_info:
        key, is_oauth = key_info
        logger.info(f"Claude key found: {'OAuth' if is_oauth else 'API key'} ({key[:20]}...)")
    else:
        logger.warning("No Claude API key found! Bot will not be able to respond.")

    # Start notifier
    if ALLOWED_USERS:
        chat_ids = {int(uid.strip()) for uid in ALLOWED_USERS.split(",") if uid.strip()}
        if chat_ids:
            notifier = ScanNotifier(app.bot, chat_ids, REDIS_URL)
            asyncio.create_task(notifier.start())
            logger.info(f"Notifier started for {chat_ids}")

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
