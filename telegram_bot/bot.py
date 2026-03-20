"""PHANTOM Telegram Bot — manage scans, view vulns, get reports via Telegram."""
import asyncio
import logging
import os
import re
from datetime import datetime, timezone

from telegram import Update, BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from phantom_api import PhantomAPI
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
ALLOWED_USERS = os.environ.get("ALLOWED_USERS", "")  # comma-separated telegram user IDs
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

api = PhantomAPI(PHANTOM_URL, PHANTOM_USER, PHANTOM_PASS)

SEVERITY_EMOJI = {
    "critical": "\U0001f534",  # red circle
    "high": "\U0001f7e0",      # orange circle
    "medium": "\U0001f7e1",    # yellow circle
    "low": "\U0001f535",       # blue circle
    "info": "\u26aa",          # white circle
}


def _is_allowed(update: Update) -> bool:
    if not ALLOWED_USERS:
        return True
    allowed = {int(uid.strip()) for uid in ALLOWED_USERS.split(",") if uid.strip()}
    return update.effective_user and update.effective_user.id in allowed


def _escape_md(text: str) -> str:
    """Escape MarkdownV2 special characters."""
    special = r"_*[]()~`>#+-=|{}.!"
    return re.sub(f"([{re.escape(special)}])", r"\\\1", str(text))


async def _reply(update: Update, text: str, parse_mode: str = "HTML"):
    """Send reply, splitting if too long."""
    max_len = 4000
    for i in range(0, len(text), max_len):
        await update.message.reply_text(text[i:i + max_len], parse_mode=parse_mode)


# --- Command Handlers ---

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    text = (
        "<b>👻 PHANTOM Bot</b>\n\n"
        "AI-Powered Pentesting via Telegram.\n\n"
        "<b>Commands:</b>\n"
        "/scan &lt;url&gt; — Start a full scan\n"
        "/quick &lt;url&gt; — Quick scan\n"
        "/status — Running scans\n"
        "/targets — List targets\n"
        "/vulns [critical|high|medium] — Recent vulns\n"
        "/vuln &lt;id&gt; — Vulnerability details\n"
        "/stop &lt;scan_id&gt; — Stop a scan\n"
        "/dashboard — Stats overview\n"
        "/health — System health\n"
        "/h1 &lt;vuln_id&gt; — Generate HackerOne report\n"
        "/recon &lt;target_id&gt; — Recon data\n"
        "/token — Claude token status\n"
    )
    await _reply(update, text)


async def cmd_dashboard(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    try:
        stats = await api.get_stats()
        text = (
            "<b>📊 PHANTOM Dashboard</b>\n\n"
            f"🎯 Targets: <b>{stats.get('total_targets', 0)}</b>\n"
            f"🔍 Total scans: <b>{stats.get('total_scans', 0)}</b>\n"
            f"▶️ Running: <b>{stats.get('running_scans', 0)}</b>\n"
            f"⚠️ Vulnerabilities: <b>{stats.get('total_vulnerabilities', 0)}</b>\n"
            f"🔴 Critical: <b>{stats.get('critical_vulns', 0)}</b>\n"
            f"🟠 High: <b>{stats.get('high_vulns', 0)}</b>\n"
            f"🧠 KB Patterns: <b>{stats.get('kb_patterns', 0)}</b>\n"
        )
        await _reply(update, text)
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_targets(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    try:
        targets = await api.list_targets()
        if not targets:
            await _reply(update, "No targets yet. Use /scan &lt;url&gt; to add one.")
            return
        lines = ["<b>🎯 Targets</b>\n"]
        for t in targets[:20]:
            name = t.get("name", "?")
            url = t.get("url", "?")
            tid = str(t.get("id", ""))[:8]
            lines.append(f"• <code>{tid}</code> {name}\n  {url}")
        await _reply(update, "\n".join(lines))
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    if not ctx.args:
        await _reply(update, "Usage: /scan &lt;url&gt;\nExample: /scan https://example.com")
        return
    url = ctx.args[0]
    if not url.startswith("http"):
        url = f"https://{url}"
    scan_type = "full"
    try:
        await _reply(update, f"🚀 Creating target and starting <b>{scan_type}</b> scan for:\n<code>{url}</code>")
        # Find or create target
        targets = await api.list_targets()
        target = next((t for t in targets if t.get("url", "").rstrip("/") == url.rstrip("/")), None)
        if not target:
            target = await api.create_target(url)
            await _reply(update, f"✅ Target created: <code>{str(target['id'])[:8]}</code>")
        target_id = str(target["id"])
        # Start scan
        scan = await api.start_scan(target_id, scan_type)
        scan_id = str(scan.get("id", "?"))[:8]
        await _reply(update, f"✅ Scan started!\nID: <code>{scan_id}</code>\n\nUse /status to track progress.")
    except Exception as e:
        await _reply(update, f"❌ Failed to start scan: {e}")


async def cmd_quick(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    if not ctx.args:
        await _reply(update, "Usage: /quick &lt;url&gt;")
        return
    url = ctx.args[0]
    if not url.startswith("http"):
        url = f"https://{url}"
    try:
        targets = await api.list_targets()
        target = next((t for t in targets if t.get("url", "").rstrip("/") == url.rstrip("/")), None)
        if not target:
            target = await api.create_target(url)
        scan = await api.start_scan(str(target["id"]), "quick")
        scan_id = str(scan.get("id", "?"))[:8]
        await _reply(update, f"⚡ Quick scan started!\nID: <code>{scan_id}</code>")
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    try:
        queue = await api.get_scan_queue()
        running = queue.get("running", [])
        queued = queue.get("queued", [])
        if not running and not queued:
            await _reply(update, "✅ No active scans.")
            return
        lines = ["<b>📡 Active Scans</b>\n"]
        for s in running:
            sid = str(s.get("id", "?"))[:8]
            target = s.get("target_name", s.get("target_url", "?"))
            phase = s.get("current_phase", "?")
            progress = s.get("progress", 0)
            lines.append(f"▶️ <code>{sid}</code> {target}\n   Phase: {phase} | {progress}%")
        if queued:
            lines.append(f"\n⏳ Queued: {len(queued)}")
        await _reply(update, "\n".join(lines))
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    if not ctx.args:
        await _reply(update, "Usage: /stop &lt;scan_id&gt;")
        return
    scan_id = ctx.args[0]
    try:
        await api.stop_scan(scan_id)
        await _reply(update, f"🛑 Scan <code>{scan_id[:8]}</code> stopped.")
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_vulns(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    severity = ctx.args[0] if ctx.args else None
    try:
        vulns = await api.list_vulns(severity=severity, limit=15)
        if not vulns:
            await _reply(update, "No vulnerabilities found.")
            return
        lines = ["<b>⚠️ Vulnerabilities</b>\n"]
        for v in vulns[:15]:
            vid = str(v.get("id", "?"))[:8]
            sev = v.get("severity", "?")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            vtype = v.get("vuln_type", "?")
            title = v.get("title", "?")[:60]
            url = v.get("url", "")[:50]
            lines.append(f"{emoji} <code>{vid}</code> [{sev.upper()}] {vtype}\n   {title}\n   {url}")
        await _reply(update, "\n".join(lines))
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_vuln(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    if not ctx.args:
        await _reply(update, "Usage: /vuln &lt;vuln_id&gt;")
        return
    try:
        v = await api.get_vuln(ctx.args[0])
        sev = v.get("severity", "?")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        text = (
            f"{emoji} <b>{v.get('title', '?')}</b>\n\n"
            f"Type: {v.get('vuln_type', '?')}\n"
            f"Severity: {sev.upper()}\n"
            f"URL: <code>{v.get('url', '?')}</code>\n"
            f"Status: {v.get('status', '?')}\n"
        )
        if v.get("description"):
            text += f"\n📝 {v['description'][:500]}\n"
        if v.get("payload_used"):
            text += f"\n💉 Payload: <code>{v['payload_used'][:200]}</code>\n"
        if v.get("remediation"):
            text += f"\n🛡 Fix: {v['remediation'][:300]}\n"
        if v.get("cvss_score"):
            text += f"\nCVSS: {v['cvss_score']}\n"
        await _reply(update, text)
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_h1(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    if not ctx.args:
        await _reply(update, "Usage: /h1 &lt;vuln_id&gt;")
        return
    try:
        await _reply(update, "📝 Generating HackerOne report...")
        report = await api.generate_h1_report(ctx.args[0])
        title = report.get("title", "Report")
        body = report.get("report_body", report.get("body", str(report)))
        text = f"<b>📋 {title}</b>\n\n<pre>{body[:3500]}</pre>"
        await _reply(update, text)
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_recon(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    if not ctx.args:
        await _reply(update, "Usage: /recon &lt;target_id&gt;")
        return
    try:
        data = await api.get_target_recon(ctx.args[0])
        lines = ["<b>🔎 Recon Data</b>\n"]
        if data.get("subdomains"):
            subs = data["subdomains"][:10]
            lines.append(f"\n🌐 Subdomains ({len(data['subdomains'])}):")
            for s in subs:
                lines.append(f"  • {s}")
        if data.get("technologies"):
            lines.append(f"\n🛠 Technologies:")
            for t in data["technologies"][:15]:
                lines.append(f"  • {t}")
        if data.get("open_ports"):
            ports = data["open_ports"][:20]
            lines.append(f"\n🔌 Open ports: {', '.join(str(p) for p in ports)}")
        if data.get("endpoints"):
            lines.append(f"\n📡 Endpoints: {len(data['endpoints'])}")
        await _reply(update, "\n".join(lines))
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def cmd_health(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    try:
        h = await api.get_health()
        status = "✅" if h.get("status") == "healthy" else "⚠️"
        llm = h.get("llm_available", False)
        provider = h.get("llm_provider", "?")
        text = (
            f"<b>{status} System Health</b>\n\n"
            f"API: ✅ Online\n"
            f"LLM: {'✅' if llm else '❌'} {provider}\n"
        )
        await _reply(update, text)
    except Exception as e:
        await _reply(update, f"❌ API unreachable: {e}")


async def cmd_token(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update):
        return
    try:
        ts = await api.get_token_status()
        has_access = ts.get("has_access_token", False)
        has_refresh = ts.get("has_refresh_token", False)
        expires_h = ts.get("expires_in_hours", "?")
        source = ts.get("source", "?")
        text = (
            "<b>🔑 Claude Token Status</b>\n\n"
            f"Access token: {'✅' if has_access else '❌'}\n"
            f"Refresh token: {'✅' if has_refresh else '❌'}\n"
            f"Expires in: {expires_h}h\n"
            f"Source: {source}\n"
        )
        await _reply(update, text)
    except Exception as e:
        await _reply(update, f"❌ Error: {e}")


async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Handle plain text messages — try to understand intent."""
    if not _is_allowed(update):
        return
    text = update.message.text.strip().lower()

    # Simple pattern matching for natural language
    if any(w in text for w in ["scan", "сканируй", "проверь", "check", "атакуй"]):
        # Extract URL
        urls = re.findall(r'https?://\S+', update.message.text)
        if not urls:
            # Try bare domain
            domains = re.findall(r'(?:[\w-]+\.)+[a-z]{2,}', update.message.text)
            if domains:
                urls = [f"https://{domains[0]}"]
        if urls:
            ctx.args = [urls[0]]
            await cmd_scan(update, ctx)
            return

    if any(w in text for w in ["status", "статус", "что идёт", "running"]):
        await cmd_status(update, ctx)
        return

    if any(w in text for w in ["vuln", "уязвимост", "баг", "bug", "findings"]):
        await cmd_vulns(update, ctx)
        return

    if any(w in text for w in ["target", "цел", "сайт", "site"]):
        await cmd_targets(update, ctx)
        return

    if any(w in text for w in ["dashboard", "стат", "обзор", "overview"]):
        await cmd_dashboard(update, ctx)
        return

    if any(w in text for w in ["health", "здоров", "alive"]):
        await cmd_health(update, ctx)
        return

    await _reply(
        update,
        "🤔 Не понял. Попробуй:\n"
        "• <code>/scan https://example.com</code>\n"
        "• <code>/status</code>\n"
        "• <code>/vulns</code>\n"
        "• <code>/dashboard</code>\n"
        "• Или просто напиши URL для сканирования",
    )


async def post_init(app: Application):
    """Set bot commands menu and start notifier."""
    # Start background notifier for scan events
    if ALLOWED_USERS:
        chat_ids = {int(uid.strip()) for uid in ALLOWED_USERS.split(",") if uid.strip()}
    else:
        chat_ids = set()
    if chat_ids:
        notifier = ScanNotifier(app.bot, chat_ids, REDIS_URL)
        asyncio.create_task(notifier.start())
        logger.info(f"Notifier started for chat IDs: {chat_ids}")

    await app.bot.set_my_commands([
        BotCommand("scan", "Scan a website"),
        BotCommand("quick", "Quick scan"),
        BotCommand("status", "Running scans"),
        BotCommand("targets", "List targets"),
        BotCommand("vulns", "Recent vulnerabilities"),
        BotCommand("vuln", "Vulnerability details"),
        BotCommand("stop", "Stop a scan"),
        BotCommand("dashboard", "Stats overview"),
        BotCommand("health", "System health"),
        BotCommand("h1", "HackerOne report"),
        BotCommand("recon", "Recon data"),
        BotCommand("token", "Claude token status"),
    ])
    logger.info("PHANTOM Telegram bot started!")


def main():
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set!")
        return

    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

    # Command handlers
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("quick", cmd_quick))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("targets", cmd_targets))
    app.add_handler(CommandHandler("vulns", cmd_vulns))
    app.add_handler(CommandHandler("vuln", cmd_vuln))
    app.add_handler(CommandHandler("dashboard", cmd_dashboard))
    app.add_handler(CommandHandler("health", cmd_health))
    app.add_handler(CommandHandler("h1", cmd_h1))
    app.add_handler(CommandHandler("recon", cmd_recon))
    app.add_handler(CommandHandler("token", cmd_token))

    # Plain text — natural language
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info(f"Starting bot, PHANTOM API: {PHANTOM_URL}")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
