"""Background notifier — polls PHANTOM for scan completions and critical vulns."""
import asyncio
import logging
import time
import redis as redis_lib

logger = logging.getLogger("phantom_notifier")

SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
}


class ScanNotifier:
    """Polls Redis for scan events and sends Telegram notifications."""

    def __init__(self, bot, chat_ids: set[int], redis_url: str = "redis://redis:6379/0"):
        self.bot = bot
        self.chat_ids = chat_ids
        self.redis_url = redis_url
        self._seen_scans: set[str] = set()
        self._seen_vulns: set[str] = set()
        self._running = False

    async def start(self):
        self._running = True
        logger.info(f"Notifier started, watching for events (chat_ids: {self.chat_ids})")
        while self._running:
            try:
                await self._check_events()
            except Exception as e:
                logger.error(f"Notifier error: {e}")
            await asyncio.sleep(15)

    def stop(self):
        self._running = False

    async def _check_events(self):
        r = redis_lib.from_url(self.redis_url)

        # Check for scan completion notifications
        while True:
            event = r.lpop("phantom:telegram:scan_events")
            if not event:
                break
            import json
            data = json.loads(event)
            event_type = data.get("type")
            scan_id = data.get("scan_id", "?")

            if scan_id in self._seen_scans:
                continue
            self._seen_scans.add(scan_id)

            if event_type == "scan_completed":
                vulns = data.get("vulns_found", 0)
                target = data.get("target_name", "?")
                critical = data.get("critical", 0)
                high = data.get("high", 0)
                text = (
                    f"✅ <b>Scan Complete</b>\n\n"
                    f"Target: {target}\n"
                    f"Scan: <code>{scan_id[:8]}</code>\n"
                    f"Findings: {vulns} total"
                )
                if critical:
                    text += f"\n🔴 Critical: {critical}"
                if high:
                    text += f"\n🟠 High: {high}"
                await self._broadcast(text)

            elif event_type == "scan_failed":
                target = data.get("target_name", "?")
                error = data.get("error", "Unknown")
                await self._broadcast(
                    f"❌ <b>Scan Failed</b>\n\n"
                    f"Target: {target}\n"
                    f"Error: {error[:200]}"
                )

        # Check for critical vuln alerts
        while True:
            event = r.lpop("phantom:telegram:vuln_alerts")
            if not event:
                break
            import json
            data = json.loads(event)
            vuln_id = data.get("vuln_id", "?")
            if vuln_id in self._seen_vulns:
                continue
            self._seen_vulns.add(vuln_id)

            sev = data.get("severity", "?")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            await self._broadcast(
                f"{emoji} <b>New {sev.upper()} Vulnerability!</b>\n\n"
                f"Type: {data.get('vuln_type', '?')}\n"
                f"URL: <code>{data.get('url', '?')[:80]}</code>\n"
                f"Title: {data.get('title', '?')[:100]}\n"
                f"\nUse /vuln {vuln_id[:8]} for details"
            )

        r.close()

        # Trim seen sets
        if len(self._seen_scans) > 500:
            self._seen_scans = set(list(self._seen_scans)[-200:])
        if len(self._seen_vulns) > 1000:
            self._seen_vulns = set(list(self._seen_vulns)[-500:])

    async def _broadcast(self, text: str):
        for chat_id in self.chat_ids:
            try:
                await self.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")
            except Exception as e:
                logger.error(f"Failed to send to {chat_id}: {e}")
