"""Notification engine for PHANTOM.

Supports webhook (POST JSON), email (SMTP), and Telegram bot notifications.
Settings stored in Redis: phantom:settings:notifications
History stored in Redis list: phantom:notifications:history (last 100)
"""

import json
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SETTINGS_KEY = "phantom:settings:notifications"
HISTORY_KEY = "phantom:notifications:history"
HISTORY_MAX = 100


def _get_redis():
    import redis as redis_lib
    from app.config import get_settings
    settings = get_settings()
    return redis_lib.from_url(settings.redis_url, decode_responses=True)


def get_notification_settings() -> dict:
    """Load notification settings from Redis."""
    try:
        r = _get_redis()
        raw = r.get(SETTINGS_KEY)
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning(f"Failed to load notification settings: {e}")
    return {
        "enabled_channels": [],
        "webhook_url": "",
        "email_to": "",
        "email_from": "",
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "smtp_tls": True,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "notify_critical": True,
        "notify_high": True,
        "notify_scan_complete": True,
        "notify_new_finding": False,
    }


def save_notification_settings(settings: dict):
    """Save notification settings to Redis."""
    r = _get_redis()
    r.set(SETTINGS_KEY, json.dumps(settings))


def _record_history(channel: str, event_type: str, summary: str, success: bool, error: str | None = None):
    """Store a notification record in Redis (last 100)."""
    try:
        r = _get_redis()
        entry = {
            "channel": channel,
            "event_type": event_type,
            "summary": summary,
            "success": success,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r.lpush(HISTORY_KEY, json.dumps(entry))
        r.ltrim(HISTORY_KEY, 0, HISTORY_MAX - 1)
    except Exception as e:
        logger.debug(f"Failed to record notification history: {e}")


def get_notification_history(limit: int = 100) -> list[dict]:
    """Return the last N notification history entries."""
    try:
        r = _get_redis()
        raw_list = r.lrange(HISTORY_KEY, 0, limit - 1)
        return [json.loads(item) for item in raw_list]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Channel senders
# ---------------------------------------------------------------------------

def _send_webhook(url: str, payload: dict, event_type: str):
    """POST JSON payload to a webhook URL."""
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(url, json=payload, headers={"Content-Type": "application/json"})
            resp.raise_for_status()
        _record_history("webhook", event_type, payload.get("summary", ""), True)
    except Exception as e:
        logger.error(f"Webhook notification failed: {e}")
        _record_history("webhook", event_type, payload.get("summary", ""), False, str(e))


def _send_email(settings: dict, subject: str, body: str, event_type: str):
    """Send an email via SMTP."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.get("email_from", settings.get("smtp_user", ""))
        msg["To"] = settings["email_to"]
        msg.attach(MIMEText(body, "plain"))

        host = settings.get("smtp_host", "")
        port = int(settings.get("smtp_port", 587))
        use_tls = settings.get("smtp_tls", True)

        if use_tls:
            ctx = ssl.create_default_context()
            server = smtplib.SMTP(host, port)
            server.starttls(context=ctx)
        else:
            server = smtplib.SMTP(host, port)

        user = settings.get("smtp_user", "")
        pwd = settings.get("smtp_password", "")
        if user and pwd:
            server.login(user, pwd)

        server.sendmail(msg["From"], [settings["email_to"]], msg.as_string())
        server.quit()
        _record_history("email", event_type, subject, True)
    except Exception as e:
        logger.error(f"Email notification failed: {e}")
        _record_history("email", event_type, subject, False, str(e))


def _send_telegram(bot_token: str, chat_id: str, text: str, event_type: str):
    """Send a message via Telegram Bot API."""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        with httpx.Client(timeout=10) as client:
            resp = client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
            })
            resp.raise_for_status()
        _record_history("telegram", event_type, text[:120], True)
    except Exception as e:
        logger.error(f"Telegram notification failed: {e}")
        _record_history("telegram", event_type, text[:120], False, str(e))


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------

def _dispatch(event_type: str, webhook_payload: dict, subject: str, body_text: str, telegram_text: str):
    """Send notification to all enabled channels."""
    settings = get_notification_settings()
    channels = settings.get("enabled_channels", [])

    if "webhook" in channels and settings.get("webhook_url"):
        _send_webhook(settings["webhook_url"], webhook_payload, event_type)

    if "email" in channels and settings.get("email_to") and settings.get("smtp_host"):
        _send_email(settings, subject, body_text, event_type)

    if "telegram" in channels and settings.get("telegram_bot_token") and settings.get("telegram_chat_id"):
        _send_telegram(settings["telegram_bot_token"], settings["telegram_chat_id"], telegram_text, event_type)


# ---------------------------------------------------------------------------
# Public notification methods
# ---------------------------------------------------------------------------

def _severity_val(obj: Any) -> str:
    """Extract severity string from model or dict."""
    if isinstance(obj, dict):
        s = obj.get("severity", "unknown")
    else:
        s = getattr(obj, "severity", "unknown")
    return s.value if hasattr(s, "value") else str(s)


def _vuln_type_val(obj: Any) -> str:
    if isinstance(obj, dict):
        vt = obj.get("vuln_type", "unknown")
    else:
        vt = getattr(obj, "vuln_type", "unknown")
    return vt.value if hasattr(vt, "value") else str(vt)


def _get_field(obj: Any, field: str, default: str = "") -> str:
    if isinstance(obj, dict):
        return str(obj.get(field, default))
    return str(getattr(obj, field, default))


def notify_critical_vuln(vuln, target, scan=None):
    """Send alert for critical/high severity vulnerabilities."""
    settings = get_notification_settings()
    severity = _severity_val(vuln)
    if severity.upper() == "CRITICAL" and not settings.get("notify_critical", True):
        return
    if severity.upper() == "HIGH" and not settings.get("notify_high", True):
        return
    if severity.upper() not in ("CRITICAL", "HIGH"):
        return

    domain = _get_field(target, "domain")
    title = _get_field(vuln, "title", "Untitled")
    url = _get_field(vuln, "url")
    vtype = _vuln_type_val(vuln)
    scan_id = _get_field(scan, "id") if scan else ""

    webhook_payload = {
        "event": "critical_vuln",
        "summary": f"[{severity.upper()}] {title} on {domain}",
        "severity": severity,
        "vuln_type": vtype,
        "title": title,
        "url": url,
        "domain": domain,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    subject = f"PHANTOM Alert: [{severity.upper()}] {title} on {domain}"
    body = (
        f"PHANTOM Security Alert\n"
        f"{'=' * 40}\n\n"
        f"Severity: {severity.upper()}\n"
        f"Vulnerability: {title}\n"
        f"Type: {vtype}\n"
        f"Target: {domain}\n"
        f"URL: {url}\n"
        f"Scan: {scan_id}\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )

    telegram = (
        f"<b>PHANTOM Alert</b>\n"
        f"<b>{severity.upper()}</b>: {title}\n"
        f"Target: {domain}\n"
        f"Type: {vtype}\n"
        f"URL: {url}"
    )

    _dispatch("critical_vuln", webhook_payload, subject, body, telegram)


def notify_scan_complete(scan, target, vulns_count: int):
    """Send notification when a scan finishes."""
    settings = get_notification_settings()
    if not settings.get("notify_scan_complete", True):
        return

    domain = _get_field(target, "domain")
    scan_id = _get_field(scan, "id")
    scan_type = _get_field(scan, "scan_type", "full")
    if hasattr(scan_type, "value"):
        scan_type = scan_type.value

    webhook_payload = {
        "event": "scan_complete",
        "summary": f"Scan complete on {domain}: {vulns_count} vulnerabilities found",
        "domain": domain,
        "scan_id": scan_id,
        "scan_type": scan_type,
        "vulns_count": vulns_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    subject = f"PHANTOM: Scan complete on {domain} ({vulns_count} vulns)"
    body = (
        f"PHANTOM Scan Complete\n"
        f"{'=' * 40}\n\n"
        f"Target: {domain}\n"
        f"Scan Type: {scan_type}\n"
        f"Scan ID: {scan_id}\n"
        f"Vulnerabilities Found: {vulns_count}\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )

    telegram = (
        f"<b>PHANTOM Scan Complete</b>\n"
        f"Target: {domain}\n"
        f"Type: {scan_type}\n"
        f"Vulnerabilities: {vulns_count}"
    )

    _dispatch("scan_complete", webhook_payload, subject, body, telegram)


def notify_new_finding(vuln, target):
    """Send notification for any new finding (if enabled)."""
    settings = get_notification_settings()
    if not settings.get("notify_new_finding", False):
        return

    domain = _get_field(target, "domain")
    severity = _severity_val(vuln)
    title = _get_field(vuln, "title", "Untitled")
    url = _get_field(vuln, "url")
    vtype = _vuln_type_val(vuln)

    webhook_payload = {
        "event": "new_finding",
        "summary": f"New finding on {domain}: {title}",
        "severity": severity,
        "vuln_type": vtype,
        "title": title,
        "url": url,
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    subject = f"PHANTOM: New finding on {domain} — {title}"
    body = (
        f"PHANTOM New Finding\n"
        f"{'=' * 40}\n\n"
        f"Target: {domain}\n"
        f"Severity: {severity}\n"
        f"Vulnerability: {title}\n"
        f"Type: {vtype}\n"
        f"URL: {url}\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )

    telegram = (
        f"<b>PHANTOM New Finding</b>\n"
        f"[{severity.upper()}] {title}\n"
        f"Target: {domain}\n"
        f"URL: {url}"
    )

    _dispatch("new_finding", webhook_payload, subject, body, telegram)


def send_test_notification():
    """Send a test notification to all enabled channels. Returns results per channel."""
    settings = get_notification_settings()
    channels = settings.get("enabled_channels", [])
    results: dict[str, dict] = {}

    test_payload = {
        "event": "test",
        "summary": "PHANTOM test notification",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    test_subject = "PHANTOM: Test Notification"
    test_body = (
        f"PHANTOM Test Notification\n"
        f"{'=' * 40}\n\n"
        f"This is a test notification from PHANTOM.\n"
        f"If you received this, your notification channel is configured correctly.\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
    )
    test_telegram = (
        "<b>PHANTOM Test Notification</b>\n"
        "Your Telegram notifications are working correctly."
    )

    if "webhook" in channels and settings.get("webhook_url"):
        try:
            _send_webhook(settings["webhook_url"], test_payload, "test")
            results["webhook"] = {"success": True}
        except Exception as e:
            results["webhook"] = {"success": False, "error": str(e)}

    if "email" in channels and settings.get("email_to") and settings.get("smtp_host"):
        try:
            _send_email(settings, test_subject, test_body, "test")
            results["email"] = {"success": True}
        except Exception as e:
            results["email"] = {"success": False, "error": str(e)}

    if "telegram" in channels and settings.get("telegram_bot_token") and settings.get("telegram_chat_id"):
        try:
            _send_telegram(
                settings["telegram_bot_token"],
                settings["telegram_chat_id"],
                test_telegram,
                "test",
            )
            results["telegram"] = {"success": True}
        except Exception as e:
            results["telegram"] = {"success": False, "error": str(e)}

    if not results:
        results["message"] = {"success": False, "error": "No channels enabled or configured"}

    return results
