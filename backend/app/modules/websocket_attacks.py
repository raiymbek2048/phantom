"""
WebSocket Security Testing Module

Tests for:
1. Cross-Site WebSocket Hijacking (CSWSH) — missing Origin validation
2. WebSocket injection (SQLi, XSS, command injection via WS messages)
3. Authentication bypass on WebSocket upgrade
4. Information leakage via WebSocket
5. Unencrypted WebSocket (ws:// instead of wss://)
"""
import asyncio
import json
import logging
import re
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Common WebSocket paths
WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/", "/api/ws", "/api/websocket",
    "/realtime", "/live", "/stream", "/events",
    "/cable", "/hub", "/signalr",
]

# Injection payloads for WebSocket messages
WS_INJECTION_PAYLOADS = {
    "xss": [
        '<script>alert("pHnT0m")</script>',
        '<img src=x onerror=alert("pHnT0m")>',
    ],
    "sqli": [
        "' OR 1=1--",
        "1' UNION SELECT null,null--",
    ],
    "cmd": [
        "; id",
        "| cat /etc/passwd",
        "`id`",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
    ],
}


class WebSocketModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        base_url = context.get("base_url", "")
        endpoints = context.get("endpoints", [])
        auth_cookie = context.get("auth_cookie")
        findings = []

        # Discover WebSocket endpoints
        ws_endpoints = await self._discover_ws_endpoints(base_url, endpoints)

        if not ws_endpoints:
            return findings

        # Check for CSWSH (Cross-Site WebSocket Hijacking)
        for ws_url in ws_endpoints:
            cswsh = await self._check_cswsh(ws_url, base_url, auth_cookie)
            findings.extend(cswsh)

        # Check for unencrypted WebSocket
        for ws_url in ws_endpoints:
            if ws_url.startswith("ws://") and not context.get("is_internal"):
                findings.append({
                    "title": f"Unencrypted WebSocket: {ws_url}",
                    "url": ws_url,
                    "severity": "medium",
                    "vuln_type": "misconfig",
                    "impact": "WebSocket uses ws:// instead of wss://. "
                             "All WebSocket traffic is transmitted in plaintext, "
                             "vulnerable to MITM attacks.",
                    "remediation": "Use wss:// (WebSocket Secure) for all WebSocket connections.",
                })

        # Check for WebSocket auth bypass
        for ws_url in ws_endpoints:
            auth_bypass = await self._check_ws_auth_bypass(ws_url)
            findings.extend(auth_bypass)

        # Check WebSocket injection
        for ws_url in ws_endpoints:
            injection = await self._check_ws_injection(ws_url, auth_cookie)
            findings.extend(injection)

        return findings

    async def _discover_ws_endpoints(self, base_url, endpoints) -> list[str]:
        """Find WebSocket endpoints via HTTP upgrade probing."""
        ws_endpoints = []
        parsed = urlparse(base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"

        # Check known WS paths
        async with make_client(timeout=5.0) as client:
            tasks = []
            for path in WS_PATHS:
                url = f"{base_url}{path}"
                tasks.append(self._probe_ws_endpoint(client, url, ws_scheme, parsed))

            # Also check endpoints that look like WebSocket paths
            for ep in endpoints[:30]:
                ep_url = ep if isinstance(ep, str) else ep.get("url", "")
                if any(k in ep_url.lower() for k in ("ws", "socket", "real", "live", "stream", "event")):
                    tasks.append(self._probe_ws_endpoint(client, ep_url, ws_scheme, parsed))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):
                    ws_endpoints.append(result)

        return list(set(ws_endpoints))

    async def _probe_ws_endpoint(self, client, url, ws_scheme, parsed) -> str | None:
        """Check if URL supports WebSocket upgrade."""
        try:
            async with self.rate_limit:
                resp = await client.get(
                    url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGVzdA==",
                        "Sec-WebSocket-Version": "13",
                    },
                )
                # 101 Switching Protocols = WebSocket endpoint
                if resp.status_code == 101:
                    ws_url = url.replace("https://", f"{ws_scheme}://").replace("http://", f"{ws_scheme}://")
                    return ws_url

                # Some servers return 400 with "upgrade required" — still a WS endpoint
                if resp.status_code == 400:
                    body = resp.text.lower()
                    if any(k in body for k in ("upgrade", "websocket", "ws")):
                        ws_url = url.replace("https://", f"{ws_scheme}://").replace("http://", f"{ws_scheme}://")
                        return ws_url

                # Check response headers for WebSocket indicators
                upgrade_header = resp.headers.get("upgrade", "").lower()
                if "websocket" in upgrade_header:
                    ws_url = url.replace("https://", f"{ws_scheme}://").replace("http://", f"{ws_scheme}://")
                    return ws_url

        except Exception:
            pass
        return None

    async def _check_cswsh(self, ws_url, base_url, auth_cookie) -> list[dict]:
        """Check for Cross-Site WebSocket Hijacking (missing Origin validation)."""
        findings = []
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

        try:
            async with make_client(timeout=5.0) as client:
                # Test with evil Origin
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGVzdA==",
                    "Sec-WebSocket-Version": "13",
                    "Origin": "https://evil.com",
                }
                if auth_cookie:
                    if auth_cookie.startswith("token="):
                        headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
                    else:
                        headers["Cookie"] = auth_cookie

                async with self.rate_limit:
                    resp = await client.get(http_url, headers=headers)

                    if resp.status_code == 101:
                        findings.append({
                            "title": f"Cross-Site WebSocket Hijacking: {urlparse(ws_url).path}",
                            "url": ws_url,
                            "severity": "high",
                            "vuln_type": "csrf",
                            "payload": "Origin: https://evil.com",
                            "impact": "WebSocket accepts connections from any Origin. "
                                     "Attacker can hijack WebSocket from a malicious page "
                                     "and perform actions as the victim.",
                            "remediation": "Validate the Origin header on WebSocket upgrade requests. "
                                          "Only accept connections from trusted origins.",
                        })

                    # Also test with null Origin
                    headers["Origin"] = "null"
                    async with self.rate_limit:
                        resp2 = await client.get(http_url, headers=headers)
                        if resp2.status_code == 101:
                            findings.append({
                                "title": f"CSWSH with null Origin: {urlparse(ws_url).path}",
                                "url": ws_url,
                                "severity": "high",
                                "vuln_type": "csrf",
                                "payload": "Origin: null",
                                "impact": "WebSocket accepts null Origin (e.g., from sandboxed iframes).",
                                "remediation": "Reject null Origin on WebSocket connections.",
                            })

        except Exception as e:
            logger.debug(f"CSWSH check error for {ws_url}: {e}")

        return findings

    async def _check_ws_auth_bypass(self, ws_url) -> list[dict]:
        """Check if WebSocket can be connected without authentication."""
        findings = []
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

        try:
            async with make_client(timeout=5.0) as client:
                # Try connecting without any auth
                async with self.rate_limit:
                    resp = await client.get(
                        http_url,
                        headers={
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "dGVzdA==",
                            "Sec-WebSocket-Version": "13",
                        },
                    )
                    if resp.status_code == 101:
                        findings.append({
                            "title": f"WebSocket No Authentication: {urlparse(ws_url).path}",
                            "url": ws_url,
                            "severity": "medium",
                            "vuln_type": "misconfig",
                            "impact": "WebSocket endpoint accepts connections without authentication. "
                                     "Any user can connect and potentially access real-time data.",
                            "remediation": "Require authentication token in WebSocket handshake "
                                          "(via cookie, query param, or first message).",
                        })

        except Exception:
            pass

        return findings

    async def _check_ws_injection(self, ws_url, auth_cookie) -> list[dict]:
        """Test WebSocket messages for injection vulnerabilities.
        Note: This uses HTTP-based probing since we can't do full WS in httpx.
        We test the HTTP endpoints that likely back the WebSocket."""
        findings = []

        # WebSocket endpoints often have HTTP API counterparts
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        parsed = urlparse(http_url)

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        # Try sending injection payloads as JSON messages to the HTTP endpoint
        async with make_client(timeout=5.0, extra_headers=headers) as client:
            for vuln_type, payloads in WS_INJECTION_PAYLOADS.items():
                for payload in payloads:
                    try:
                        # Send as JSON message (common WS format)
                        msg = {"message": payload, "type": "message", "data": payload}

                        async with self.rate_limit:
                            resp = await client.post(http_url, json=msg)
                            body = resp.text

                            if vuln_type == "xss" and "pHnT0m" in body:
                                findings.append({
                                    "title": f"WebSocket XSS Injection: {parsed.path}",
                                    "url": ws_url,
                                    "severity": "high",
                                    "vuln_type": "xss",
                                    "payload": payload,
                                    "impact": "XSS payload reflected in WebSocket response. "
                                             "Attacker can inject scripts via WebSocket messages.",
                                    "remediation": "Sanitize all WebSocket message content before rendering.",
                                })
                                break

                            if vuln_type == "sqli" and any(e in body.lower() for e in
                                    ("sql", "syntax", "mysql", "postgresql", "sqlite", "oracle")):
                                findings.append({
                                    "title": f"WebSocket SQLi: {parsed.path}",
                                    "url": ws_url,
                                    "severity": "high",
                                    "vuln_type": "sqli",
                                    "payload": payload,
                                    "impact": "SQL injection via WebSocket message.",
                                    "remediation": "Use parameterized queries for all DB operations.",
                                })
                                break

                    except Exception:
                        continue

        return findings
