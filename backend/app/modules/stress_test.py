"""
Stress/Resilience Testing Module — Test rate limiting, concurrency handling, resource limits.

NOT a destructive DDoS tool. This module:
1. Tests if rate limiting is properly configured
2. Sends concurrent requests to find race conditions
3. Tests resource exhaustion (large payloads, deep recursion)
4. Validates error handling under load
5. Checks for slowloris-style timeout vulnerabilities

All tests are bounded and controlled — max ~100 concurrent requests.
"""
import asyncio
import logging
import time
from urllib.parse import urljoin, urlparse

import httpx

from app.utils.url_utils import is_static_url

logger = logging.getLogger(__name__)

# Endpoints to test (relative paths)
STRESS_ENDPOINTS = [
    "/", "/login", "/api/health", "/search", "/api/v1",
]


class StressTestModule:
    """Test target's resilience to concurrent requests and edge cases."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(20)

    async def run(self, context: dict) -> list[dict]:
        """Run all resilience tests."""
        findings = []
        base_url = context.get("base_url", "")
        if not base_url:
            return []

        # 1. Rate limiting test — focus on auth endpoints, skip static assets
        from app.utils.spa_detector import is_static_asset

        endpoints = context.get("endpoints", [])
        auth_keywords = ("login", "signin", "auth", "token", "register",
                         "signup", "password", "reset", "otp")

        # Prioritize auth endpoints for rate limit testing
        auth_urls = []
        other_urls = []
        for ep in endpoints:
            ep_url = ep.get("url") if isinstance(ep, dict) else ep
            if not ep_url or is_static_asset(ep_url):
                continue
            ep_lower = ep_url.lower()
            if any(kw in ep_lower for kw in auth_keywords):
                auth_urls.append(ep_url)
            elif len(other_urls) < 3:
                other_urls.append(ep_url)

        # Test auth endpoints with POST (correct method for login/register)
        for url in auth_urls[:3]:
            result = await self._test_rate_limiting(
                url, method="POST",
                post_body={"email": "test@test.com", "password": "wrong"})
            if result:
                findings.append(result)

        # Test base_url and a few other endpoints with GET
        for url in [base_url] + other_urls[:2]:
            result = await self._test_rate_limiting(url, method="GET")
            if result:
                findings.append(result)

        # 2. Concurrent request handling (race condition potential)
        race_results = await self._test_race_conditions(base_url, endpoints)
        findings.extend(race_results)

        # 3. Large payload handling
        payload_results = await self._test_large_payloads(base_url, endpoints)
        findings.extend(payload_results)

        # 4. Slowloris-style slow read test
        slowloris_result = await self._test_slow_connection(base_url)
        if slowloris_result:
            findings.append(slowloris_result)

        # 5. HTTP method fuzzing
        method_results = await self._test_http_methods(base_url, endpoints)
        findings.extend(method_results)

        logger.info(f"Stress test: {len(findings)} resilience issues found")
        return findings

    async def _test_rate_limiting(self, url: str, method: str = "GET",
                                   post_body: dict | None = None) -> dict | None:
        """Send rapid requests to test rate limiting.

        Only reports a finding if the server returns 200/201 on all requests
        (i.e. actually processes them). 403/401/429 responses mean protection
        is already in place — NOT a vulnerability.
        """
        from urllib.parse import urlparse
        path = urlparse(url).path.lower()

        # Skip endpoints where rate limiting is irrelevant
        skip_patterns = ("/health", "/healthz", "/status", "/ping", "/ready",
                         "/alive", "/favicon", "/robots.txt", "/sitemap")
        if any(path.endswith(p) or path == p for p in skip_patterns):
            return None

        # Skip static assets
        if is_static_url(url):
            return None

        num_requests = 20
        results = []

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            start = time.time()

            async def send_one(i):
                try:
                    headers = {"X-Test": f"stress-{i}",
                               "Content-Type": "application/json"}
                    if method == "POST" and post_body:
                        resp = await client.post(url, json=post_body, headers=headers)
                    else:
                        resp = await client.get(url, headers=headers)
                    return resp.status_code
                except Exception:
                    return 0

            tasks = [send_one(i) for i in range(num_requests)]
            results = await asyncio.gather(*tasks)

            elapsed = time.time() - start

        # Count response categories
        success = sum(1 for r in results if r in (200, 201))
        rate_limited = sum(1 for r in results if r == 429)
        blocked = sum(1 for r in results if r in (403, 401))
        errors = sum(1 for r in results if r >= 500)

        # If server blocks requests (403/401), that IS protection — not a vulnerability
        if blocked > 0:
            return None

        # Only report if ALL requests were processed successfully (no blocking at all)
        if success == num_requests and rate_limited == 0:
            rps = num_requests / elapsed if elapsed > 0 else 0
            # Determine severity based on endpoint type
            is_auth = any(kw in path for kw in ("/login", "/signin", "/auth",
                                                  "/token", "/register", "/signup",
                                                  "/password", "/reset", "/otp"))
            severity = "medium" if is_auth else "low"
            return {
                "title": f"No rate limiting on {'auth' if is_auth else ''} endpoint: {path}",
                "url": url,
                "severity": severity,
                "vuln_type": "misconfiguration",
                "payload": f"Sent {num_requests} concurrent {method} requests in {elapsed:.1f}s",
                "method": method,
                "impact": f"Endpoint processed all {num_requests} requests ({rps:.0f} req/s) "
                         f"with HTTP 200. No rate limiting, blocking, or throttling detected."
                         f"{' Brute-force attacks on credentials are possible.' if is_auth else ''}",
                "remediation": "Implement rate limiting (e.g., nginx limit_req, "
                              "application-level throttling). "
                              f"{'For auth endpoints: max 5 attempts per 15 minutes per IP.' if is_auth else 'Recommended: 10-30 req/s per IP.'}",
                "ai_confidence": 0.9 if is_auth else 0.7,
            }

        if errors > num_requests * 0.5:
            return {
                "title": f"Server errors under moderate load: {path}",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"{errors}/{num_requests} requests returned 5xx errors",
                "method": method,
                "impact": f"Server returned {errors} errors out of {num_requests} concurrent requests. "
                         f"The server may have stability issues under load.",
                "remediation": "Improve server capacity, add connection pooling, "
                              "and implement graceful degradation.",
                "ai_confidence": 0.5,
            }

        return None

    async def _test_race_conditions(self, base_url: str,
                                      endpoints: list) -> list[dict]:
        """Test for race conditions by sending identical requests simultaneously."""
        findings = []

        # Find form endpoints that might have race conditions
        form_endpoints = []
        for ep in endpoints:
            if isinstance(ep, dict):
                method = ep.get("method", "GET").upper()
                if method == "POST":
                    form_endpoints.append(ep)

        for ep in form_endpoints[:3]:
            url = ep.get("url", "")
            if not url:
                continue

            # Send 10 identical POST requests simultaneously
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                async def send_post():
                    try:
                        resp = await client.post(url, data={"test": "race_condition_check"})
                        return {
                            "status": resp.status_code,
                            "length": len(resp.text),
                            "headers": dict(resp.headers),
                        }
                    except Exception:
                        return None

                tasks = [send_post() for _ in range(10)]
                results = [r for r in await asyncio.gather(*tasks) if r]

            if len(results) < 5:
                continue

            # Analyze responses — different lengths/statuses might indicate race
            statuses = [r["status"] for r in results]
            lengths = [r["length"] for r in results]

            unique_statuses = set(statuses)
            length_variance = max(lengths) - min(lengths) if lengths else 0

            if len(unique_statuses) > 2 or length_variance > 500:
                findings.append({
                    "title": f"Inconsistent responses under concurrent requests",
                    "url": url,
                    "severity": "low",
                    "vuln_type": "misconfiguration",
                    "payload": f"10 concurrent POST requests → "
                              f"{len(unique_statuses)} different status codes, "
                              f"{length_variance} bytes length variance",
                    "method": "POST",
                    "impact": f"Endpoint returns inconsistent responses under concurrent load. "
                             f"Statuses: {unique_statuses}. "
                             f"This may indicate race condition vulnerabilities.",
                    "remediation": "Implement proper locking/mutex for state-changing operations. "
                                  "Use database transactions with appropriate isolation levels.",
                })

        return findings

    async def _test_large_payloads(self, base_url: str,
                                     endpoints: list) -> list[dict]:
        """Test how the server handles oversized payloads."""
        findings = []

        # Test large query string
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            # 1. Very long URL (8KB+ query string)
            long_param = "A" * 8192
            try:
                resp = await client.get(f"{base_url}/?q={long_param}")
                if resp.status_code == 200:
                    findings.append({
                        "title": "Server accepts very long query strings",
                        "url": base_url,
                        "severity": "low",
                        "vuln_type": "misconfiguration",
                        "payload": f"GET /?q={'A' * 20}... (8KB total)",
                        "method": "GET",
                        "impact": "Server accepted an 8KB query string without rejection. "
                                 "May be vulnerable to buffer overflow or memory exhaustion attacks.",
                        "remediation": "Configure maximum query string length in web server "
                                      "(e.g., LimitRequestLine in Apache, large_client_header_buffers in nginx).",
                    })
            except Exception:
                pass

            # 2. Large POST body (1MB)
            try:
                large_body = "x" * (1024 * 1024)
                resp = await client.post(base_url, content=large_body,
                                          headers={"Content-Type": "text/plain"})
                if resp.status_code not in (413, 414, 400):
                    findings.append({
                        "title": "Server accepts very large request bodies",
                        "url": base_url,
                        "severity": "low",
                        "vuln_type": "misconfiguration",
                        "payload": "POST with 1MB body",
                        "method": "POST",
                        "impact": f"Server accepted 1MB POST body (status: {resp.status_code}). "
                                 "No body size limit configured.",
                        "remediation": "Configure client_max_body_size (nginx) or "
                                      "LimitRequestBody (Apache) to reject oversized requests.",
                    })
            except Exception:
                pass

            # 3. Deeply nested JSON
            try:
                # Build 100-level deep JSON
                deep_json = {"a": "b"}
                for _ in range(100):
                    deep_json = {"nested": deep_json}
                resp = await client.post(base_url, json=deep_json)
                if resp.status_code == 200:
                    findings.append({
                        "title": "Server processes deeply nested JSON",
                        "url": base_url,
                        "severity": "low",
                        "vuln_type": "misconfiguration",
                        "payload": "100-level nested JSON object",
                        "method": "POST",
                        "impact": "Server processed deeply nested JSON without rejection. "
                                 "May be vulnerable to stack overflow or CPU exhaustion.",
                        "remediation": "Limit JSON nesting depth in the application "
                                      "or use a JSON parser with depth limits.",
                    })
            except Exception:
                pass

        return findings

    async def _test_slow_connection(self, base_url: str) -> dict | None:
        """Test if server is vulnerable to slow connection attacks (slowloris-like)."""
        # Open multiple connections and send data very slowly
        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        max_connections = 20

        async def slow_connect():
            """Returns number of seconds connection stayed alive with partial request."""
            try:
                if use_ssl:
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx), timeout=5
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=5
                    )

                # Send partial HTTP request (no \r\n\r\n terminator)
                writer.write(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n")
                await writer.drain()

                # Keep connection open for 10 seconds, sending headers slowly
                seconds_alive = 0
                for i in range(10):
                    await asyncio.sleep(1)
                    try:
                        writer.write(f"X-Slow-{i}: {'A' * 20}\r\n".encode())
                        await writer.drain()
                        seconds_alive += 1
                    except Exception:
                        break

                writer.close()
                return seconds_alive

            except Exception:
                return 0

        tasks = [slow_connect() for _ in range(max_connections)]
        results = await asyncio.gather(*tasks)

        # Count connections that stayed open for the full 10 seconds
        connections_held_full = sum(1 for secs in results if secs >= 9)
        connections_held_any = sum(1 for secs in results if secs > 0)

        # If most connections were closed early (< full duration), the server
        # has proper timeouts — this is NOT a vulnerability
        if connections_held_full < max_connections * 0.8:
            # Server timed out connections properly — not vulnerable
            return None

        # Only flag if connections were held for the FULL duration with
        # incomplete requests AND it's not just nginx default behavior (60s timeout)
        # 20 connections for 10s is trivially handled by any modern server
        if connections_held_full >= max_connections * 0.8:
            return {
                "title": "Vulnerable to slow HTTP attacks (Slowloris-style)",
                "url": base_url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"Held {connections_held_full}/{max_connections} slow connections for full 10s",
                "method": "GET",
                "impact": f"Server kept {connections_held_full} slow/incomplete connections alive "
                         f"for the full test duration. An attacker could exhaust connection pool "
                         f"with many slow connections, causing denial of service.",
                "remediation": "Configure timeouts: client_header_timeout (nginx), "
                              "RequestReadTimeout (Apache). Use a reverse proxy with "
                              "connection timeout enforcement. Consider mod_reqtimeout or "
                              "nginx limit_conn.",
            }

        return None

    async def _test_http_methods(self, base_url: str,
                                   endpoints: list) -> list[dict]:
        """Test for dangerous HTTP methods (PUT, DELETE, TRACE, etc.)."""
        findings = []
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

        test_urls = [base_url]
        for ep in endpoints[:3]:
            url = ep.get("url") if isinstance(ep, dict) else ep
            if url:
                test_urls.append(url)

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for url in test_urls[:3]:
                # OPTIONS check first
                try:
                    resp = await client.options(url)
                    allow = resp.headers.get("allow", "")
                    if allow:
                        allowed_methods = [m.strip().upper() for m in allow.split(",")]
                        dangerous_found = [m for m in dangerous_methods if m in allowed_methods]
                        if dangerous_found:
                            findings.append({
                                "title": f"Dangerous HTTP methods allowed: {', '.join(dangerous_found)}",
                                "url": url,
                                "severity": "medium" if "DELETE" in dangerous_found or "PUT" in dangerous_found else "low",
                                "vuln_type": "misconfiguration",
                                "payload": f"OPTIONS → Allow: {allow}",
                                "method": "OPTIONS",
                                "impact": f"Server allows {', '.join(dangerous_found)} methods. "
                                         f"PUT/DELETE could allow unauthorized file modification. "
                                         f"TRACE enables XST (Cross-Site Tracing) attacks.",
                                "remediation": "Disable unnecessary HTTP methods in web server config. "
                                              "Only allow GET, POST, HEAD where needed.",
                            })
                except Exception:
                    pass

                # TRACE test — can reveal internal headers
                try:
                    resp = await client.request("TRACE", url)
                    if resp.status_code == 200 and "trace" in resp.text.lower():
                        findings.append({
                            "title": f"TRACE method enabled (XST risk)",
                            "url": url,
                            "severity": "medium",
                            "vuln_type": "misconfiguration",
                            "payload": "TRACE / HTTP/1.1",
                            "method": "TRACE",
                            "impact": "TRACE method echoes back the request including cookies and "
                                     "auth headers. Combined with XSS, this enables "
                                     "Cross-Site Tracing (XST) to steal credentials.",
                            "remediation": "Disable TRACE method: TraceEnable off (Apache), "
                                          "deny TRACE in nginx config.",
                        })
                except Exception:
                    pass

        return findings
