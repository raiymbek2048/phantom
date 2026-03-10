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

        # 1. Rate limiting test on discovered endpoints
        from app.utils.spa_detector import is_static_asset

        endpoints = context.get("endpoints", [])
        test_urls = [base_url]
        for ep in endpoints[:5]:
            ep_url = ep.get("url") if isinstance(ep, dict) else ep
            if ep_url and not is_static_asset(ep_url):
                test_urls.append(ep_url)

        for url in test_urls[:5]:
            result = await self._test_rate_limiting(url)
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

    async def _test_rate_limiting(self, url: str) -> dict | None:
        """Send rapid requests to test rate limiting."""
        # Skip health/status endpoints — they are expected to accept unlimited requests
        from urllib.parse import urlparse
        path = urlparse(url).path.lower()
        health_patterns = ("/health", "/healthz", "/status", "/ping", "/ready", "/alive")
        if any(path.endswith(p) or path == p for p in health_patterns):
            return None

        num_requests = 50
        results = []

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            start = time.time()

            async def send_one(i):
                try:
                    resp = await client.get(url, headers={"X-Test": f"stress-{i}"})
                    return resp.status_code
                except Exception:
                    return 0

            # Send all requests concurrently
            tasks = [send_one(i) for i in range(num_requests)]
            results = await asyncio.gather(*tasks)

            elapsed = time.time() - start

        success = sum(1 for r in results if r == 200)
        rate_limited = sum(1 for r in results if r == 429)
        errors = sum(1 for r in results if r >= 500)

        if success == num_requests and rate_limited == 0:
            rps = num_requests / elapsed if elapsed > 0 else 0
            return {
                "title": f"No rate limiting detected: {url}",
                "url": url,
                "severity": "info",
                "vuln_type": "misconfiguration",
                "payload": f"Sent {num_requests} concurrent GET requests in {elapsed:.1f}s",
                "method": "GET",
                "impact": f"Endpoint accepted all {num_requests} requests ({rps:.0f} req/s) "
                         f"without rate limiting. Vulnerable to brute force and resource exhaustion.",
                "remediation": "Implement rate limiting (e.g., nginx limit_req, "
                              "application-level throttling). Recommended: 10-30 req/s per IP.",
            }

        if errors > num_requests * 0.3:
            return {
                "title": f"Server errors under moderate load: {url}",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"{errors}/{num_requests} requests returned 5xx errors",
                "method": "GET",
                "impact": f"Server returned {errors} errors out of {num_requests} concurrent requests. "
                         f"The server may have stability issues under load.",
                "remediation": "Improve server capacity, add connection pooling, "
                              "and implement graceful degradation.",
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
