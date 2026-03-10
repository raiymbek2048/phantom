"""
Cache Poisoning & Web Cache Deception Module

Tests for:
1. Web Cache Deception (WCD) — access cached private content
2. Host header cache poisoning
3. X-Forwarded-Host / X-Forwarded-Scheme poisoning
4. HTTP Request Smuggling indicators (CL/TE mismatch)
5. Cache key manipulation
"""
import asyncio
import logging
import random
import string
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Static file extensions for Web Cache Deception
STATIC_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".pdf",
]

# Headers that influence caching
CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Host", "evil.com"),
    ("X-Forwarded-Server", "evil.com"),
    ("Forwarded", "host=evil.com"),
]


class CachePoisoningModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        base_url = context.get("base_url", "")
        endpoints = context.get("endpoints", [])
        auth_cookie = context.get("auth_cookie")
        findings = []

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        async with make_client(
            extra_headers=headers, follow_redirects=False
        ) as client:
            # 1. Web Cache Deception
            wcd = await self._check_web_cache_deception(client, base_url, endpoints)
            findings.extend(wcd)

            # 2. Host header cache poisoning
            host_poison = await self._check_host_header_poison(client, base_url)
            findings.extend(host_poison)

            # 3. Cache header analysis
            cache_info = await self._check_cache_headers(client, base_url, endpoints)
            findings.extend(cache_info)

            # 4. HTTP Request Smuggling indicators
            smuggling = await self._check_request_smuggling(client, base_url)
            findings.extend(smuggling)

        return findings

    async def _check_web_cache_deception(self, client, base_url, endpoints) -> list[dict]:
        """Test for Web Cache Deception (WCD).
        If /profile/nonexistent.css returns the same content as /profile,
        CDN may cache private content under a static-looking URL."""
        findings = []

        # Find authenticated pages with private content
        private_urls = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in ("profile", "account", "dashboard", "settings", "me")):
                private_urls.append(url)

        if not private_urls:
            private_urls = [f"{base_url}/profile", f"{base_url}/account", f"{base_url}/dashboard"]

        for url in private_urls[:5]:
            try:
                # Get normal response
                async with self.rate_limit:
                    normal_resp = await client.get(url)
                    if normal_resp.status_code != 200:
                        continue
                    normal_body = normal_resp.text
                    normal_len = len(normal_body)

                # If page has private-looking content, test WCD
                if normal_len < 50:
                    continue

                for ext in STATIC_EXTENSIONS[:5]:
                    cache_buster = "".join(random.choices(string.ascii_lowercase, k=8))
                    wcd_url = f"{url}/{cache_buster}{ext}"

                    async with self.rate_limit:
                        wcd_resp = await client.get(wcd_url)

                        if wcd_resp.status_code == 200:
                            wcd_body = wcd_resp.text
                            wcd_len = len(wcd_body)

                            # If the response is similar to the private page
                            # (not a 404, not empty, and similar length)
                            if wcd_len > 50 and abs(wcd_len - normal_len) < normal_len * 0.3:
                                # Check cache headers
                                cache_control = wcd_resp.headers.get("cache-control", "")
                                is_cached = (
                                    "public" in cache_control
                                    or "max-age" in cache_control
                                    or "x-cache" in str(wcd_resp.headers).lower()
                                    or "cf-cache-status" in wcd_resp.headers
                                )

                                if is_cached:
                                    findings.append({
                                        "title": f"Web Cache Deception: {urlparse(url).path}",
                                        "url": wcd_url,
                                        "severity": "high",
                                        "vuln_type": "misconfig",
                                        "original_url": url,
                                        "cache_headers": cache_control,
                                        "impact": f"Private page {urlparse(url).path} is served when accessed as "
                                                 f"{urlparse(wcd_url).path}. CDN caches this as a static file. "
                                                 "Attacker can trick victim into visiting the URL, "
                                                 "then access cached private data.",
                                        "remediation": "Configure CDN to cache based on Content-Type, not URL extension. "
                                                      "Set Cache-Control: no-store on private pages.",
                                    })
                                    return findings

            except Exception as e:
                logger.debug(f"WCD check error for {url}: {e}")

        return findings

    async def _check_host_header_poison(self, client, base_url) -> list[dict]:
        """Test if Host/X-Forwarded-Host header values are reflected in response."""
        findings = []
        parsed = urlparse(base_url)

        for header_name, header_value in CACHE_POISON_HEADERS:
            try:
                cache_buster = "".join(random.choices(string.ascii_lowercase, k=6))
                test_url = f"{base_url}/?cb={cache_buster}"

                async with self.rate_limit:
                    resp = await client.get(
                        test_url,
                        headers={header_name: header_value},
                    )
                    body = resp.text

                    # Check if our injected value appears in the response
                    if header_value in body:
                        # Verify it's in a meaningful context (link, script, redirect)
                        in_link = f'href="' in body and header_value in body
                        in_script = f'<script' in body.lower() and header_value in body
                        in_meta = f'<meta' in body.lower() and header_value in body

                        if in_link or in_script or in_meta:
                            # Check if response is cacheable
                            cache_control = resp.headers.get("cache-control", "")
                            is_cacheable = (
                                "no-store" not in cache_control
                                and "private" not in cache_control
                            )

                            severity = "high" if is_cacheable else "medium"

                            findings.append({
                                "title": f"Cache Poisoning via {header_name}",
                                "url": base_url,
                                "severity": severity,
                                "vuln_type": "misconfig",
                                "header": f"{header_name}: {header_value}",
                                "reflected_in": "link" if in_link else ("script" if in_script else "meta"),
                                "cacheable": is_cacheable,
                                "impact": f"Header {header_name} value is reflected in page content. "
                                         f"{'Response is cacheable — attacker can poison cache for all users.' if is_cacheable else 'Response is not cached, but still exploitable for targeted attacks.'}",
                                "remediation": f"Do not use {header_name} header to generate URLs or content. "
                                              "Use a hardcoded base URL. Set Cache-Control: no-store for dynamic pages.",
                            })
                            break

            except Exception:
                continue

        return findings

    async def _check_cache_headers(self, client, base_url, endpoints) -> list[dict]:
        """Analyze cache headers for misconfigurations.
        Only reports when pages are explicitly cacheable (public/max-age/s-maxage)
        AND contain user-specific content indicators."""
        findings = []

        # Check if sensitive endpoints are cacheable
        sensitive_paths = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in (
                "profile", "account", "settings", "admin",
                "api/me", "api/auth", "api/user", "dashboard",
            )):
                sensitive_paths.append(url)

        # Deduplicate by path to avoid multiple findings for same page
        seen_paths = set()
        for url in sensitive_paths[:10]:
            path = urlparse(url).path
            if path in seen_paths:
                continue
            seen_paths.add(path)

            try:
                async with self.rate_limit:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue

                    body = resp.text
                    # Skip pages with very little content (likely error/redirect pages)
                    if len(body) < 200:
                        continue

                    # Check if page actually contains user-specific content indicators
                    body_lower = body.lower()
                    has_user_content = any(k in body_lower for k in (
                        "username", "email", "password", "logout", "sign out",
                        "my account", "welcome", "profile", "api_key", "token",
                    ))
                    if not has_user_content:
                        continue

                    cache_control = resp.headers.get("cache-control", "")
                    vary = resp.headers.get("vary", "")

                    issues = []

                    # Only flag if page is EXPLICITLY cacheable (not just missing headers)
                    if cache_control and "no-store" not in cache_control and "private" not in cache_control:
                        if "public" in cache_control or "max-age" in cache_control:
                            issues.append(f"Cacheable: {cache_control}")
                        elif "s-maxage" in cache_control:
                            issues.append(f"CDN cacheable: {cache_control}")

                        if not vary or "cookie" not in vary.lower():
                            issues.append("Missing Vary: Cookie (CDN may serve wrong user's content)")

                    if issues:
                        findings.append({
                            "title": f"Sensitive Page Caching: {path}",
                            "url": url,
                            "severity": "medium",
                            "vuln_type": "misconfig",
                            "issues": issues,
                            "cache_control": cache_control,
                            "impact": f"Sensitive endpoint with user data is explicitly cacheable: "
                                     f"{'; '.join(issues)}. "
                                     "Private data may be cached by CDN/proxy and served to other users.",
                            "remediation": "Set 'Cache-Control: no-store' on all authenticated/sensitive pages. "
                                          "Add 'Vary: Cookie' to ensure cache respects sessions.",
                        })

            except Exception:
                continue

        return findings

    async def _check_request_smuggling(self, client, base_url) -> list[dict]:
        """Check for HTTP Request Smuggling indicators (CL/TE mismatch)."""
        findings = []

        try:
            # Test CL.TE smuggling indicator
            # Send a request with both Content-Length and Transfer-Encoding
            # and observe if the server processes it differently
            async with self.rate_limit:
                # Check if server supports HTTP/1.1 chunked
                resp = await client.post(
                    base_url,
                    content="0\r\n\r\n",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Transfer-Encoding": "chunked",
                    },
                )

                # Check for timeout or unusual behavior
                te_header = resp.headers.get("transfer-encoding", "")

                # Check if server accepts both CL and TE
                async with self.rate_limit:
                    resp2 = await client.post(
                        base_url,
                        content="0\r\n\r\n",
                        headers={
                            "Content-Length": "5",
                            "Transfer-Encoding": "chunked",
                        },
                    )

                    # If server returns different results, potential CL.TE mismatch
                    if resp.status_code != resp2.status_code:
                        findings.append({
                            "title": "HTTP Request Smuggling Indicator (CL/TE)",
                            "url": base_url,
                            "severity": "medium",
                            "vuln_type": "misconfig",
                            "cl_response": resp2.status_code,
                            "te_response": resp.status_code,
                            "impact": "Server handles Content-Length and Transfer-Encoding "
                                     "differently, which may indicate HTTP Request Smuggling vulnerability. "
                                     "Requires further manual testing to confirm.",
                            "remediation": "Configure front-end and back-end servers to handle "
                                          "CL/TE headers consistently. Reject ambiguous requests.",
                        })

        except Exception as e:
            logger.debug(f"Request smuggling check error: {e}")

        return findings
