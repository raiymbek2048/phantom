"""
Web Cache Poisoning & Cache Deception Module

Tests for two related but distinct vulnerability classes:

1. Cache Poisoning: Inject malicious content into cached responses via unkeyed
   headers/params so subsequent users receive poisoned content.

2. Cache Deception: Trick a cache into storing sensitive (authenticated) responses
   by appending static-looking extensions to dynamic URLs.

Detection:
- Compare responses with/without unkeyed headers
- Check cache indicator headers (Age, X-Cache, CF-Cache-Status, X-Varnish)
- Verify cross-session leakage for deception attacks
"""
import asyncio
import json
import logging
import random
import time
from urllib.parse import urlparse, urljoin, urlencode

import httpx

from app.utils.http_client import make_client, get_random_ua

logger = logging.getLogger(__name__)


class CachePoisoningModule:
    """Tests for Web Cache Poisoning and Web Cache Deception."""

    # Unkeyed headers that may be reflected in cached responses
    UNKEYED_HEADERS = [
        ("X-Forwarded-Host", "evil-phantom-{marker}.com"),
        ("X-Original-URL", "/phantom-test-{marker}"),
        ("X-Rewrite-URL", "/phantom-test-{marker}"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Port", "9876"),
        ("X-Host", "evil-phantom-{marker}.com"),
        ("X-Forwarded-Server", "evil-phantom-{marker}.com"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Forwarded-Prefix", "/phantom-test-{marker}"),
        ("X-Original-Host", "evil-phantom-{marker}.com"),
    ]

    # Unkeyed query parameters (commonly excluded from cache keys)
    UNKEYED_PARAMS = [
        "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
        "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
        "callback", "jsonp", "cb", "_",
    ]

    # Cache indicator headers
    CACHE_HEADERS = [
        "X-Cache", "CF-Cache-Status", "X-Varnish", "Age",
        "X-Cache-Hits", "X-Served-By", "X-Cache-Lookup",
        "X-Proxy-Cache", "X-Fastly-Request-ID", "Via",
        "X-Akamai-Transformed", "X-CDN",
    ]

    # Path separators that might confuse path parsing (for cache deception)
    DECEPTION_SEPARATORS = [
        "/nonexistent.css",
        "/.css",
        "%0d.css",
        "%0a.css",
        "%00.css",
        "/..%2f..%2fstatic/x.css",
        ";.css",
        "?.css",
    ]

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def run(self, context: dict) -> list[dict]:
        """Run all cache poisoning and deception tests."""
        base_url = context.get("base_url", "")
        endpoints = context.get("endpoints", [])[:20]
        auth_cookie = context.get("auth_cookie")
        findings = []

        if not base_url:
            return findings

        # Build test URL list
        test_urls = [base_url]
        for ep in endpoints[:10]:
            if isinstance(ep, dict):
                url = ep.get("url", "")
            else:
                url = str(ep)
            if url and url not in test_urls:
                test_urls.append(url)

        # Test cache poisoning on all URLs
        for url in test_urls:
            try:
                # Test unkeyed header poisoning
                result = await self._test_cache_poisoning(url, context)
                if result:
                    findings.append(result)

                # Test unkeyed parameter poisoning
                result = await self._test_param_poisoning(url, context)
                if result:
                    findings.append(result)

                # Test fat GET
                result = await self._test_fat_get(url, context)
                if result:
                    findings.append(result)

            except Exception as e:
                logger.debug(f"Cache poisoning test error for {url}: {e}")

        # Test cache deception on authenticated endpoints
        if auth_cookie:
            auth_urls = self._get_auth_endpoints(endpoints, base_url)
            for url in auth_urls[:5]:
                try:
                    result = await self._test_cache_deception(url, context)
                    if result:
                        findings.append(result)
                except Exception as e:
                    logger.debug(f"Cache deception test error for {url}: {e}")

        return findings

    def _make_client(self, context: dict, extra_headers: dict = None, **kwargs) -> httpx.AsyncClient:
        """Create HTTP client with optional auth."""
        headers = dict(context.get("custom_headers", {}))
        auth_cookie = context.get("auth_cookie")
        if auth_cookie:
            if auth_cookie.startswith("token="):
                token = auth_cookie.split("=", 1)[1]
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["Cookie"] = auth_cookie
        if extra_headers:
            headers.update(extra_headers)
        return make_client(extra_headers=headers, **kwargs)

    def _make_unauth_client(self, context: dict, extra_headers: dict = None, **kwargs) -> httpx.AsyncClient:
        """Create HTTP client WITHOUT auth (for cross-session tests)."""
        headers = dict(context.get("custom_headers", {}))
        if extra_headers:
            headers.update(extra_headers)
        return make_client(extra_headers=headers, **kwargs)

    def _detect_cache(self, headers: dict) -> dict:
        """Detect cache presence and status from response headers."""
        result = {"cached": False, "cache_type": None, "indicators": []}

        for hdr in self.CACHE_HEADERS:
            val = headers.get(hdr.lower()) or headers.get(hdr)
            if val:
                result["indicators"].append(f"{hdr}: {val}")
                val_lower = str(val).lower()

                if hdr.lower() == "x-cache" and "hit" in val_lower:
                    result["cached"] = True
                    result["cache_type"] = "proxy/CDN"
                elif hdr.lower() == "cf-cache-status" and val_lower in ("hit", "dynamic"):
                    result["cached"] = True
                    result["cache_type"] = "Cloudflare"
                elif hdr.lower() == "age":
                    try:
                        if int(val) > 0:
                            result["cached"] = True
                            result["cache_type"] = "proxy"
                    except ValueError:
                        pass
                elif hdr.lower() == "x-varnish" and " " in str(val):
                    result["cached"] = True
                    result["cache_type"] = "Varnish"

        return result

    async def _test_cache_poisoning(self, url: str, context: dict) -> dict | None:
        """Test for cache poisoning via unkeyed headers.

        For each unkeyed header:
        1. Send request with cache buster + poisoned header
        2. Send same request without poisoned header (same cache buster)
        3. If response 2 contains poison from step 1, cache is poisoned
        """
        marker = f"phantom{random.randint(100000, 999999)}"

        for header_name, header_value_template in self.UNKEYED_HEADERS:
            try:
                header_value = header_value_template.format(marker=marker)
                cache_buster = f"_cb={random.randint(100000, 999999)}"

                # Add cache buster to URL
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{cache_buster}"

                # Step 1: Send with poisoned header
                async with self.rate_limit:
                    async with self._make_client(context, extra_headers={header_name: header_value}) as client:
                        resp1 = await client.get(test_url)
                        resp1_text = resp1.text[:10000]

                # Check if poisoned value is reflected
                if header_value not in resp1_text and marker not in resp1_text:
                    continue

                # Small delay to let cache store
                await asyncio.sleep(0.5)

                # Step 2: Send WITHOUT poisoned header (same cache buster)
                async with self.rate_limit:
                    async with self._make_client(context) as client:
                        resp2 = await client.get(test_url)
                        resp2_text = resp2.text[:10000]
                        resp2_headers = dict(resp2.headers)

                # Step 3: Check if poison persists in cached response
                cache_info = self._detect_cache(resp2_headers)

                if (header_value in resp2_text or marker in resp2_text):
                    severity = "high" if cache_info["cached"] else "medium"

                    return {
                        "title": f"Web Cache Poisoning via {header_name} at {urlparse(url).path}",
                        "url": url,
                        "severity": severity,
                        "vuln_type": "misconfiguration",
                        "description": (
                            f"Web cache poisoning detected via unkeyed header '{header_name}'. "
                            f"The value '{header_value}' is reflected in the response and persists "
                            f"in the cache. A subsequent request without the header returns the "
                            f"poisoned content. "
                            f"Cache indicators: {', '.join(cache_info['indicators']) or 'none detected'}."
                        ),
                        "impact": (
                            "An attacker can inject malicious content (XSS payloads, redirects, "
                            "fake login forms) into cached responses. Every user who requests "
                            "the poisoned URL receives the attacker's content. This can lead to "
                            "mass credential theft, malware distribution, or defacement."
                        ),
                        "remediation": (
                            "1. Include all reflected headers in the cache key. "
                            "2. Do not reflect unvalidated header values in responses. "
                            "3. Use 'Vary' header to include custom headers in cache key. "
                            "4. Implement strict input validation for forwarded headers. "
                            "5. Consider using 'Cache-Control: private' for dynamic content."
                        ),
                        "payload": f"{header_name}: {header_value}",
                        "proof": (
                            f"Request 1 with header '{header_name}: {header_value}' — value reflected. "
                            f"Request 2 without header — value still present in response (cached)."
                        ),
                        "method": "GET",
                    }

                await asyncio.sleep(0.2)

            except Exception as e:
                logger.debug(f"Cache poisoning header test error ({header_name}): {e}")

        return None

    async def _test_param_poisoning(self, url: str, context: dict) -> dict | None:
        """Test cache poisoning via unkeyed query parameters.

        Some caches exclude tracking params (utm_*, fbclid, etc.) from the cache key.
        If these params are reflected in the response, an attacker can poison the cache.
        """
        marker = f"phantom{random.randint(100000, 999999)}"

        for param in self.UNKEYED_PARAMS[:8]:
            try:
                cache_buster = f"_cb={random.randint(100000, 999999)}"
                poison_value = f"javascript:alert('{marker}')"

                sep = "&" if "?" in url else "?"
                poisoned_url = f"{url}{sep}{cache_buster}&{param}={poison_value}"
                clean_url = f"{url}{sep}{cache_buster}"

                # Send with poisoned param
                async with self.rate_limit:
                    async with self._make_client(context) as client:
                        resp1 = await client.get(poisoned_url)
                        resp1_text = resp1.text[:10000]

                if marker not in resp1_text:
                    continue

                await asyncio.sleep(0.5)

                # Send without poisoned param but same cache buster
                async with self.rate_limit:
                    async with self._make_client(context) as client:
                        resp2 = await client.get(clean_url)
                        resp2_text = resp2.text[:10000]
                        cache_info = self._detect_cache(dict(resp2.headers))

                if marker in resp2_text:
                    return {
                        "title": f"Cache Poisoning via Unkeyed Parameter '{param}' at {urlparse(url).path}",
                        "url": url,
                        "severity": "medium",
                        "vuln_type": "misconfiguration",
                        "description": (
                            f"Cache poisoning via unkeyed query parameter '{param}'. "
                            f"The parameter is reflected in the response but excluded from "
                            f"the cache key. Injected value persists for other users. "
                            f"Cache: {', '.join(cache_info['indicators']) or 'unknown'}."
                        ),
                        "impact": (
                            "Attacker can inject XSS payloads or redirects via tracking parameters "
                            "that are excluded from the cache key, affecting all subsequent visitors."
                        ),
                        "remediation": (
                            "1. Include all reflected parameters in the cache key. "
                            "2. Do not reflect query parameter values in HTML responses. "
                            "3. Strip or sanitize tracking parameters at the edge/CDN level."
                        ),
                        "payload": f"?{param}={poison_value}",
                        "proof": f"Parameter '{param}' reflected and persisted in cache without re-sending",
                        "method": "GET",
                    }

                await asyncio.sleep(0.2)

            except Exception as e:
                logger.debug(f"Param poisoning test error ({param}): {e}")

        return None

    async def _test_fat_get(self, url: str, context: dict) -> dict | None:
        """Test for Fat GET — GET request with a body that influences the response.

        Some servers process the body of GET requests, but caches only key on
        URL + headers (not body), creating a poisoning vector.
        """
        marker = f"phantom{random.randint(100000, 999999)}"
        cache_buster = f"_cb={random.randint(100000, 999999)}"
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{cache_buster}"

        try:
            # Send GET with body
            body_payload = json.dumps({"role": "admin", "marker": marker})
            async with self.rate_limit:
                async with self._make_client(
                    context,
                    extra_headers={"Content-Type": "application/json"}
                ) as client:
                    resp1 = await client.request("GET", test_url, content=body_payload)
                    resp1_text = resp1.text[:10000]

            if marker not in resp1_text:
                return None

            await asyncio.sleep(0.5)

            # Send normal GET without body
            async with self.rate_limit:
                async with self._make_client(context) as client:
                    resp2 = await client.get(test_url)
                    resp2_text = resp2.text[:10000]
                    cache_info = self._detect_cache(dict(resp2.headers))

            if marker in resp2_text:
                return {
                    "title": f"Cache Poisoning via Fat GET at {urlparse(url).path}",
                    "url": url,
                    "severity": "medium",
                    "vuln_type": "misconfiguration",
                    "description": (
                        f"Fat GET cache poisoning detected at {url}. The server processes "
                        f"the body of GET requests, but the cache ignores the body when "
                        f"computing the cache key. An attacker can poison cached responses "
                        f"by sending GET requests with malicious bodies."
                    ),
                    "impact": (
                        "Attacker can poison cached GET responses by including a body "
                        "that modifies the response content. All subsequent users "
                        "receive the poisoned response."
                    ),
                    "remediation": (
                        "1. Configure the server to ignore GET request bodies. "
                        "2. Include the request body in the cache key for endpoints that use it. "
                        "3. Use POST for endpoints that require a body."
                    ),
                    "payload": f"GET with body: {body_payload}",
                    "proof": "GET body content persisted in cache without re-sending body",
                    "method": "GET",
                }

        except Exception as e:
            logger.debug(f"Fat GET test error for {url}: {e}")

        return None

    async def _test_cache_deception(self, url: str, context: dict) -> dict | None:
        """Test for Web Cache Deception.

        Trick the cache into storing a sensitive (authenticated) response by
        appending a static-looking path extension.

        1. Request /profile/settings/nonexistent.css (authenticated)
        2. If server returns the actual profile page (path normalization)
        3. Check if cache stored it (Age > 0, X-Cache: HIT)
        4. Request same URL unauthenticated — if it returns profile data, deception confirmed
        """
        for suffix in self.DECEPTION_SEPARATORS[:5]:
            try:
                deception_url = url.rstrip("/") + suffix
                cache_buster = f"_dcb={random.randint(100000, 999999)}"
                sep = "&" if "?" in deception_url else "?"
                test_url = f"{deception_url}{sep}{cache_buster}"

                # Step 1: Authenticated request
                async with self.rate_limit:
                    async with self._make_client(context) as client:
                        resp_auth = await client.get(test_url)
                        auth_text = resp_auth.text[:10000]
                        auth_status = resp_auth.status_code

                # Skip if server returned error or redirect
                if auth_status >= 400 or auth_status in (301, 302):
                    continue

                if len(auth_text) < 100:
                    continue

                # Check for sensitive data markers in response
                has_sensitive = self._has_sensitive_data(auth_text)
                if not has_sensitive:
                    continue

                await asyncio.sleep(0.5)

                # Step 2: Unauthenticated request to same URL
                async with self.rate_limit:
                    async with self._make_unauth_client(context) as client:
                        resp_unauth = await client.get(test_url)
                        unauth_text = resp_unauth.text[:10000]
                        unauth_status = resp_unauth.status_code
                        unauth_headers = dict(resp_unauth.headers)

                cache_info = self._detect_cache(unauth_headers)

                # Step 3: Check if unauthenticated response contains the same sensitive data
                if unauth_status == 200 and self._has_sensitive_data(unauth_text):
                    if self._responses_similar(auth_text, unauth_text):
                        return {
                            "title": f"Web Cache Deception at {urlparse(url).path}",
                            "url": url,
                            "severity": "high",
                            "vuln_type": "info_disclosure",
                            "description": (
                                f"Web Cache Deception vulnerability detected. Requesting "
                                f"'{deception_url}' with authentication returns sensitive data "
                                f"that gets cached. An unauthenticated request to the same URL "
                                f"retrieves the cached sensitive response. "
                                f"Cache: {', '.join(cache_info['indicators']) or 'inferred from behavior'}."
                            ),
                            "impact": (
                                "An attacker can steal other users' sensitive data (profile info, "
                                "tokens, session data, personal information) by tricking them into "
                                "visiting a URL with a static extension appended. The cache stores "
                                "the authenticated response, and the attacker retrieves it."
                            ),
                            "remediation": (
                                "1. Configure the cache to respect Cache-Control headers from the origin. "
                                "2. Only cache responses with explicit caching headers. "
                                "3. Use 'Cache-Control: no-store, private' for authenticated pages. "
                                "4. Configure the CDN/proxy to not cache based on file extension alone. "
                                "5. Reject or 404 requests with unexpected path extensions."
                            ),
                            "payload": deception_url,
                            "proof": (
                                f"Authenticated request to {deception_url} returned sensitive data. "
                                f"Unauthenticated request returned same content (cache deception). "
                                f"Suffix used: '{suffix}'"
                            ),
                            "method": "GET",
                        }

                await asyncio.sleep(0.3)

            except Exception as e:
                logger.debug(f"Cache deception test error for {url} + {suffix}: {e}")

        return None

    def _get_auth_endpoints(self, endpoints: list, base_url: str) -> list[str]:
        """Select endpoints that likely serve authenticated content."""
        auth_keywords = [
            "profile", "account", "settings", "dashboard", "me",
            "user", "admin", "billing", "orders", "notifications",
            "messages", "inbox",
        ]
        urls = []

        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get("url", "")
            else:
                url = str(ep)

            if any(kw in url.lower() for kw in auth_keywords):
                if url not in urls:
                    urls.append(url)

        for path in ["/profile", "/account", "/settings", "/dashboard", "/api/me", "/api/user"]:
            full = urljoin(base_url, path)
            if full not in urls:
                urls.append(full)

        return urls

    def _has_sensitive_data(self, text: str) -> bool:
        """Check if response contains markers of sensitive/personal data."""
        sensitive_markers = [
            "email", "username", "user_id", "userId", "password",
            "token", "session", "api_key", "apiKey", "secret",
            "phone", "address", "credit_card", "ssn", "balance",
            "profile", "account", "role", "permission",
            "@", "Bearer", "csrf",
        ]
        text_lower = text.lower()
        matches = sum(1 for m in sensitive_markers if m.lower() in text_lower)
        return matches >= 3

    def _responses_similar(self, text1: str, text2: str) -> bool:
        """Check if two responses are similar enough to confirm cache deception."""
        if not text1 or not text2:
            return False

        len_ratio = min(len(text1), len(text2)) / max(len(text1), len(text2))
        if len_ratio < 0.5:
            return False

        words1 = set(text1.split()[:200])
        words2 = set(text2.split()[:200])
        if not words1 or not words2:
            return False

        overlap = len(words1 & words2) / len(words1 | words2)
        return overlap > 0.6
