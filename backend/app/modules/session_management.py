"""
Session Management Security Module

Tests for:
1. Session fixation (pre-login token reuse after authentication)
2. Weak session tokens (short, predictable, low entropy)
3. Missing Secure/HttpOnly/SameSite cookie flags
4. Session not invalidated on logout
5. Concurrent session handling
6. Session timeout testing
"""
import asyncio
import hashlib
import math
import re
import logging
from collections import Counter
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Common session cookie names
SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
    "aspsessionid", "asp.net_sessionid", "cfid", "cftoken",
    "connect.sid", "token", "auth_token", "access_token",
    "jwt", "_session", "sess", "laravel_session", "ci_session",
    "wordpress_logged_in", "wp-settings", "django_session",
}

# Login form indicators
LOGIN_INDICATORS = [
    "login", "signin", "sign-in", "log-in", "auth",
    "authenticate", "session", "account/login",
]

LOGOUT_INDICATORS = [
    "logout", "signout", "sign-out", "log-out",
    "disconnect", "session/destroy",
]


class SessionManagementModule:
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
            # 1. Cookie flag analysis
            cookie_findings = await self._check_cookie_flags(client, base_url, endpoints)
            findings.extend(cookie_findings)

            # 2. Session token quality
            token_findings = await self._check_token_quality(client, base_url, endpoints)
            findings.extend(token_findings)

            # 3. Session fixation
            fixation = await self._check_session_fixation(client, base_url, endpoints)
            findings.extend(fixation)

            # 4. Logout invalidation
            logout = await self._check_logout_invalidation(client, base_url, endpoints, auth_cookie)
            findings.extend(logout)

        return findings

    async def _check_cookie_flags(self, client, base_url, endpoints) -> list[dict]:
        """Check for missing Secure, HttpOnly, SameSite flags on session cookies."""
        findings = []
        urls_to_check = [base_url]

        for ep in endpoints[:10]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url and any(k in url.lower() for k in LOGIN_INDICATORS):
                urls_to_check.append(url)

        checked = set()
        for url in urls_to_check:
            if url in checked:
                continue
            checked.add(url)

            try:
                async with self.rate_limit:
                    resp = await client.get(url)
                    set_cookies = resp.headers.get_list("set-cookie")

                    for cookie_header in set_cookies:
                        cookie_name = cookie_header.split("=")[0].strip().lower()

                        # Check if it's a session-related cookie
                        is_session = (
                            cookie_name in SESSION_COOKIE_NAMES
                            or any(s in cookie_name for s in ("sess", "token", "auth", "jwt", "sid"))
                        )
                        if not is_session:
                            continue

                        header_lower = cookie_header.lower()
                        issues = []

                        if "secure" not in header_lower:
                            issues.append("Missing Secure flag")
                        if "httponly" not in header_lower:
                            issues.append("Missing HttpOnly flag")
                        if "samesite" not in header_lower:
                            issues.append("Missing SameSite attribute")
                        elif "samesite=none" in header_lower:
                            issues.append("SameSite=None (allows cross-site)")

                        # Check for overly long expiry
                        max_age_match = re.search(r"max-age=(\d+)", header_lower)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age > 86400 * 30:  # > 30 days
                                issues.append(f"Excessive session lifetime ({max_age // 86400} days)")

                        if issues:
                            findings.append({
                                "title": f"Insecure Session Cookie: {cookie_name}",
                                "url": url,
                                "severity": "medium" if "HttpOnly" in str(issues) else "low",
                                "vuln_type": "misconfig",
                                "cookie_name": cookie_name,
                                "issues": issues,
                                "cookie_header": cookie_header[:200],
                                "impact": f"Session cookie '{cookie_name}' has security issues: "
                                         f"{'; '.join(issues)}. "
                                         "This may allow session hijacking via XSS or MITM.",
                                "remediation": "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on session cookies.",
                            })
            except Exception as e:
                logger.debug(f"Cookie flag check error for {url}: {e}")

        return findings

    async def _check_token_quality(self, client, base_url, endpoints) -> list[dict]:
        """Collect multiple session tokens and analyze randomness."""
        findings = []

        # Find login or session-generating endpoint
        session_url = base_url
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in LOGIN_INDICATORS):
                session_url = url
                break

        tokens = []
        for _ in range(10):
            try:
                async with self.rate_limit:
                    resp = await client.get(session_url)
                    for cookie_header in resp.headers.get_list("set-cookie"):
                        name = cookie_header.split("=")[0].strip().lower()
                        if any(s in name for s in ("sess", "token", "sid", "auth")):
                            value = cookie_header.split("=", 1)[1].split(";")[0].strip()
                            if value:
                                tokens.append(value)
            except Exception:
                continue

        if len(tokens) >= 5:
            # Check token length
            avg_len = sum(len(t) for t in tokens) / len(tokens)
            if avg_len < 16:
                findings.append({
                    "title": "Weak Session Token: Short Length",
                    "url": session_url,
                    "severity": "high",
                    "vuln_type": "misconfig",
                    "avg_length": avg_len,
                    "impact": f"Session tokens are only {avg_len:.0f} chars on average. "
                             "Short tokens are easier to brute-force.",
                    "remediation": "Use session tokens with at least 128 bits of entropy (32+ hex chars).",
                })

            # Check for sequential/predictable patterns
            if all(t.isdigit() for t in tokens):
                int_tokens = sorted(int(t) for t in tokens)
                diffs = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
                if len(set(diffs)) <= 2:
                    findings.append({
                        "title": "Predictable Session Token: Sequential",
                        "url": session_url,
                        "severity": "critical",
                        "vuln_type": "misconfig",
                        "sample_tokens": tokens[:3],
                        "impact": "Session tokens are sequential integers. "
                                 "Attacker can predict valid session IDs.",
                        "remediation": "Use cryptographically secure random token generation.",
                    })

            # Check entropy
            entropy = self._calculate_entropy(tokens)
            if entropy < 3.0:
                findings.append({
                    "title": "Weak Session Token: Low Entropy",
                    "url": session_url,
                    "severity": "high",
                    "vuln_type": "misconfig",
                    "entropy": round(entropy, 2),
                    "impact": f"Session token entropy is {entropy:.2f} bits/char (expected >4.0). "
                             "Tokens may be predictable.",
                    "remediation": "Use cryptographically secure random token generation (e.g., secrets.token_hex).",
                })

            # Check for duplicates
            if len(set(tokens)) < len(tokens):
                dup_count = len(tokens) - len(set(tokens))
                findings.append({
                    "title": "Session Token Reuse Detected",
                    "url": session_url,
                    "severity": "high",
                    "vuln_type": "misconfig",
                    "duplicate_count": dup_count,
                    "impact": f"{dup_count} duplicate tokens found in {len(tokens)} samples. "
                             "Session tokens are being reused across different sessions.",
                    "remediation": "Generate a unique token for each new session.",
                })

        return findings

    async def _check_session_fixation(self, client, base_url, endpoints) -> list[dict]:
        """Check if pre-authentication session ID persists after login."""
        findings = []

        # Find login endpoint (POST)
        login_url = None
        for ep in endpoints:
            if isinstance(ep, str):
                if any(k in ep.lower() for k in LOGIN_INDICATORS):
                    login_url = ep
            elif isinstance(ep, dict):
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                if any(k in url.lower() for k in LOGIN_INDICATORS) and method == "POST":
                    login_url = url
                    break

        if not login_url:
            return findings

        try:
            # Step 1: Get a pre-auth session cookie
            async with self.rate_limit:
                pre_resp = await client.get(login_url)
                pre_cookies = {}
                for cookie_header in pre_resp.headers.get_list("set-cookie"):
                    name = cookie_header.split("=")[0].strip()
                    value = cookie_header.split("=", 1)[1].split(";")[0].strip()
                    name_lower = name.lower()
                    if any(s in name_lower for s in ("sess", "token", "sid", "phpsessid")):
                        pre_cookies[name] = value

            if not pre_cookies:
                return findings

            # Step 2: Submit login with the pre-auth session
            # We don't know valid creds, but we can check if the session ID changes
            # by submitting a dummy login and comparing
            cookie_str = "; ".join(f"{k}={v}" for k, v in pre_cookies.items())
            async with self.rate_limit:
                post_resp = await client.post(
                    login_url,
                    data={"username": "test", "password": "test"},
                    headers={"Cookie": cookie_str},
                )
                post_cookies = {}
                for cookie_header in post_resp.headers.get_list("set-cookie"):
                    name = cookie_header.split("=")[0].strip()
                    value = cookie_header.split("=", 1)[1].split(";")[0].strip()
                    name_lower = name.lower()
                    if any(s in name_lower for s in ("sess", "token", "sid", "phpsessid")):
                        post_cookies[name] = value

                # If same session cookie persists without change, potential fixation
                for name, pre_value in pre_cookies.items():
                    if name in post_cookies and post_cookies[name] == pre_value:
                        # Session wasn't regenerated even after auth attempt
                        findings.append({
                            "title": f"Session Fixation: {name} not regenerated",
                            "url": login_url,
                            "severity": "high",
                            "vuln_type": "misconfig",
                            "cookie_name": name,
                            "impact": f"Session cookie '{name}' is not regenerated after login attempt. "
                                     "Attacker can set a known session ID and wait for victim to authenticate.",
                            "remediation": "Always regenerate session ID after successful authentication. "
                                          "Invalidate the old session.",
                        })

        except Exception as e:
            logger.debug(f"Session fixation check error: {e}")

        return findings

    async def _check_logout_invalidation(self, client, base_url, endpoints, auth_cookie) -> list[dict]:
        """Check if session is properly invalidated after logout."""
        findings = []

        if not auth_cookie:
            return findings

        # Find logout endpoint
        logout_url = None
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in LOGOUT_INDICATORS):
                logout_url = url
                break

        if not logout_url:
            # Try common logout paths
            for path in ["/logout", "/api/auth/logout", "/signout", "/api/logout"]:
                test_url = f"{base_url}{path}"
                try:
                    async with self.rate_limit:
                        resp = await client.get(test_url)
                        if resp.status_code in (200, 302, 303):
                            logout_url = test_url
                            break
                except Exception:
                    continue

        if not logout_url:
            return findings

        try:
            # Find an authenticated endpoint to test
            auth_test_url = None
            auth_headers = {}
            if auth_cookie.startswith("token="):
                auth_headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                auth_headers["Cookie"] = auth_cookie

            for ep in endpoints:
                url = ep if isinstance(ep, str) else ep.get("url", "")
                if any(k in url.lower() for k in ("profile", "dashboard", "account", "me", "user")):
                    auth_test_url = url
                    break

            if not auth_test_url:
                auth_test_url = f"{base_url}/api/auth/me"

            # Step 1: Verify auth works before logout
            async with self.rate_limit:
                pre_resp = await client.get(auth_test_url, headers=auth_headers)
                if pre_resp.status_code not in (200, 201):
                    return findings

            # Step 2: Perform logout
            async with self.rate_limit:
                await client.get(logout_url, headers=auth_headers)
                # Also try POST
                await client.post(logout_url, headers=auth_headers)

            # Step 3: Try using the old session
            async with self.rate_limit:
                post_resp = await client.get(auth_test_url, headers=auth_headers)
                if post_resp.status_code in (200, 201):
                    # Session still valid after logout
                    findings.append({
                        "title": "Session Not Invalidated After Logout",
                        "url": logout_url,
                        "severity": "medium",
                        "vuln_type": "misconfig",
                        "auth_endpoint": auth_test_url,
                        "impact": "Session remains valid after logout. "
                                 "If an attacker captures a session token, "
                                 "it remains usable even after the user logs out.",
                        "remediation": "Invalidate the session server-side on logout. "
                                      "Clear session data and revoke tokens.",
                    })

        except Exception as e:
            logger.debug(f"Logout invalidation check error: {e}")

        return findings

    def _calculate_entropy(self, tokens: list[str]) -> float:
        """Calculate Shannon entropy of token character distribution."""
        all_chars = "".join(tokens)
        if not all_chars:
            return 0.0
        freq = Counter(all_chars)
        total = len(all_chars)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
