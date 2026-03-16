"""
Account Enumeration Module — Detect user existence via side channels.

Tests for:
1. Error message differentiation — "User not found" vs "Wrong password"
2. Response time analysis — existing users take longer (password hash check)
3. Status code differentiation — different codes for valid/invalid users
4. Response length differentiation — different response sizes
5. Registration endpoint — "Email already taken" reveals existing accounts
6. Password reset — "Reset email sent" vs "User not found"
7. API endpoint probing — /api/users/{id}, /api/users/{email}
8. Rate limit differentiation — different rate limits for valid/invalid
"""
import asyncio
import json
import logging
import re
import statistics
import time
from urllib.parse import urljoin, urlparse

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Usernames likely to exist on most apps
LIKELY_EXISTING = ["admin", "administrator", "root", "test", "user", "demo",
                   "info", "support", "contact", "webmaster", "postmaster"]

# Usernames that definitely should not exist
DEFINITELY_FAKE = ["xyznonexistent99887", "phantomfakeuser000", "notreal_zzz777",
                   "aabbccdd_nouser_12345", "qwertyzxcvb_fake99"]

# Common login paths
LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/user/login",
    "/admin/login", "/api/login", "/api/auth/login",
    "/api/v1/auth/login", "/api/v1/login",
    "/accounts/login", "/account/login",
    "/rest/user/login", "/api/sessions",
    "/Account/Login", "/users/sign_in",
    "/session/new", "/auth/signin",
]

# Common registration paths
REGISTER_PATHS = [
    "/register", "/signup", "/auth/register", "/user/register",
    "/api/register", "/api/auth/register", "/api/v1/auth/register",
    "/api/v1/register", "/accounts/register", "/account/register",
    "/create-account", "/join", "/api/users",
    "/Account/Register", "/users/sign_up",
    "/auth/signup", "/api/signup",
]

# Common password reset paths
RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/password/reset",
    "/auth/forgot-password", "/api/forgot-password",
    "/api/auth/forgot-password", "/api/v1/auth/forgot-password",
    "/api/password/reset", "/api/v1/password/reset",
    "/account/forgot-password", "/accounts/password/reset",
    "/Account/ForgotPassword", "/users/password/new",
    "/auth/reset-password", "/password-reset",
    "/api/password-reset", "/reset-password",
]

# API enumeration paths (with {id} and {email} placeholders)
API_ENUM_PATHS = [
    "/api/users/{id}", "/api/user/{id}", "/api/v1/users/{id}",
    "/api/users/{username}", "/api/user/{username}",
    "/api/users/check?email={email}", "/api/users/exists?username={username}",
    "/api/auth/check-email?email={email}", "/api/v1/users/check?email={email}",
    "/api/users/lookup?username={username}", "/api/user/check?email={email}",
    "/api/v1/user/{username}", "/api/v2/users/{username}",
    "/api/members/{username}", "/api/profiles/{username}",
]

# Error messages indicating user does NOT exist
USER_NOT_FOUND_PATTERNS = [
    r"user\s*not\s*found",
    r"account\s*not\s*found",
    r"no\s*account\s*(found\s*)?with",
    r"email\s*not\s*found",
    r"username\s*not\s*found",
    r"doesn.t\s*exist",
    r"does\s*not\s*exist",
    r"invalid\s*username",
    r"no\s*user\s*(found\s*)?with\s*(that|this)",
    r"unknown\s*(user|account|email)",
    r"not\s*registered",
    r"not\s*a\s*registered",
    r"could\s*not\s*find",
    r"we\s*can.t\s*find",
    r"check\s*your\s*email\s*and\s*try",
]

# Error messages indicating user EXISTS (wrong password)
WRONG_PASSWORD_PATTERNS = [
    r"wrong\s*password",
    r"incorrect\s*password",
    r"invalid\s*password",
    r"password\s*is\s*(incorrect|wrong|invalid)",
    r"authentication\s*failed",
    r"bad\s*credentials",
    r"invalid\s*credentials",
]

# Generic error messages (same for both — good practice)
GENERIC_ERROR_PATTERNS = [
    r"invalid\s*(username|email)\s*(or|and)\s*password",
    r"login\s*failed",
    r"unable\s*to\s*log\s*in",
    r"invalid\s*login",
]

# Registration patterns indicating user exists
REG_EXISTS_PATTERNS = [
    r"already\s*(registered|exists|taken|in\s*use)",
    r"email\s*(already|is\s*already)\s*(registered|taken|in\s*use|exists)",
    r"username\s*(already|is\s*already)\s*(taken|in\s*use|exists)",
    r"account\s*already\s*exists",
    r"(this|that)\s*(email|username)\s*is\s*(already\s*)?(taken|registered|in\s*use)",
    r"duplicate\s*(email|user|account)",
]


class AccountEnumerationModule:
    """Detect user existence via side channels in auth flows."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def run(self, context: dict) -> list[dict]:
        """Run all account enumeration tests."""
        findings = []
        base_url = context.get("base_url", "")
        if not base_url:
            return []

        endpoints = context.get("endpoints", [])
        domain = self._extract_domain(base_url)

        # Find auth endpoints
        login_urls = await self._find_endpoints(base_url, endpoints, LOGIN_PATHS,
                                                 ["login", "signin", "auth", "session"])
        register_urls = await self._find_endpoints(base_url, endpoints, REGISTER_PATHS,
                                                    ["register", "signup", "join", "create"])
        reset_urls = await self._find_endpoints(base_url, endpoints, RESET_PATHS,
                                                 ["forgot", "reset", "password"])

        logger.info(f"Account enum: {len(login_urls)} login, {len(register_urls)} register, "
                    f"{len(reset_urls)} reset endpoints")

        # Test login enumeration (error message + timing)
        for url in login_urls[:3]:
            form = await self._extract_login_form(url)
            if not form:
                continue

            result = await self._test_login_enumeration(form, domain)
            if result:
                findings.append(result)

            timing = await self._test_timing_enumeration(form, domain)
            if timing:
                findings.append(timing)

        # Test registration enumeration
        for url in register_urls[:3]:
            result = await self._test_register_enumeration(url, domain)
            if result:
                findings.append(result)

        # Test password reset enumeration
        for url in reset_urls[:3]:
            result = await self._test_reset_enumeration(url, domain)
            if result:
                findings.append(result)

        # Test API user enumeration
        api_results = await self._test_api_enumeration(base_url, domain)
        findings.extend(api_results)

        logger.info(f"Account enum: {len(findings)} findings")
        return findings

    # ── Endpoint Discovery ────────────────────────────────────────────

    async def _find_endpoints(self, base_url: str, endpoints: list,
                               paths: list, keywords: list) -> list[str]:
        """Find specific endpoint types by probing paths and checking discovered endpoints."""
        found = []

        # Check discovered endpoints
        for ep in endpoints:
            ep_url = ep.get("url") if isinstance(ep, dict) else ep
            if not ep_url or not isinstance(ep_url, str):
                continue
            lower = ep_url.lower()
            if any(kw in lower for kw in keywords):
                if ep_url not in found:
                    found.append(ep_url)

        # Probe common paths
        async with make_client(timeout=8.0, follow_redirects=True) as client:
            for path in paths:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                if url in found:
                    continue
                try:
                    async with self.rate_limit:
                        resp = await client.get(url)
                        if resp.status_code in (200, 405):
                            found.append(url)
                        elif resp.status_code == 405:
                            # Method not allowed on GET — try POST
                            found.append(url)
                except Exception:
                    continue

        return found

    async def _extract_login_form(self, url: str) -> dict | None:
        """Extract login form fields from a URL."""
        try:
            async with make_client(timeout=8.0) as client:
                async with self.rate_limit:
                    resp = await client.get(url)

                ct = resp.headers.get("content-type", "")

                # API endpoint (JSON)
                if "application/json" in ct or resp.status_code == 405:
                    return {
                        "url": url,
                        "type": "api",
                        "method": "POST",
                        "username_field": "username",
                        "password_field": "password",
                        "email_field": "email",
                        "extra_fields": {},
                    }

                # HTML form
                if "text/html" in ct:
                    return self._parse_login_form(resp.text, url)

                # Fallback
                return {
                    "url": url,
                    "type": "api",
                    "method": "POST",
                    "username_field": "username",
                    "password_field": "password",
                    "email_field": "email",
                    "extra_fields": {},
                }

        except Exception:
            return None

    def _parse_login_form(self, html: str, page_url: str) -> dict | None:
        """Parse HTML to find login form with username/password fields."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return None

        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            username_field = None
            password_field = None
            email_field = None
            extra_fields = {}

            for inp in inputs:
                inp_type = (inp.get("type") or "text").lower()
                inp_name = inp.get("name") or inp.get("id") or ""

                if inp_type == "password":
                    password_field = inp_name
                elif inp_type == "email":
                    email_field = inp_name
                    if not username_field:
                        username_field = inp_name
                elif inp_type in ("text",) and not username_field:
                    username_field = inp_name
                elif inp_type == "hidden":
                    extra_fields[inp_name] = inp.get("value", "")

            if password_field and username_field:
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
                    "username_field": username_field,
                    "password_field": password_field,
                    "email_field": email_field or username_field,
                    "extra_fields": extra_fields,
                }

        return None

    # ── Login Enumeration ─────────────────────────────────────────────

    async def _test_login_enumeration(self, form: dict, domain: str) -> dict | None:
        """Compare error messages for existing vs non-existing usernames."""
        url = form["url"]
        username_field = form["username_field"]
        password_field = form["password_field"]

        # Collect responses for likely-existing users
        existing_responses = []
        for user in LIKELY_EXISTING[:5]:
            resp = await self._submit_login(form, user, "WrongPassword_Phantom99!")
            if resp:
                existing_responses.append(resp)

        # Collect responses for definitely-fake users
        fake_responses = []
        for user in DEFINITELY_FAKE[:3]:
            resp = await self._submit_login(form, user, "WrongPassword_Phantom99!")
            if resp:
                fake_responses.append(resp)

        if not existing_responses or not fake_responses:
            return None

        # Compare error messages
        differentiators = []

        # 1. Status code difference
        existing_statuses = set(r["status"] for r in existing_responses)
        fake_statuses = set(r["status"] for r in fake_responses)
        if existing_statuses != fake_statuses:
            differentiators.append(
                f"Status codes differ: existing users → {existing_statuses}, "
                f"fake users → {fake_statuses}"
            )

        # 2. Error message difference
        existing_msgs = set()
        fake_msgs = set()
        for r in existing_responses:
            msg = self._extract_error_message(r["body"])
            if msg:
                existing_msgs.add(msg)
        for r in fake_responses:
            msg = self._extract_error_message(r["body"])
            if msg:
                fake_msgs.add(msg)

        if existing_msgs and fake_msgs and existing_msgs != fake_msgs:
            differentiators.append(
                f"Error messages differ: existing users → {list(existing_msgs)[:2]}, "
                f"fake users → {list(fake_msgs)[:2]}"
            )

        # 3. Check for explicit "user not found" vs "wrong password" messages
        for r in existing_responses:
            body = r["body"].lower()
            for pattern in WRONG_PASSWORD_PATTERNS:
                if re.search(pattern, body):
                    differentiators.append(f"Wrong-password message found for existing user")
                    break

        for r in fake_responses:
            body = r["body"].lower()
            for pattern in USER_NOT_FOUND_PATTERNS:
                if re.search(pattern, body):
                    differentiators.append(f"User-not-found message found for fake user")
                    break

        # 4. Response length difference
        existing_lens = [r["body_len"] for r in existing_responses]
        fake_lens = [r["body_len"] for r in fake_responses]
        avg_existing = statistics.mean(existing_lens) if existing_lens else 0
        avg_fake = statistics.mean(fake_lens) if fake_lens else 0
        if avg_existing > 0 and avg_fake > 0:
            diff_pct = abs(avg_existing - avg_fake) / max(avg_existing, avg_fake) * 100
            if diff_pct > 10:
                differentiators.append(
                    f"Response length differs by {diff_pct:.0f}%: "
                    f"existing avg={avg_existing:.0f}, fake avg={avg_fake:.0f}"
                )

        # 5. Header differences
        existing_headers = set()
        fake_headers = set()
        for r in existing_responses:
            for h in ["x-ratelimit-remaining", "x-ratelimit-limit", "retry-after"]:
                val = r.get("headers", {}).get(h, "")
                if val:
                    existing_headers.add(f"{h}: {val}")
        for r in fake_responses:
            for h in ["x-ratelimit-remaining", "x-ratelimit-limit", "retry-after"]:
                val = r.get("headers", {}).get(h, "")
                if val:
                    fake_headers.add(f"{h}: {val}")
        if existing_headers and fake_headers and existing_headers != fake_headers:
            differentiators.append(
                f"Rate-limit headers differ: existing → {list(existing_headers)[:2]}, "
                f"fake → {list(fake_headers)[:2]}"
            )

        if differentiators:
            return {
                "title": "Account enumeration via login error message differentiation",
                "url": url,
                "severity": "medium",
                "vuln_type": "info_disclosure",
                "payload": f"Compare login responses for existing vs non-existing users",
                "impact": f"The login endpoint reveals whether a username exists via different "
                          f"responses. Differences found: {'; '.join(differentiators[:3])}. "
                          f"Attackers can enumerate valid accounts before brute-forcing passwords.",
                "remediation": "Return the same error message, status code, and response length "
                               "for both valid and invalid usernames. Use generic messages like "
                               "'Invalid username or password'.",
            }
        return None

    async def _test_timing_enumeration(self, form: dict, domain: str) -> dict | None:
        """Measure response time for existing vs non-existing users.

        Existing users: server hashes password → slower
        Non-existing users: immediate rejection → faster
        """
        url = form["url"]
        num_samples = 5

        # Measure timing for likely-existing users
        existing_times = []
        for user in LIKELY_EXISTING[:num_samples]:
            resp = await self._submit_login(form, user, "WrongPassword_Phantom99!")
            if resp and resp.get("elapsed"):
                existing_times.append(resp["elapsed"])

        # Measure timing for fake users
        fake_times = []
        for user in DEFINITELY_FAKE[:num_samples]:
            resp = await self._submit_login(form, user, "WrongPassword_Phantom99!")
            if resp and resp.get("elapsed"):
                fake_times.append(resp["elapsed"])

        if len(existing_times) < 3 or len(fake_times) < 3:
            return None

        avg_existing = statistics.mean(existing_times)
        avg_fake = statistics.mean(fake_times)

        # Need at least 50ms difference and 30% relative difference
        abs_diff = abs(avg_existing - avg_fake)
        if abs_diff < 0.05:  # Less than 50ms
            return None

        max_avg = max(avg_existing, avg_fake)
        if max_avg == 0:
            return None
        rel_diff = abs_diff / max_avg

        if rel_diff > 0.30:
            slower = "existing" if avg_existing > avg_fake else "non-existing"
            return {
                "title": "Account enumeration via timing side-channel",
                "url": url,
                "severity": "low",
                "vuln_type": "info_disclosure",
                "payload": f"Timing analysis: {num_samples} requests per user class",
                "impact": f"Response times differ significantly between existing and "
                          f"non-existing users. Avg existing: {avg_existing*1000:.0f}ms, "
                          f"avg non-existing: {avg_fake*1000:.0f}ms "
                          f"(diff: {abs_diff*1000:.0f}ms, {rel_diff*100:.0f}%). "
                          f"The {slower} users are slower, suggesting the server performs "
                          f"additional work (e.g., password hashing) for valid accounts.",
                "remediation": "Always perform the same work for valid and invalid users. "
                               "Hash a dummy password even when the user doesn't exist "
                               "to equalize response times.",
            }
        return None

    # ── Registration Enumeration ──────────────────────────────────────

    async def _test_register_enumeration(self, url: str, domain: str) -> dict | None:
        """Check if registration reveals existing accounts."""
        # Determine what fields the registration endpoint expects
        reg_form = await self._analyze_register_endpoint(url)
        if not reg_form:
            return None

        enumerated_users = []

        for user in LIKELY_EXISTING[:5]:
            email = f"{user}@{domain}"
            try:
                async with make_client(timeout=8.0, follow_redirects=False) as client:
                    async with self.rate_limit:
                        data = dict(reg_form.get("extra_fields", {}))
                        # Fill registration fields
                        for field_name in reg_form.get("fields", {}):
                            lower = field_name.lower()
                            if "email" in lower:
                                data[field_name] = email
                            elif "user" in lower or "name" in lower:
                                data[field_name] = user
                            elif "pass" in lower:
                                data[field_name] = "PhantomTest123!@#"
                            else:
                                data[field_name] = "phantom_test_value"

                        # Also try common field names if form parsing failed
                        if not data or len(data) < 2:
                            data = {
                                "username": user,
                                "email": email,
                                "password": "PhantomTest123!@#",
                                "password_confirmation": "PhantomTest123!@#",
                            }

                        resp = await client.post(url, data=data)
                        body = resp.text.lower()

                        # Check for "already exists" indicators
                        for pattern in REG_EXISTS_PATTERNS:
                            if re.search(pattern, body):
                                enumerated_users.append(user)
                                break
            except Exception:
                continue

        # Also test with definitely-fake users to confirm they DON'T trigger the message
        fake_triggered = False
        for user in DEFINITELY_FAKE[:2]:
            email = f"{user}@{domain}"
            try:
                async with make_client(timeout=8.0, follow_redirects=False) as client:
                    async with self.rate_limit:
                        data = {
                            "username": user,
                            "email": email,
                            "password": "PhantomTest123!@#",
                            "password_confirmation": "PhantomTest123!@#",
                        }
                        resp = await client.post(url, data=data)
                        body = resp.text.lower()
                        for pattern in REG_EXISTS_PATTERNS:
                            if re.search(pattern, body):
                                fake_triggered = True
                                break
            except Exception:
                continue

        if enumerated_users and not fake_triggered:
            return {
                "title": "Account enumeration via registration endpoint",
                "url": url,
                "severity": "medium",
                "vuln_type": "info_disclosure",
                "payload": f"POST {url} with existing usernames/emails",
                "impact": f"Registration endpoint reveals existing accounts via "
                          f"'already registered' messages. Confirmed users: "
                          f"{', '.join(enumerated_users[:5])}",
                "remediation": "Use generic messages like 'If this email is not already "
                               "registered, a confirmation email will be sent'. "
                               "Alternatively, send an email to the address informing them "
                               "an account already exists.",
            }
        return None

    async def _analyze_register_endpoint(self, url: str) -> dict | None:
        """Analyze registration endpoint to extract form fields."""
        try:
            async with make_client(timeout=8.0) as client:
                async with self.rate_limit:
                    resp = await client.get(url)

                ct = resp.headers.get("content-type", "")
                if "text/html" in ct:
                    return self._parse_register_form(resp.text, url)

                # API endpoint — use common field names
                return {
                    "url": url,
                    "type": "api",
                    "fields": {"username": "", "email": "", "password": ""},
                    "extra_fields": {},
                }
        except Exception:
            return None

    def _parse_register_form(self, html: str, page_url: str) -> dict | None:
        """Parse registration form fields."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return {"url": page_url, "type": "api",
                    "fields": {"username": "", "email": "", "password": ""},
                    "extra_fields": {}}

        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            fields = {}
            extra_fields = {}

            for inp in inputs:
                inp_type = (inp.get("type") or "text").lower()
                inp_name = inp.get("name") or inp.get("id") or ""
                if inp_type == "hidden":
                    extra_fields[inp_name] = inp.get("value", "")
                elif inp_type in ("text", "email", "password", "tel"):
                    fields[inp_name] = ""

            if len(fields) >= 2:
                action = form.get("action", "")
                if action and not action.startswith("http"):
                    action = urljoin(page_url, action)
                elif not action:
                    action = page_url

                return {
                    "url": action,
                    "type": "form",
                    "fields": fields,
                    "extra_fields": extra_fields,
                }

        return None

    # ── Password Reset Enumeration ────────────────────────────────────

    async def _test_reset_enumeration(self, url: str, domain: str) -> dict | None:
        """Check if password reset reveals existing accounts."""
        # Determine field names
        reset_fields = await self._analyze_reset_endpoint(url)

        existing_responses = []
        fake_responses = []

        # Test with likely-existing emails
        for user in LIKELY_EXISTING[:4]:
            email = f"{user}@{domain}"
            resp = await self._submit_reset(url, email, reset_fields)
            if resp:
                existing_responses.append(resp)

        # Test with fake emails
        for user in DEFINITELY_FAKE[:3]:
            email = f"{user}@{domain}"
            resp = await self._submit_reset(url, email, reset_fields)
            if resp:
                fake_responses.append(resp)

        if not existing_responses or not fake_responses:
            return None

        differentiators = []

        # Status code difference
        existing_statuses = set(r["status"] for r in existing_responses)
        fake_statuses = set(r["status"] for r in fake_responses)
        if existing_statuses != fake_statuses:
            differentiators.append(
                f"Status codes: existing → {existing_statuses}, fake → {fake_statuses}"
            )

        # Error message difference
        existing_msgs = set()
        fake_msgs = set()
        for r in existing_responses:
            body = r["body"].lower()
            # Check for "user not found" in fake responses
            for pattern in USER_NOT_FOUND_PATTERNS:
                if re.search(pattern, body):
                    existing_msgs.add("user_found_pattern")
                    break
        for r in fake_responses:
            body = r["body"].lower()
            for pattern in USER_NOT_FOUND_PATTERNS:
                if re.search(pattern, body):
                    fake_msgs.add("user_not_found_pattern")
                    break

        if fake_msgs and not existing_msgs:
            differentiators.append(
                "Reset endpoint returns 'user not found' for non-existing accounts "
                "but different message for existing ones"
            )

        # Response body length difference
        existing_lens = [r["body_len"] for r in existing_responses]
        fake_lens = [r["body_len"] for r in fake_responses]
        avg_existing = statistics.mean(existing_lens) if existing_lens else 0
        avg_fake = statistics.mean(fake_lens) if fake_lens else 0
        if avg_existing > 0 and avg_fake > 0:
            diff_pct = abs(avg_existing - avg_fake) / max(avg_existing, avg_fake) * 100
            if diff_pct > 10:
                differentiators.append(
                    f"Response length differs by {diff_pct:.0f}%"
                )

        # Timing difference
        existing_times = [r.get("elapsed", 0) for r in existing_responses if r.get("elapsed")]
        fake_times = [r.get("elapsed", 0) for r in fake_responses if r.get("elapsed")]
        if len(existing_times) >= 2 and len(fake_times) >= 2:
            avg_et = statistics.mean(existing_times)
            avg_ft = statistics.mean(fake_times)
            if abs(avg_et - avg_ft) > 0.1:
                differentiators.append(
                    f"Timing: existing avg {avg_et*1000:.0f}ms, fake avg {avg_ft*1000:.0f}ms"
                )

        if differentiators:
            return {
                "title": "Account enumeration via password reset endpoint",
                "url": url,
                "severity": "medium",
                "vuln_type": "info_disclosure",
                "payload": f"POST {url} with existing vs fake emails",
                "impact": f"Password reset endpoint reveals whether an account exists. "
                          f"Differences: {'; '.join(differentiators[:3])}. "
                          f"Attackers can enumerate valid accounts.",
                "remediation": "Always return the same response regardless of whether the "
                               "email exists. Use 'If an account with that email exists, "
                               "a reset link has been sent.' for all cases.",
            }
        return None

    async def _analyze_reset_endpoint(self, url: str) -> dict:
        """Determine field names for password reset endpoint."""
        try:
            async with make_client(timeout=8.0) as client:
                async with self.rate_limit:
                    resp = await client.get(url)
                ct = resp.headers.get("content-type", "")
                if "text/html" in ct:
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(resp.text, "html.parser")
                        for form in soup.find_all("form"):
                            for inp in form.find_all("input"):
                                inp_name = (inp.get("name") or "").lower()
                                if "email" in inp_name:
                                    return {"email_field": inp.get("name")}
                    except ImportError:
                        pass
        except Exception:
            pass
        return {"email_field": "email"}

    async def _submit_reset(self, url: str, email: str, fields: dict) -> dict | None:
        """Submit password reset request."""
        email_field = fields.get("email_field", "email")
        try:
            async with make_client(timeout=8.0, follow_redirects=False) as client:
                async with self.rate_limit:
                    start = time.monotonic()
                    resp = await client.post(url, data={email_field: email})
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

    # ── API Enumeration ───────────────────────────────────────────────

    async def _test_api_enumeration(self, base_url: str, domain: str) -> list[dict]:
        """Test /api/users/{id} and user check endpoints."""
        findings = []
        found_endpoints = []

        async with make_client(timeout=8.0) as client:
            for path_template in API_ENUM_PATHS:
                for test_val in ["admin", "1", f"admin@{domain}"]:
                    path = path_template.replace("{id}", test_val)
                    path = path.replace("{username}", test_val)
                    path = path.replace("{email}", test_val)
                    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

                    try:
                        async with self.rate_limit:
                            resp = await client.get(url)

                            if resp.status_code == 200:
                                body = resp.text.lower()
                                # Check if response contains user data
                                if any(kw in body for kw in [
                                    '"email"', '"username"', '"user"', '"name"',
                                    '"id"', '"account"', '"profile"',
                                ]):
                                    found_endpoints.append({
                                        "url": url,
                                        "user": test_val,
                                        "body_preview": resp.text[:200],
                                    })
                                    break  # Found one, move to next template

                            elif resp.status_code == 404:
                                # Check if 404 message reveals user info
                                body = resp.text.lower()
                                if any(kw in body for kw in [
                                    "not found", "does not exist", "no user",
                                ]):
                                    # Now check if a different user DOES return data
                                    found_endpoints.append({
                                        "url": url,
                                        "user": test_val,
                                        "type": "404_enumeration",
                                        "body_preview": resp.text[:200],
                                    })
                                    break

                    except Exception:
                        continue

        # Verify by testing with fake user
        if found_endpoints:
            verified = []
            async with make_client(timeout=8.0) as client:
                for ep in found_endpoints[:5]:
                    fake_url = ep["url"].replace("admin", DEFINITELY_FAKE[0])
                    fake_url = fake_url.replace("1", "99999999")
                    fake_url = fake_url.replace(f"admin@{domain}",
                                                 f"{DEFINITELY_FAKE[0]}@{domain}")
                    try:
                        async with self.rate_limit:
                            resp = await client.get(fake_url)
                            if resp.status_code != 200:
                                verified.append(ep)
                            elif len(resp.text) != len(ep.get("body_preview", "")):
                                verified.append(ep)
                    except Exception:
                        verified.append(ep)

            if verified:
                urls = [v["url"] for v in verified[:3]]
                findings.append({
                    "title": "Account enumeration via API user lookup endpoint",
                    "url": urls[0],
                    "severity": "medium",
                    "vuln_type": "info_disclosure",
                    "payload": f"GET {urls[0]}",
                    "impact": f"API endpoints allow checking if a user exists. "
                              f"Found {len(verified)} enumerable endpoints: "
                              f"{', '.join(urls[:3])}. "
                              f"Returns different responses for valid vs invalid users.",
                    "remediation": "Require authentication for user lookup APIs. "
                                   "If public lookup is needed, implement rate limiting and "
                                   "CAPTCHA to prevent mass enumeration.",
                })

        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _submit_login(self, form: dict, username: str, password: str) -> dict | None:
        """Submit a login attempt and return response details."""
        try:
            async with make_client(timeout=10.0, follow_redirects=False) as client:
                async with self.rate_limit:
                    data = dict(form.get("extra_fields", {}))
                    data[form["username_field"]] = username
                    data[form["password_field"]] = password

                    start = time.monotonic()

                    if form["method"] == "POST":
                        # Try both form data and JSON
                        ct = "application/x-www-form-urlencoded"
                        if form.get("type") == "api":
                            resp = await client.post(form["url"], json=data)
                        else:
                            resp = await client.post(form["url"], data=data)
                    else:
                        resp = await client.get(form["url"], params=data)

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

    def _extract_error_message(self, body: str) -> str | None:
        """Extract the error/flash message from a response body."""
        body_lower = body.lower()

        # Try JSON
        try:
            data = json.loads(body)
            for key in ["message", "error", "detail", "msg", "errors"]:
                if key in data:
                    val = data[key]
                    if isinstance(val, str):
                        return val.lower().strip()
                    elif isinstance(val, list) and val:
                        return str(val[0]).lower().strip()
                    elif isinstance(val, dict):
                        return json.dumps(val).lower()
        except (json.JSONDecodeError, TypeError):
            pass

        # Try HTML alert/error elements
        patterns = [
            r'<div[^>]*class="[^"]*(?:alert|error|flash|message|notice)[^"]*"[^>]*>(.*?)</div>',
            r'<p[^>]*class="[^"]*(?:error|alert|message)[^"]*"[^>]*>(.*?)</p>',
            r'<span[^>]*class="[^"]*(?:error|alert)[^"]*"[^>]*>(.*?)</span>',
        ]
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                text = re.sub(r'<[^>]+>', '', match.group(1)).strip().lower()
                if text and len(text) < 200:
                    return text

        return None

    def _extract_domain(self, base_url: str) -> str:
        """Extract domain from base URL."""
        parsed = urlparse(base_url)
        return parsed.hostname or parsed.netloc or "example.com"
