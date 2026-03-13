"""
Auto-Register Module — Creates test accounts on targets to test authenticated surfaces.

Discovers registration endpoints, creates an account, logs in, and provides
JWT/session tokens to all subsequent pipeline phases. This is what separates
a real pentester from an automated scanner.
"""
import asyncio
import json
import logging
import random
import re
import string
import uuid

import httpx

logger = logging.getLogger(__name__)

# Common registration endpoint patterns
REGISTER_PATHS = [
    "/api/v1/auth/register", "/api/v2/auth/register",
    "/api/auth/register", "/api/register", "/auth/register",
    "/api/v1/register", "/api/v1/users/register",
    "/api/v1/signup", "/api/signup", "/auth/signup",
    "/api/v1/auth/signup", "/api/v2/auth/signup",
    "/register", "/signup", "/api/account/register",
    "/api/v1/account/register", "/api/v1/account/signup",
    "/users/register", "/users/signup",
    "/api/users", "/api/v1/users",  # POST = create user
]

LOGIN_PATHS = [
    "/api/v1/auth/login", "/api/v2/auth/login",
    "/api/auth/login", "/api/login", "/auth/login",
    "/api/v1/login", "/api/v1/auth/signin",
    "/api/v1/signin", "/api/signin", "/auth/signin",
    "/login", "/signin", "/api/account/login",
    "/api/v1/account/login", "/api/v1/sessions",
    "/api/token", "/oauth/token",
]

# JWT extraction patterns
JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

# Common registration field name variants
EMAIL_FIELDS = ["email", "mail", "emailAddress", "email_address", "user_email"]
PASSWORD_FIELDS = ["password", "passwd", "pass", "user_password", "pwd"]
NAME_FIELDS = ["fullName", "full_name", "name", "username", "displayName",
               "display_name", "firstName", "first_name", "login"]


class AutoRegister:
    """Automatically register a test account on the target and obtain auth tokens."""

    def __init__(self, context: dict):
        self.context = context or {}
        self.domain = self.context.get("domain", "")
        self.base_url = self.context.get("base_url", f"https://{self.domain}")
        self.rate_limit = self.context.get("rate_limit") or 5
        self.semaphore = asyncio.Semaphore(self.rate_limit)

        # Generated test credentials
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.test_email = f"phantom_test_{rand}@protonmail.com"
        self.test_password = f"Ph@nt0m_{uuid.uuid4().hex[:12]}"
        self.test_name = f"Phantom Tester {rand}"

        # Results
        self.access_token = None
        self.refresh_token = None
        self.token_type = "Bearer"
        self.user_id = None
        self.user_role = None
        self.session_cookies = {}
        self.register_endpoint = None
        self.login_endpoint = None

    async def run(self) -> dict:
        """Discover auth endpoints, register, login, return tokens."""
        results = {
            "registered": False,
            "authenticated": False,
            "access_token": None,
            "refresh_token": None,
            "token_type": "Bearer",
            "user_id": None,
            "user_role": None,
            "session_cookies": {},
            "test_email": self.test_email,
            "test_password": self.test_password,
            "register_endpoint": None,
            "login_endpoint": None,
            "auth_header": None,
            "findings": [],
        }

        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True, verify=False
        ) as client:
            # Step 1: Find register endpoint
            self.register_endpoint = await self._find_register_endpoint(client)
            if self.register_endpoint:
                results["register_endpoint"] = self.register_endpoint
                logger.info(f"Found register endpoint: {self.register_endpoint}")

                # Step 2: Register
                reg_result = await self._try_register(client)
                if reg_result:
                    results["registered"] = True
                    results["findings"].extend(reg_result.get("findings", []))

                    # If registration returned tokens directly
                    if reg_result.get("access_token"):
                        self._store_tokens(reg_result, results)

            # Step 3: Find login endpoint and login
            self.login_endpoint = await self._find_login_endpoint(client)
            if self.login_endpoint:
                results["login_endpoint"] = self.login_endpoint

                if not results["authenticated"]:
                    login_result = await self._try_login(client)
                    if login_result:
                        self._store_tokens(login_result, results)

            # Step 4: If we have a token, test what we can access
            if results["authenticated"]:
                extra_findings = await self._test_auth_surface(client, results)
                results["findings"].extend(extra_findings)

        return results

    def _store_tokens(self, token_data: dict, results: dict):
        """Extract and store tokens from auth response."""
        token = (token_data.get("access_token") or token_data.get("accessToken")
                 or token_data.get("token") or token_data.get("jwt"))
        if token:
            self.access_token = token
            results["access_token"] = token
            results["authenticated"] = True
            results["auth_header"] = f"Bearer {token}"

        refresh = token_data.get("refresh_token") or token_data.get("refreshToken")
        if refresh:
            self.refresh_token = refresh
            results["refresh_token"] = refresh

        # Extract user info from response or JWT
        user = token_data.get("user", {})
        uid = user.get("id") or token_data.get("user_id") or token_data.get("userId")
        if uid:
            self.user_id = uid
            results["user_id"] = uid

        role = user.get("role") or token_data.get("role")
        if role:
            self.user_role = role
            results["user_role"] = role

        # Try to decode JWT for user info
        if token and not uid:
            try:
                import base64
                parts = token.split(".")
                if len(parts) >= 2:
                    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded = json.loads(base64.b64decode(payload))
                    results["user_id"] = decoded.get("sub") or decoded.get("user_id")
                    results["user_role"] = decoded.get("role")
                    self.user_id = results["user_id"]
                    self.user_role = results["user_role"]
                    results["jwt_claims"] = decoded
            except Exception:
                pass

    async def _find_register_endpoint(self, client: httpx.AsyncClient) -> str | None:
        """Probe common registration paths."""
        # First check endpoints from context (extracted from JS)
        js_endpoints = self.context.get("js_api_endpoints", [])
        for ep in js_endpoints:
            ep_lower = str(ep).lower()
            if any(kw in ep_lower for kw in ["register", "signup", "sign-up"]):
                full = f"{self.base_url}{ep}" if ep.startswith("/") else ep
                if await self._check_endpoint(client, full, "POST"):
                    return full

        for path in REGISTER_PATHS:
            url = f"{self.base_url}{path}"
            if await self._check_endpoint(client, url, "POST"):
                return url
        return None

    async def _find_login_endpoint(self, client: httpx.AsyncClient) -> str | None:
        """Probe common login paths."""
        js_endpoints = self.context.get("js_api_endpoints", [])
        for ep in js_endpoints:
            ep_lower = str(ep).lower()
            if any(kw in ep_lower for kw in ["login", "signin", "sign-in", "token"]):
                full = f"{self.base_url}{ep}" if ep.startswith("/") else ep
                if await self._check_endpoint(client, full, "POST"):
                    return full

        for path in LOGIN_PATHS:
            url = f"{self.base_url}{path}"
            if await self._check_endpoint(client, url, "POST"):
                return url
        return None

    async def _check_endpoint(self, client: httpx.AsyncClient, url: str, method: str) -> bool:
        """Check if endpoint exists (returns non-404)."""
        try:
            async with self.semaphore:
                if method == "POST":
                    resp = await client.post(url, json={}, headers={"Content-Type": "application/json"})
                else:
                    resp = await client.options(url)
                # 400, 401, 405, 422 = endpoint exists; 404 = doesn't
                return resp.status_code != 404
        except Exception:
            return False

    async def _try_register(self, client: httpx.AsyncClient) -> dict | None:
        """Try different registration payload formats."""
        findings = []

        # Try multiple field name combinations
        payloads = [
            {"email": self.test_email, "password": self.test_password, "fullName": self.test_name},
            {"email": self.test_email, "password": self.test_password, "name": self.test_name},
            {"email": self.test_email, "password": self.test_password, "username": self.test_name},
            {"email": self.test_email, "password": self.test_password,
             "firstName": "Phantom", "lastName": "Tester"},
            {"emailAddress": self.test_email, "password": self.test_password, "displayName": self.test_name},
            {"login": self.test_email, "password": self.test_password},
        ]

        for payload in payloads:
            try:
                async with self.semaphore:
                    resp = await client.post(
                        self.register_endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                if resp.status_code in (200, 201):
                    data = resp.json()
                    logger.info(f"Registration successful at {self.register_endpoint}")

                    # Check for immediate token (no email verification = finding)
                    has_token = bool(
                        data.get("accessToken") or data.get("access_token")
                        or data.get("token") or data.get("jwt")
                    )
                    if has_token:
                        findings.append({
                            "title": "Registration returns auth token without email verification",
                            "vuln_type": "auth_bypass",
                            "severity": "high",
                            "url": self.register_endpoint,
                            "method": "POST",
                            "description": "User registration immediately returns an access token without requiring email verification. An attacker can create accounts with any email address.",
                            "impact": "Account impersonation, fake accounts, spam",
                            "remediation": "Require email verification before granting access tokens",
                            "ai_confidence": 0.95,
                        })
                    data["findings"] = findings
                    return data

                elif resp.status_code == 400:
                    body = resp.text.lower()
                    if "already registered" in body or "already exists" in body or "duplicate" in body:
                        findings.append({
                            "title": "User enumeration via registration endpoint",
                            "vuln_type": "info_disclosure",
                            "severity": "medium",
                            "url": self.register_endpoint,
                            "method": "POST",
                            "description": f"Registration endpoint reveals if an email is already registered: {resp.text[:200]}",
                            "impact": "Attacker can enumerate valid user emails",
                            "remediation": "Use generic error message: 'If this email is not registered, you will receive a confirmation'",
                            "ai_confidence": 0.9,
                        })

            except Exception as e:
                logger.debug(f"Register attempt failed: {e}")
                continue

        if findings:
            return {"findings": findings}
        return None

    async def _try_login(self, client: httpx.AsyncClient) -> dict | None:
        """Try to login with registered credentials."""
        payloads = [
            {"email": self.test_email, "password": self.test_password},
            {"username": self.test_email, "password": self.test_password},
            {"login": self.test_email, "password": self.test_password},
            {"emailAddress": self.test_email, "password": self.test_password},
        ]

        for payload in payloads:
            try:
                async with self.semaphore:
                    resp = await client.post(
                        self.login_endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("accessToken") or data.get("access_token") or data.get("token"):
                        logger.info(f"Login successful at {self.login_endpoint}")
                        return data

                    # Check for token in cookies
                    for cookie_name, cookie_val in resp.cookies.items():
                        if JWT_PATTERN.search(cookie_val):
                            return {"access_token": cookie_val, "token_type": "cookie"}

            except Exception as e:
                logger.debug(f"Login attempt failed: {e}")
                continue

        return None

    async def _test_auth_surface(self, client: httpx.AsyncClient, results: dict) -> list[dict]:
        """With auth token, test for common authenticated vulnerabilities."""
        findings = []
        headers = {"Authorization": f"Bearer {self.access_token}"}

        # Test 1: Rate limiting on login
        findings.extend(await self._test_login_rate_limit(client))

        # Test 2: Trial/subscription abuse
        findings.extend(await self._test_subscription_abuse(client, headers))

        # Test 3: IDOR user enumeration
        findings.extend(await self._test_idor_users(client, headers))

        # Test 4: Stored XSS in profile
        findings.extend(await self._test_stored_xss_profile(client, headers))

        return findings

    async def _test_login_rate_limit(self, client: httpx.AsyncClient) -> list[dict]:
        """Test if login has rate limiting."""
        if not self.login_endpoint:
            return []

        success_count = 0
        for i in range(10):
            try:
                async with self.semaphore:
                    resp = await client.post(
                        self.login_endpoint,
                        json={"email": "nonexistent@test.com", "password": f"wrong{i}"},
                        headers={"Content-Type": "application/json"},
                    )
                if resp.status_code in (401, 400, 200):
                    success_count += 1
            except Exception:
                break

        if success_count >= 10:
            return [{
                "title": "No rate limiting on login endpoint",
                "vuln_type": "auth_bypass",
                "severity": "high",
                "url": self.login_endpoint,
                "method": "POST",
                "description": f"Login endpoint accepted {success_count}/10 rapid requests without rate limiting or account lockout",
                "impact": "Credential brute-force attacks are possible",
                "remediation": "Implement rate limiting (5 attempts per 15 minutes) and account lockout",
                "ai_confidence": 0.95,
            }]
        return []

    async def _test_subscription_abuse(self, client: httpx.AsyncClient, headers: dict) -> list[dict]:
        """Test for free subscription/trial abuse."""
        findings = []
        trial_paths = [
            "/api/v1/subscription/start-trial",
            "/api/subscription/start-trial",
            "/api/v1/trial/start",
            "/api/trial/activate",
        ]

        for path in trial_paths:
            try:
                url = f"{self.base_url}{path}"
                async with self.semaphore:
                    resp = await client.post(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    days = data.get("daysRemaining") or data.get("trialDays") or 0
                    if days > 30:
                        findings.append({
                            "title": f"Excessive free trial: {days} days premium access",
                            "vuln_type": "business_logic",
                            "severity": "high",
                            "url": url,
                            "method": "POST",
                            "description": f"Trial subscription grants {days} days of premium access. Any registered user can activate this.",
                            "impact": "Complete bypass of payment/subscription system",
                            "remediation": "Limit trial to 7-14 days, enforce one trial per user/email",
                            "payload_used": "POST with auth token",
                            "ai_confidence": 0.95,
                            "response_data": data,
                        })
            except Exception:
                continue

        return findings

    async def _test_idor_users(self, client: httpx.AsyncClient, headers: dict) -> list[dict]:
        """Test for IDOR by enumerating user IDs with authenticated token."""
        findings = []
        user_paths = [
            "/api/v1/users/{id}", "/api/v1/user/{id}", "/api/users/{id}",
            "/api/v1/profiles/{id}", "/api/v1/members/{id}",
            "/api/v1/accounts/{id}", "/api/accounts/{id}",
        ]

        for path_template in user_paths:
            # First test with our own user_id to confirm endpoint exists
            if self.user_id:
                own_url = f"{self.base_url}{path_template.replace('{id}', str(self.user_id))}"
                try:
                    async with self.semaphore:
                        resp = await client.get(own_url, headers=headers)
                    if resp.status_code != 200:
                        continue
                except Exception:
                    continue
            else:
                # Try ID 1 to see if endpoint exists
                test_url = f"{self.base_url}{path_template.replace('{id}', '1')}"
                try:
                    async with self.semaphore:
                        resp = await client.get(test_url, headers=headers)
                    if resp.status_code == 404:
                        continue
                except Exception:
                    continue

            # Endpoint exists — enumerate IDs 1-10
            accessible_count = 0
            pii_found = False
            sample_data = None
            for test_id in range(1, 11):
                if self.user_id and str(test_id) == str(self.user_id):
                    continue
                test_url = f"{self.base_url}{path_template.replace('{id}', str(test_id))}"
                try:
                    async with self.semaphore:
                        resp = await client.get(test_url, headers=headers)
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        if len(body) > 20 and "not found" not in body[:100]:
                            accessible_count += 1
                            if any(kw in body for kw in ("email", "phone", "password", "address")):
                                pii_found = True
                            if not sample_data:
                                sample_data = resp.text[:500]
                except Exception:
                    continue

            if accessible_count >= 3:
                severity = "critical" if pii_found else "high"
                findings.append({
                    "title": f"IDOR — User enumeration via {path_template} ({accessible_count} users accessible)",
                    "vuln_type": "idor",
                    "severity": severity,
                    "url": f"{self.base_url}{path_template}",
                    "method": "GET",
                    "description": (
                        f"Authenticated user can access other users' data by incrementing ID. "
                        f"Tested IDs 1-10: {accessible_count} returned data. "
                        f"{'PII (email/phone/address) exposed.' if pii_found else 'User data exposed.'}"
                    ),
                    "impact": "Mass user data exfiltration via sequential ID enumeration",
                    "remediation": "Implement authorization: verify the requesting user owns the resource. Use UUIDs instead of sequential IDs.",
                    "ai_confidence": 0.95,
                    "response_data": {"accessible_count": accessible_count, "pii_found": pii_found,
                                      "sample": sample_data},
                })
                break  # One finding per pattern is enough

        return findings

    async def _test_stored_xss_profile(self, client: httpx.AsyncClient, headers: dict) -> list[dict]:
        """Test for stored XSS in profile update endpoints."""
        findings = []
        profile_paths = [
            ("/api/v1/users/me", "PUT"), ("/api/v1/users/me", "PATCH"),
            ("/api/v1/profile", "PUT"), ("/api/v1/profile", "PATCH"),
            ("/api/v1/account", "PUT"), ("/api/users/me", "PUT"),
        ]
        xss_payloads = {
            "fullName": '<script>alert(1)</script>',
            "bio": '<img src=x onerror=alert(document.cookie)>',
            "website": 'javascript:alert(1)',
            "company": '"><svg/onload=alert(1)>',
        }

        for path, method in profile_paths:
            url = f"{self.base_url}{path}"
            for field, payload in xss_payloads.items():
                try:
                    body = {field: payload}
                    async with self.semaphore:
                        if method == "PUT":
                            resp = await client.put(url, json=body, headers=headers)
                        else:
                            resp = await client.patch(url, json=body, headers=headers)

                    if resp.status_code in (200, 201):
                        if payload in resp.text:
                            findings.append({
                                "title": f"Stored XSS in profile field '{field}'",
                                "vuln_type": "xss",
                                "severity": "high",
                                "url": url,
                                "method": method,
                                "description": (
                                    f"XSS payload in '{field}' stored and reflected without sanitization. "
                                    f"Any user viewing this profile will execute the injected script."
                                ),
                                "impact": "Session hijacking, credential theft, account takeover via stored XSS",
                                "remediation": "Sanitize all user input. Use output encoding. Set Content-Security-Policy.",
                                "payload_used": f"{field}={payload}",
                                "ai_confidence": 0.95,
                            })
                            return findings  # One proof is enough
                    elif resp.status_code == 404:
                        break  # Path doesn't exist
                except Exception:
                    continue

        return findings
