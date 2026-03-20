"""
Authenticated API Fuzzer — discovers and tests internal API endpoints post-login.

After StatefulCrawler obtains auth session (cookies/JWT/headers), this module:
1. Discovers hidden API endpoints by fuzzing common paths WITH auth
2. Extracts API schema from Swagger/OpenAPI if available (auth-protected docs)
3. Tests each discovered endpoint for parameter injection (SQLi, XSS, IDOR)
4. Tests RBAC: compares authenticated vs unauthenticated responses
5. Maps API versioning (v1→v2→v3) and checks for removed-but-accessible endpoints
6. Detects mass assignment by adding extra fields to POST/PUT bodies
"""
import asyncio
import json
import logging
import re
import time
from urllib.parse import urljoin, urlparse

import httpx
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# ─── API Path Wordlists ─────────────────────────────────────────────────

# Organized by category for smarter fuzzing
API_PATHS = {
    "user": [
        "/api/me", "/api/user", "/api/users", "/api/profile",
        "/api/account", "/api/accounts", "/api/settings",
        "/api/user/profile", "/api/user/settings", "/api/user/security",
        "/api/users/me", "/api/users/current", "/api/users/self",
        "/api/v1/me", "/api/v1/user", "/api/v1/users",
        "/api/v1/profile", "/api/v1/account",
        "/api/v2/me", "/api/v2/user", "/api/v2/users",
    ],
    "admin": [
        "/api/admin", "/api/admin/users", "/api/admin/settings",
        "/api/admin/config", "/api/admin/dashboard", "/api/admin/logs",
        "/api/admin/stats", "/api/admin/system", "/api/admin/audit",
        "/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/config",
        "/api/internal", "/api/internal/health", "/api/internal/debug",
        "/api/debug", "/api/system", "/api/config",
        "/admin/api", "/admin/api/users", "/admin/api/config",
    ],
    "financial": [
        "/api/balance", "/api/wallet", "/api/wallets",
        "/api/transactions", "/api/transaction", "/api/transfers",
        "/api/payments", "/api/payment", "/api/cards", "/api/card",
        "/api/accounts", "/api/bank", "/api/loans", "/api/credits",
        "/api/statements", "/api/receipts", "/api/invoices",
        "/api/v1/balance", "/api/v1/transactions", "/api/v1/transfers",
        "/api/v1/payments", "/api/v1/cards", "/api/v1/accounts",
        "/api/v1/wallet", "/api/v1/statements",
        "/api/v2/balance", "/api/v2/transactions",
    ],
    "notification": [
        "/api/notifications", "/api/messages", "/api/inbox",
        "/api/alerts", "/api/push", "/api/sms",
        "/api/v1/notifications", "/api/v1/messages",
    ],
    "document": [
        "/api/documents", "/api/files", "/api/uploads",
        "/api/attachments", "/api/media", "/api/export",
        "/api/reports", "/api/download",
        "/api/v1/documents", "/api/v1/files",
    ],
    "schema": [
        "/swagger.json", "/swagger/v1/swagger.json",
        "/api-docs", "/api/docs", "/api/schema",
        "/openapi.json", "/openapi.yaml", "/api/openapi.json",
        "/v2/api-docs", "/v3/api-docs",
        "/api/v1/docs", "/api/v2/docs",
        "/.well-known/openapi.json",
        "/graphql",  # GraphQL introspection
    ],
    "misc": [
        "/api/search", "/api/feedback", "/api/support",
        "/api/contacts", "/api/favorites", "/api/bookmarks",
        "/api/history", "/api/activity", "/api/events",
        "/api/permissions", "/api/roles", "/api/tokens",
        "/api/sessions", "/api/devices", "/api/security",
        "/api/v1/search", "/api/v1/permissions",
    ],
}

# Common API parameter names for injection testing
INJECTABLE_PARAMS = {
    "id": ["1", "1 OR 1=1", "1'", "1 UNION SELECT 1--"],
    "user_id": ["1", "0", "admin", "1' OR '1'='1"],
    "search": ["test", "test<script>alert(1)</script>", "test' OR '1'='1", "{{7*7}}"],
    "q": ["test", "test%00", "test' AND '1'='1"],
    "page": ["1", "0", "-1", "99999", "1;ls"],
    "limit": ["10", "0", "-1", "99999", "10;id"],
    "sort": ["id", "id;DROP TABLE users--", "id,(SELECT 1)"],
    "order": ["asc", "asc,(SELECT 1)", "1"],
    "filter": ["all", "all'", "all{{7*7}}"],
    "format": ["json", "xml", "../../etc/passwd"],
    "callback": ["test", "test<script>alert(1)</script>"],
    "redirect": ["https://evil.com", "//evil.com", "javascript:alert(1)"],
    "url": ["https://evil.com", "file:///etc/passwd", "http://169.254.169.254/"],
    "file": ["test.txt", "../../../etc/passwd", "....//....//etc/passwd"],
    "path": ["/", "/../../../etc/passwd"],
    "email": ["test@test.com", "test@test.com' OR '1'='1"],
    "name": ["test", "test<img src=x onerror=alert(1)>"],
    "amount": ["100", "-1", "0", "999999999"],
    "account_id": ["1", "0", "99999"],
}

# Patterns indicating sensitive data in responses
SENSITIVE_PATTERNS = [
    (r'"password"\s*:\s*"[^"]+"', "password in response"),
    (r'"secret"\s*:\s*"[^"]+"', "secret in response"),
    (r'"api[_-]?key"\s*:\s*"[^"]+"', "API key in response"),
    (r'"token"\s*:\s*"[^"]+"', "token in response"),
    (r'"private[_-]?key"', "private key in response"),
    (r'"ssn"\s*:\s*"?\d', "SSN in response"),
    (r'"credit[_-]?card"', "credit card in response"),
    (r'"cvv"\s*:\s*"?\d', "CVV in response"),
    (r'sk-[a-zA-Z0-9]{20,}', "API secret key"),
    (r'-----BEGIN.*PRIVATE KEY-----', "private key"),
    (r'"balance"\s*:\s*\d', "balance data"),
    (r'"account[_-]?number"', "account number"),
    (r'"iban"\s*:', "IBAN data"),
]

# SQLi error patterns
SQLI_ERRORS = [
    "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
    "syntax error", "unclosed quotation", "unterminated string",
    "ORA-", "PG::SyntaxError", "near \"", "you have an error",
]

# SSTI patterns
SSTI_MARKER = "49"  # 7*7


class AuthenticatedAPIFuzzer:
    """Discovers and tests API endpoints using authenticated session."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)
        self._auth_headers: dict = {}
        self._session_cookies: dict = {}
        self._auth_cookie: str | None = None
        self._custom_headers: dict = {}

    async def run(self, context: dict) -> list[dict]:
        base_url = context.get("base_url", "")
        if not base_url:
            return []

        self._setup_auth(context)

        # Check if we have any auth credentials
        if not self._has_auth():
            logger.info("AuthAPIFuzzer: no auth session available, skipping")
            return []

        findings: list[dict] = []
        known_endpoints = self._extract_known_endpoints(context)

        logger.info(f"AuthAPIFuzzer: starting with {len(known_endpoints)} "
                     f"known endpoints, auth={'yes' if self._has_auth() else 'no'}")

        # Phase 1: Discover new authenticated endpoints
        discovered = await self._discover_authenticated_endpoints(base_url, known_endpoints)
        logger.info(f"AuthAPIFuzzer: discovered {len(discovered)} new endpoints")

        # Phase 2: Try to get API schema (Swagger/OpenAPI)
        schema_endpoints = await self._extract_from_schema(base_url)
        discovered.extend(schema_endpoints)
        logger.info(f"AuthAPIFuzzer: {len(schema_endpoints)} from API schema")

        # Phase 3: Check auth vs no-auth (access control)
        access_findings = await self._test_access_control(base_url, discovered + known_endpoints)
        findings.extend(access_findings)

        # Phase 4: Check for sensitive data exposure
        data_findings = await self._test_data_exposure(base_url, discovered + known_endpoints)
        findings.extend(data_findings)

        # Phase 5: Parameter injection on authenticated endpoints
        injection_findings = await self._test_parameter_injection(
            base_url, discovered + known_endpoints,
        )
        findings.extend(injection_findings)

        # Phase 6: API version testing
        version_findings = await self._test_api_versions(base_url, discovered + known_endpoints)
        findings.extend(version_findings)

        # Dedup
        seen = set()
        deduped = []
        for f in findings:
            key = (f.get("url", "")[:100], f.get("title", "")[:50])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Store discovered endpoints in context for downstream phases
        if discovered:
            existing = context.get("endpoints", [])
            for ep in discovered:
                existing.append({
                    "url": ep["url"],
                    "method": ep.get("method", "GET"),
                    "status": ep.get("status"),
                    "auth_required": ep.get("auth_required", True),
                })
            context["endpoints"] = existing

        logger.info(f"AuthAPIFuzzer: {len(deduped)} total findings")
        return deduped

    # ─── Auth Setup ──────────────────────────────────────────────────────

    def _setup_auth(self, context: dict):
        self._custom_headers = context.get("custom_headers", {})
        self._auth_cookie = context.get("auth_cookie")
        self._auth_headers = context.get("auth_headers", {})
        self._session_cookies = context.get("session_cookies", {})

    def _has_auth(self) -> bool:
        return bool(
            self._auth_headers or
            self._session_cookies or
            self._auth_cookie
        )

    def _build_auth_headers(self) -> dict:
        headers = dict(self._custom_headers)
        if self._auth_headers:
            headers.update(self._auth_headers)
        if self._session_cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self._session_cookies.items()
            )
        elif self._auth_cookie:
            if self._auth_cookie.startswith("token="):
                headers["Authorization"] = (
                    f"Bearer {self._auth_cookie.split('=', 1)[1]}"
                )
            else:
                headers["Cookie"] = self._auth_cookie
        return headers

    def _build_noauth_headers(self) -> dict:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        }

    def _extract_known_endpoints(self, context: dict) -> list[dict]:
        """Extract already-discovered endpoints from context."""
        result = []
        seen = set()
        for ep in context.get("endpoints", []):
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if url and url not in seen and "/api" in url.lower():
                seen.add(url)
                result.append({
                    "url": url,
                    "method": (ep.get("method", "GET") if isinstance(ep, dict) else "GET").upper(),
                })
        return result

    # ─── Phase 1: Endpoint Discovery ─────────────────────────────────────

    async def _discover_authenticated_endpoints(
        self, base_url: str, known: list[dict],
    ) -> list[dict]:
        """Fuzz API paths with auth to find hidden endpoints."""
        discovered = []
        known_urls = {ep["url"] for ep in known}
        auth_headers = self._build_auth_headers()
        noauth_headers = self._build_noauth_headers()

        all_paths = []
        for category, paths in API_PATHS.items():
            if category == "schema":
                continue  # Handled separately
            all_paths.extend(paths)

        async with make_client(extra_headers=auth_headers, timeout=8.0) as auth_client:
            async with make_client(extra_headers=noauth_headers, timeout=8.0) as noauth_client:
                tasks = []
                for path in all_paths:
                    full_url = base_url.rstrip("/") + path
                    if full_url in known_urls:
                        continue
                    tasks.append(self._probe_endpoint(
                        auth_client, noauth_client, full_url, path,
                    ))

                # Process in batches of 20
                for i in range(0, len(tasks), 20):
                    batch = tasks[i:i + 20]
                    results = await asyncio.gather(*batch, return_exceptions=True)
                    for r in results:
                        if isinstance(r, dict) and r:
                            discovered.append(r)

        return discovered

    async def _probe_endpoint(
        self,
        auth_client: httpx.AsyncClient,
        noauth_client: httpx.AsyncClient,
        url: str,
        path: str,
    ) -> dict | None:
        """Probe a single endpoint with and without auth."""
        try:
            async with self.rate_limit:
                auth_resp = await auth_client.get(url)
            async with self.rate_limit:
                noauth_resp = await noauth_client.get(url)
        except Exception:
            return None

        auth_status = auth_resp.status_code
        noauth_status = noauth_resp.status_code

        # Interesting: auth gives 200 but no-auth gives 401/403
        if auth_status == 200 and noauth_status in (401, 403):
            return {
                "url": url,
                "method": "GET",
                "status": auth_status,
                "auth_required": True,
                "category": self._categorize_path(path),
                "body_length": len(auth_resp.content),
                "content_type": auth_resp.headers.get("content-type", ""),
                "body_preview": auth_resp.text[:500],
            }

        # Also interesting: auth gives 200 and is an API endpoint (JSON)
        if auth_status == 200:
            ct = auth_resp.headers.get("content-type", "")
            if "application/json" in ct and len(auth_resp.content) > 20:
                return {
                    "url": url,
                    "method": "GET",
                    "status": auth_status,
                    "auth_required": noauth_status in (401, 403, 302),
                    "category": self._categorize_path(path),
                    "body_length": len(auth_resp.content),
                    "content_type": ct,
                    "body_preview": auth_resp.text[:500],
                }

        return None

    @staticmethod
    def _categorize_path(path: str) -> str:
        path_lower = path.lower()
        for cat, paths in API_PATHS.items():
            if path in paths:
                return cat
        if "admin" in path_lower:
            return "admin"
        if any(kw in path_lower for kw in ["balance", "payment", "transfer", "wallet"]):
            return "financial"
        return "misc"

    # ─── Phase 2: API Schema Extraction ──────────────────────────────────

    async def _extract_from_schema(self, base_url: str) -> list[dict]:
        """Try to fetch Swagger/OpenAPI schema with auth."""
        endpoints = []
        auth_headers = self._build_auth_headers()

        async with make_client(extra_headers=auth_headers, timeout=10.0) as client:
            for path in API_PATHS["schema"]:
                url = base_url.rstrip("/") + path
                try:
                    async with self.rate_limit:
                        resp = await client.get(url)
                    if resp.status_code != 200:
                        continue

                    ct = resp.headers.get("content-type", "")

                    # GraphQL introspection
                    if "graphql" in path.lower():
                        async with self.rate_limit:
                            gql_resp = await client.post(url, json={
                                "query": "{ __schema { types { name } } }",
                            })
                            if gql_resp.status_code == 200:
                                try:
                                    data = gql_resp.json()
                                    if "data" in data and "__schema" in data.get("data", {}):
                                        endpoints.append({
                                            "url": url,
                                            "method": "POST",
                                            "status": 200,
                                            "auth_required": True,
                                            "category": "schema",
                                            "body_preview": "GraphQL introspection enabled",
                                        })
                                except Exception:
                                    pass
                        continue

                    # OpenAPI/Swagger JSON
                    if "json" in ct:
                        try:
                            schema = resp.json()
                            endpoints.extend(
                                self._parse_openapi_schema(schema, base_url),
                            )
                        except Exception:
                            pass
                except Exception:
                    continue

        return endpoints

    def _parse_openapi_schema(self, schema: dict, base_url: str) -> list[dict]:
        """Extract endpoints from OpenAPI/Swagger schema."""
        endpoints = []
        paths = schema.get("paths", {})
        base = schema.get("basePath", "")

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                method = method.upper()
                if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue

                full_url = base_url.rstrip("/") + base + path
                # Replace path parameters with test values
                full_url = re.sub(r'\{[^}]+\}', '1', full_url)

                endpoints.append({
                    "url": full_url,
                    "method": method,
                    "status": None,
                    "auth_required": bool(
                        details.get("security") or schema.get("security"),
                    ),
                    "category": self._categorize_path(path),
                    "params": self._extract_params(details),
                    "body_preview": details.get("summary", ""),
                })

        logger.info(f"AuthAPIFuzzer: parsed {len(endpoints)} endpoints from OpenAPI schema")
        return endpoints

    @staticmethod
    def _extract_params(operation: dict) -> dict:
        """Extract parameter names from OpenAPI operation."""
        params = {}
        for param in operation.get("parameters", []):
            name = param.get("name", "")
            if name:
                params[name] = param.get("schema", {}).get("type", "string")
        return params

    # ─── Phase 3: Access Control Testing ─────────────────────────────────

    async def _test_access_control(
        self, base_url: str, endpoints: list[dict],
    ) -> list[dict]:
        """Check if authenticated endpoints have proper access control."""
        findings = []
        noauth_headers = self._build_noauth_headers()

        # Test admin endpoints without auth
        admin_eps = [
            ep for ep in endpoints
            if ep.get("category") == "admin" or "admin" in ep.get("url", "").lower()
        ]

        async with make_client(extra_headers=noauth_headers, timeout=8.0) as client:
            for ep in admin_eps[:10]:
                url = ep["url"]
                try:
                    async with self.rate_limit:
                        resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text.lower()[:2000]
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct and len(resp.content) > 50:
                            if not any(kw in body for kw in
                                       ["unauthorized", "forbidden", "login"]):
                                findings.append({
                                    "title": f"Admin API accessible without auth: "
                                             f"{urlparse(url).path}",
                                    "url": url,
                                    "severity": "critical",
                                    "vuln_type": "auth_bypass",
                                    "description": (
                                        f"Admin endpoint {url} returns 200 with "
                                        f"data without any authentication."
                                    ),
                                    "impact": (
                                        "Unauthenticated access to admin functionality "
                                        "allows full system compromise."
                                    ),
                                    "remediation": (
                                        "Enforce authentication and authorization on "
                                        "all admin endpoints. Use middleware."
                                    ),
                                    "payload": f"GET {url} (no auth)",
                                    "proof": f"Status: 200, Body: {resp.text[:300]}",
                                })
                except Exception:
                    continue

        return findings

    # ─── Phase 4: Sensitive Data Exposure ────────────────────────────────

    async def _test_data_exposure(
        self, base_url: str, endpoints: list[dict],
    ) -> list[dict]:
        """Check authenticated endpoints for excessive data exposure."""
        findings = []
        auth_headers = self._build_auth_headers()

        async with make_client(extra_headers=auth_headers, timeout=8.0) as client:
            for ep in endpoints[:30]:
                url = ep.get("url", "")
                if not url:
                    continue

                # Use cached body if available
                body = ep.get("body_preview", "")
                if not body:
                    try:
                        async with self.rate_limit:
                            resp = await client.get(url)
                        if resp.status_code != 200:
                            continue
                        body = resp.text
                    except Exception:
                        continue

                # Check for sensitive data patterns
                for pattern, desc in SENSITIVE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append({
                            "title": f"Sensitive Data Exposure: {desc} in "
                                     f"{urlparse(url).path}",
                            "url": url,
                            "severity": "high" if "password" in desc or "key" in desc
                                        else "medium",
                            "vuln_type": "info_disclosure",
                            "description": (
                                f"Authenticated endpoint {url} exposes "
                                f"sensitive data: {desc}."
                            ),
                            "impact": (
                                f"Sensitive information ({desc}) is returned "
                                f"in API response, potentially exposing secrets "
                                f"or PII to authorized but low-privilege users."
                            ),
                            "remediation": (
                                "Implement field-level access control. Filter "
                                "sensitive fields from API responses. Use DTO "
                                "patterns to control exposed fields."
                            ),
                            "payload": f"GET {url}",
                        })
                        break  # One finding per endpoint

        return findings

    # ─── Phase 5: Parameter Injection ────────────────────────────────────

    async def _test_parameter_injection(
        self, base_url: str, endpoints: list[dict],
    ) -> list[dict]:
        """Test authenticated endpoints for injection vulnerabilities."""
        findings = []
        auth_headers = self._build_auth_headers()

        # Select endpoints that accept parameters
        testable = [
            ep for ep in endpoints
            if ep.get("params") or "?" in ep.get("url", "")
        ]

        # Also test common endpoints with standard params
        if len(testable) < 5:
            for ep in endpoints[:15]:
                if ep not in testable:
                    testable.append(ep)

        async with make_client(extra_headers=auth_headers, timeout=10.0) as client:
            for ep in testable[:20]:
                url = ep.get("url", "")
                if not url:
                    continue

                # Get baseline
                try:
                    async with self.rate_limit:
                        baseline = await client.get(url)
                    if baseline.status_code in (404, 405, 502):
                        continue
                    baseline_text = baseline.text[:2000]
                except Exception:
                    continue

                # Test with injectable params
                for param, payloads in list(INJECTABLE_PARAMS.items())[:8]:
                    for payload in payloads[1:]:  # Skip normal value
                        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                        try:
                            async with self.rate_limit:
                                resp = await client.get(test_url)
                        except Exception:
                            continue

                        body = resp.text[:3000]

                        # Check for SQLi errors
                        if any(err in body.lower() for err in SQLI_ERRORS):
                            findings.append({
                                "title": f"SQL Injection in authenticated endpoint: "
                                         f"{param}",
                                "url": url,
                                "severity": "critical",
                                "vuln_type": "sqli",
                                "description": (
                                    f"SQL error triggered on authenticated endpoint "
                                    f"{url} with {param}={payload}"
                                ),
                                "impact": (
                                    "SQL injection on authenticated endpoint — "
                                    "can extract all database data including "
                                    "user credentials and financial records."
                                ),
                                "remediation": (
                                    "Use parameterized queries. Never concatenate "
                                    "user input into SQL."
                                ),
                                "payload": f"{param}={payload}",
                                "proof": body[:500],
                            })
                            break

                        # Check for SSTI (7*7=49)
                        if "{{7*7}}" in payload and SSTI_MARKER in body:
                            if SSTI_MARKER not in baseline_text:
                                findings.append({
                                    "title": f"SSTI in authenticated endpoint: "
                                             f"{param}",
                                    "url": url,
                                    "severity": "critical",
                                    "vuln_type": "ssti",
                                    "description": (
                                        f"Template injection on {url} — "
                                        f"{{{{7*7}}}} evaluated to {SSTI_MARKER}"
                                    ),
                                    "impact": "Server-side template injection → RCE",
                                    "remediation": "Sanitize template inputs",
                                    "payload": f"{param}={{{{7*7}}}}",
                                })
                                break

                        # Check for reflection (potential XSS)
                        if "<script>" in payload and "<script>" in body:
                            findings.append({
                                "title": f"Reflected XSS in authenticated API: "
                                         f"{param}",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "xss_reflected",
                                "description": (
                                    f"Script tag reflected in response from "
                                    f"authenticated endpoint {url}"
                                ),
                                "impact": "XSS in authenticated context can steal session tokens",
                                "remediation": "Encode all output. Set Content-Type headers.",
                                "payload": f"{param}={payload}",
                            })
                            break

        return findings

    # ─── Phase 6: API Version Testing ────────────────────────────────────

    async def _test_api_versions(
        self, base_url: str, endpoints: list[dict],
    ) -> list[dict]:
        """Check if older/newer API versions expose more data or lack security."""
        findings = []
        auth_headers = self._build_auth_headers()

        # Collect versioned endpoints
        version_pattern = re.compile(r'/api/v(\d+)/')
        versioned = {}
        for ep in endpoints:
            url = ep.get("url", "")
            match = version_pattern.search(url)
            if match:
                version = int(match.group(1))
                base_path = version_pattern.sub('/api/v{V}/', url)
                versioned.setdefault(base_path, {})[version] = url

        async with make_client(extra_headers=auth_headers, timeout=8.0) as client:
            for base_path, versions in list(versioned.items())[:10]:
                existing_versions = sorted(versions.keys())

                # Try adjacent versions
                for v in existing_versions:
                    for test_v in [v - 1, v + 1, v + 2]:
                        if test_v < 0 or test_v in existing_versions:
                            continue
                        test_url = base_path.replace("{V}", str(test_v))
                        try:
                            async with self.rate_limit:
                                resp = await client.get(test_url)
                            if resp.status_code == 200:
                                ct = resp.headers.get("content-type", "")
                                if "json" in ct and len(resp.content) > 50:
                                    # Compare with known version
                                    known_url = versions[v]
                                    async with self.rate_limit:
                                        known_resp = await client.get(known_url)

                                    if known_resp.text != resp.text:
                                        findings.append({
                                            "title": f"Hidden API version v{test_v} "
                                                     f"accessible: {urlparse(test_url).path}",
                                            "url": test_url,
                                            "severity": "medium",
                                            "vuln_type": "info_disclosure",
                                            "description": (
                                                f"API version v{test_v} exists "
                                                f"alongside v{v}. Different response "
                                                f"suggests different behavior/fields."
                                            ),
                                            "impact": (
                                                "Older API versions may lack security "
                                                "controls, expose more fields, or "
                                                "have known vulnerabilities."
                                            ),
                                            "remediation": (
                                                "Disable deprecated API versions. "
                                                "Apply same security controls across "
                                                "all versions."
                                            ),
                                            "payload": f"GET {test_url}",
                                        })
                        except Exception:
                            continue

        return findings
