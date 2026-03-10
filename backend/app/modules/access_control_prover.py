"""
Access Control Prover — Verifies broken access control by testing endpoints:
1. Without authentication -> should get 401/403
2. With different user tokens -> should not see other users' data
3. With sequential/harvested IDs -> proves IDOR

Saves PROOF: actual HTTP request + response as evidence.

This module transforms "potential" findings into PROVEN vulnerabilities
by performing real requests and capturing full request/response evidence.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.utils.http_client import make_client
from app.utils.spa_detector import is_spa_shell, is_real_data_response

logger = logging.getLogger(__name__)

# REST API patterns that commonly have access control issues
REST_PATTERNS = [
    re.compile(r"/api/(?:v\d+/)?users?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?accounts?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?orders?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?profiles?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?payments?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?transactions?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?invoices?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?documents?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?files?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?messages?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?tickets?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?reports?(?:/(\d+))?"),
    re.compile(r"/api/(?:v\d+/)?settings"),
    re.compile(r"/api/(?:v\d+/)?admin"),
    re.compile(r"/api/(?:v\d+/)?[^/]+/(\d+)"),
    re.compile(r"/api/(?:v\d+/)?[^/]+/([0-9a-f-]{36})"),  # UUID
]

# Sensitive JSON keys that indicate PII or confidential data
PII_KEYS = {
    "email", "e_mail", "mail", "emailAddress", "email_address",
    "phone", "phone_number", "phoneNumber", "mobile", "tel",
    "name", "first_name", "last_name", "full_name", "firstName",
    "lastName", "fullName", "username", "user_name",
    "address", "street", "city", "zip", "postal_code", "zipCode",
    "ssn", "social_security", "tax_id", "national_id",
    "balance", "amount", "price", "total", "salary", "income",
    "card", "card_number", "cardNumber", "cvv", "expiry",
    "password", "secret", "token", "api_key", "apiKey",
    "dob", "date_of_birth", "birthday", "birth_date",
}

# Regex patterns for PII detection in raw text
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
CARD_RE = re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Indicators that a response is a login/error page, not real data
LOGIN_PAGE_INDICATORS = [
    "login", "sign in", "signin", "log in", "authenticate",
    "password", "forgot password", "register", "sign up",
]

# Auth-related headers to strip when testing unauthenticated access
AUTH_HEADERS = {"authorization", "cookie", "x-auth-token", "x-api-key", "x-csrf-token"}


class AccessControlProver:
    """Proves broken access control by making real HTTP requests
    and capturing evidence of unauthorized data access."""

    def __init__(self, context: dict):
        """
        Args:
            context: Scan context dict containing:
                - base_url: Target base URL
                - auth_cookie: Session cookie for authenticated requests
                - endpoints: List of discovered endpoints
                - harvested_ids: List of IDs found during scanning
                - rate_limit: Max concurrent requests (default 5)
        """
        self.base_url = context.get("base_url", "").rstrip("/")
        self.auth_cookie = context.get("auth_cookie", "")
        self.auth_header = context.get("auth_header", "")
        self.harvested_ids = context.get("harvested_ids", [])
        self.rate_limit = context.get("rate_limit") or 5
        self.context = context
        self.findings: list[dict] = []
        self._request_count = 0
        self._max_requests = context.get("max_requests", 5000)

    async def prove_all(self, endpoints: list[dict], db=None) -> list[dict]:
        """Test all endpoints for access control issues.

        Filters to API endpoints, runs parallel tests, and returns
        a list of PROVEN findings with full evidence.

        Args:
            endpoints: List of endpoint dicts with 'url', 'method', etc.
            db: Optional database session for saving findings.

        Returns:
            List of proven finding dicts with complete evidence.
        """
        api_endpoints = self._filter_api_endpoints(endpoints)
        logger.info(
            "AccessControlProver: testing %d API endpoints (from %d total)",
            len(api_endpoints),
            len(endpoints),
        )

        if not api_endpoints:
            logger.info("No API endpoints found to test")
            return []

        semaphore = asyncio.Semaphore(min(10, self.rate_limit * 2))
        proven_findings: list[dict] = []

        # Phase 1: Test unauthenticated access on all API endpoints
        unauth_tasks = []
        for ep in api_endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                unauth_tasks.append(
                    self._bounded_test(
                        semaphore,
                        self._test_endpoint_unauth,
                        url,
                        method,
                    )
                )

        unauth_results = await asyncio.gather(*unauth_tasks, return_exceptions=True)
        for result in unauth_results:
            if isinstance(result, Exception):
                logger.debug("Unauth test error: %s", result)
                continue
            if result and result.get("vulnerable"):
                proven_findings.append(result)

        # Phase 2: Test IDOR with harvested/sequential IDs
        idor_endpoints = self._find_idor_candidates(api_endpoints)
        idor_tasks = []
        for ep_info in idor_endpoints:
            url = ep_info["url"]
            param = ep_info.get("param", "id")
            ids_to_test = self._prepare_test_ids(ep_info)
            if ids_to_test:
                idor_tasks.append(
                    self._bounded_test(
                        semaphore,
                        self._test_idor_with_ids,
                        url,
                        param,
                        ids_to_test,
                        self.auth_cookie,
                    )
                )

        idor_results = await asyncio.gather(*idor_tasks, return_exceptions=True)
        for result in idor_results:
            if isinstance(result, Exception):
                logger.debug("IDOR test error: %s", result)
                continue
            if isinstance(result, list):
                proven_findings.extend([r for r in result if r.get("proven")])

        # Phase 3: Sequential ID enumeration on high-value endpoints
        seq_endpoints = self._find_sequential_candidates(api_endpoints)
        seq_tasks = []
        for ep_info in seq_endpoints[:5]:  # Limit to 5 endpoints
            seq_tasks.append(
                self._bounded_test(
                    semaphore,
                    self._test_sequential_ids,
                    ep_info["base_url"],
                    ep_info["param_name"],
                    start=1,
                    end=100,  # Conservative range for proving
                )
            )

        seq_results = await asyncio.gather(*seq_tasks, return_exceptions=True)
        for result in seq_results:
            if isinstance(result, Exception):
                logger.debug("Sequential ID test error: %s", result)
                continue
            if isinstance(result, list) and result:
                for item in result:
                    if item.get("proven"):
                        proven_findings.append(item)

        logger.info(
            "AccessControlProver: %d proven findings from %d requests",
            len(proven_findings),
            self._request_count,
        )
        self.findings = proven_findings
        return proven_findings

    async def _test_endpoint_unauth(self, url: str, method: str = "GET") -> dict:
        """Test an endpoint WITHOUT authentication.

        If the endpoint returns 200 with meaningful data when no auth is
        provided, this is a proven broken access control issue.

        Args:
            url: Full URL to test.
            method: HTTP method (GET, POST, etc.).

        Returns:
            Dict with 'vulnerable' bool and 'proof' if vulnerable.
        """
        if self._request_count >= self._max_requests:
            return {"vulnerable": False, "reason": "request_limit_reached"}

        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
        }

        try:
            async with make_client(extra_headers=request_headers, timeout=15.0) as client:
                self._request_count += 1
                response = await client.request(method, url)

                status = response.status_code
                body = response.text[:5000]
                content_type = response.headers.get("content-type", "")

                # Not vulnerable if proper auth rejection
                if status in (401, 403, 407):
                    return {"vulnerable": False, "status": status}

                # Not vulnerable if redirect to login
                if status in (301, 302, 307, 308):
                    location = response.headers.get("location", "").lower()
                    if any(ind in location for ind in LOGIN_PAGE_INDICATORS):
                        return {"vulnerable": False, "status": status, "redirect": "login"}

                # Check if 200 with real data
                if status == 200 and len(body.strip()) > 50:
                    body_lower = body[:2000].lower()

                    # Skip if response body indicates auth rejection (200 + error message)
                    auth_reject_phrases = [
                        "unauthenticated", "unauthorized", "not authorized",
                        "access denied", "forbidden", "permission denied",
                        "authentication required", "not authenticated",
                        "token expired", "invalid token", "session expired",
                        "requires authentication", "auth required",
                        "must be logged in", "please log in",
                    ]
                    if any(phrase in body_lower for phrase in auth_reject_phrases):
                        return {"vulnerable": False, "reason": "auth_rejection_in_body"}

                    # Skip if response is a login page
                    if any(ind in body_lower for ind in LOGIN_PAGE_INDICATORS):
                        login_score = sum(1 for ind in LOGIN_PAGE_INDICATORS if ind in body_lower)
                        if login_score >= 2:
                            return {"vulnerable": False, "reason": "login_page"}

                    # SPA shell detection — React/Vue/Angular index.html is NOT real data
                    if is_spa_shell(body, content_type):
                        return {"vulnerable": False, "reason": "SPA HTML shell (not real data)"}

                    # Check for meaningful data
                    is_json = "application/json" in content_type
                    has_data = False

                    if is_json:
                        try:
                            data = json.loads(body)
                            if isinstance(data, list) and len(data) > 0:
                                has_data = True
                            elif isinstance(data, dict) and len(data) > 1:
                                # Exclude empty error responses
                                if not all(k in ("error", "message", "status") for k in data.keys()):
                                    has_data = True
                        except (json.JSONDecodeError, ValueError):
                            pass
                    else:
                        # Non-JSON: check for real data, not just large HTML
                        if is_real_data_response(body, content_type):
                            has_data = True

                    if has_data:
                        sensitive = self._extract_sensitive_data(body)
                        req_info = {
                            "url": url,
                            "method": method,
                            "headers": request_headers,
                            "body": None,
                            "auth": "none",
                        }
                        resp_info = {
                            "status_code": status,
                            "headers": dict(response.headers),
                            "body_preview": body[:3000],
                            "body_size": len(response.text),
                            "content_type": content_type,
                        }
                        proof = self._build_proof(
                            req_info,
                            resp_info,
                            "broken_access_control",
                        )
                        proof["sensitive_data"] = sensitive

                        # Build reproduction steps
                        proof["reproduction_steps"] = self._build_unauth_steps(
                            url, method, status, sensitive, body
                        )

                        return {"vulnerable": True, "proof": proof}

                return {"vulnerable": False, "status": status}

        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            logger.debug("Request failed for %s: %s", url, exc)
            return {"vulnerable": False, "error": str(exc)}
        except Exception as exc:
            logger.debug("Unexpected error testing %s: %s", url, exc)
            return {"vulnerable": False, "error": str(exc)}

    async def _test_idor_with_ids(
        self,
        url: str,
        param: str,
        ids: list,
        auth_cookie: str = None,
    ) -> list[dict]:
        """Test IDOR by substituting IDs in the URL or query parameters.

        For each ID, makes a request and compares the response to detect
        horizontal/vertical privilege escalation.

        Args:
            url: URL template with {id} placeholder or query parameter.
            param: Parameter name to substitute.
            ids: List of IDs to test (harvested + sequential).
            auth_cookie: Optional auth cookie for authenticated IDOR tests.

        Returns:
            List of proven IDOR finding dicts.
        """
        proven_findings: list[dict] = []
        baseline_response = None
        baseline_body_hash = None

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, */*",
        }
        if auth_cookie:
            headers["Cookie"] = auth_cookie

        async with make_client(extra_headers=headers, timeout=15.0) as client:
            for test_id in ids:
                if self._request_count >= self._max_requests:
                    break

                # Build the test URL
                test_url = self._substitute_id(url, param, str(test_id))
                if not test_url:
                    continue

                try:
                    self._request_count += 1
                    response = await client.get(test_url)

                    if response.status_code == 200 and len(response.text.strip()) > 20:
                        body = response.text[:5000]
                        body_hash = hash(body[:500])

                        # First valid response becomes baseline
                        if baseline_response is None:
                            baseline_response = body
                            baseline_body_hash = body_hash
                            continue

                        # Different content from baseline = IDOR confirmed
                        if body_hash != baseline_body_hash:
                            sensitive = self._extract_sensitive_data(body)
                            req_info = {
                                "url": test_url,
                                "method": "GET",
                                "headers": headers,
                                "body": None,
                                "auth": "cookie" if auth_cookie else "none",
                            }
                            resp_info = {
                                "status_code": 200,
                                "headers": dict(response.headers),
                                "body_preview": body[:3000],
                                "body_size": len(response.text),
                                "content_type": response.headers.get("content-type", ""),
                            }

                            finding_type = "idor_horizontal"
                            if "/admin" in test_url.lower():
                                finding_type = "idor_vertical"

                            proof = self._build_proof(req_info, resp_info, finding_type)
                            proof["sensitive_data"] = sensitive
                            proof["tested_id"] = test_id
                            proof["param"] = param
                            proof["reproduction_steps"] = [
                                f"1. Send GET request to {test_url}",
                                f"2. {'Include' if auth_cookie else 'No'} authentication cookie",
                                f"3. Response returns 200 with {len(body)} bytes of data",
                                f"4. Content differs from baseline — different user's data exposed",
                            ]
                            if sensitive["pii_found"]:
                                proof["reproduction_steps"].append(
                                    f"5. Response contains PII: {', '.join(sensitive['types'])}"
                                )

                            proven_findings.append(proof)

                            # Stop after 10 confirmed findings per endpoint
                            if len(proven_findings) >= 10:
                                break

                    elif response.status_code == 429:
                        # Rate limited — back off
                        await asyncio.sleep(2.0)

                except (httpx.TimeoutException, httpx.ConnectError):
                    continue
                except Exception as exc:
                    logger.debug("IDOR test error for %s: %s", test_url, exc)
                    continue

                # Small delay between requests
                await asyncio.sleep(0.1)

        return proven_findings

    async def _test_sequential_ids(
        self,
        base_url: str,
        param_name: str,
        start: int = 1,
        end: int = 1000,
    ) -> list[dict]:
        """Enumerate sequential IDs to prove predictable object references.

        Tries IDs from start to end, stopping after 10 valid responses.

        Args:
            base_url: URL template with {id} placeholder.
            param_name: Name of the ID parameter.
            start: Starting ID (default 1).
            end: Ending ID (default 1000).

        Returns:
            List of proven findings with response samples.
        """
        semaphore = asyncio.Semaphore(50)
        valid_responses: list[dict] = []
        not_found_count = 0
        stop_event = asyncio.Event()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, */*",
        }
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie

        async def probe_id(test_id: int) -> None:
            nonlocal not_found_count

            if stop_event.is_set() or self._request_count >= self._max_requests:
                return

            test_url = self._substitute_id(base_url, param_name, str(test_id))
            if not test_url:
                return

            async with semaphore:
                if stop_event.is_set():
                    return
                try:
                    async with make_client(extra_headers=headers, timeout=10.0) as client:
                        self._request_count += 1
                        response = await client.get(test_url)

                        if response.status_code == 200 and len(response.text.strip()) > 20:
                            body = response.text[:3000]
                            sensitive = self._extract_sensitive_data(body)
                            valid_responses.append({
                                "id": test_id,
                                "url": test_url,
                                "status": 200,
                                "body_preview": body[:1000],
                                "body_size": len(response.text),
                                "sensitive_data": sensitive,
                            })
                            if len(valid_responses) >= 10:
                                stop_event.set()
                        elif response.status_code in (404, 410):
                            not_found_count += 1
                        elif response.status_code == 429:
                            await asyncio.sleep(2.0)

                except (httpx.TimeoutException, httpx.ConnectError):
                    pass
                except Exception as exc:
                    logger.debug("Sequential ID probe error: %s", exc)

        # Process in batches to be respectful
        batch_size = 50
        for batch_start in range(start, end + 1, batch_size):
            if stop_event.is_set() or self._request_count >= self._max_requests:
                break
            batch_end = min(batch_start + batch_size, end + 1)
            tasks = [probe_id(i) for i in range(batch_start, batch_end)]
            await asyncio.gather(*tasks, return_exceptions=True)
            # Brief pause between batches
            await asyncio.sleep(0.2)

        # Build findings from results
        proven_findings: list[dict] = []
        if len(valid_responses) >= 3:
            # At least 3 valid IDs = predictable enumeration proven
            sample_ids = [r["id"] for r in valid_responses[:5]]
            any_pii = any(r["sensitive_data"]["pii_found"] for r in valid_responses)

            req_info = {
                "url": base_url,
                "method": "GET",
                "headers": headers,
                "body": None,
                "auth": "cookie" if self.auth_cookie else "none",
            }
            resp_info = {
                "status_code": 200,
                "headers": {},
                "body_preview": valid_responses[0]["body_preview"],
                "body_size": valid_responses[0]["body_size"],
                "content_type": "application/json",
            }

            proof = self._build_proof(req_info, resp_info, "idor_horizontal")
            proof["sensitive_data"] = valid_responses[0]["sensitive_data"]
            proof["enumeration_results"] = {
                "valid_ids_found": len(valid_responses),
                "sample_ids": sample_ids,
                "total_tested": min(end - start + 1, self._request_count),
                "pii_exposed": any_pii,
            }
            proof["reproduction_steps"] = [
                f"1. Send GET requests to {base_url} with sequential IDs",
                f"2. IDs {sample_ids} return 200 with user data",
                f"3. Found {len(valid_responses)} valid records out of {min(end - start + 1, self._request_count)} tested",
            ]
            if any_pii:
                pii_types = set()
                for r in valid_responses:
                    pii_types.update(r["sensitive_data"].get("types", []))
                proof["reproduction_steps"].append(
                    f"4. Exposed PII types: {', '.join(sorted(pii_types))}"
                )

            proven_findings.append(proof)

        return proven_findings

    def _extract_sensitive_data(self, response_body: str) -> dict:
        """Detect PII and sensitive data in response content.

        Checks for emails, phone numbers, credit card numbers, and
        sensitive JSON keys.

        Args:
            response_body: Raw response body text.

        Returns:
            Dict with pii_found, types list, sample, and count.
        """
        result = {
            "pii_found": False,
            "types": [],
            "samples": [],
            "count": 0,
        }

        # Email detection
        emails = EMAIL_RE.findall(response_body)
        if emails:
            result["types"].append("email")
            # Redact for safe storage — show pattern only
            sample = emails[0]
            result["samples"].append(f"{sample[:3]}...@{sample.split('@')[-1]}")
            result["count"] += len(emails)

        # Phone detection
        phones = PHONE_RE.findall(response_body)
        if phones:
            result["types"].append("phone")
            result["samples"].append(f"{phones[0][:4]}...{phones[0][-2:]}")
            result["count"] += len(phones)

        # Credit card detection
        cards = CARD_RE.findall(response_body)
        if cards:
            result["types"].append("credit_card")
            result["samples"].append(f"{cards[0][:4]}...{cards[0][-4:]}")
            result["count"] += len(cards)

        # SSN detection
        ssns = SSN_RE.findall(response_body)
        if ssns:
            result["types"].append("ssn")
            result["samples"].append("***-**-****")
            result["count"] += len(ssns)

        # JSON key-based detection
        try:
            data = json.loads(response_body)
            json_pii = self._scan_json_keys(data)
            for pii_type, count in json_pii.items():
                if pii_type not in result["types"]:
                    result["types"].append(pii_type)
                result["count"] += count
        except (json.JSONDecodeError, ValueError):
            pass

        result["pii_found"] = len(result["types"]) > 0
        return result

    def _scan_json_keys(self, data, depth: int = 0) -> dict:
        """Recursively scan JSON for sensitive key names.

        Args:
            data: Parsed JSON data (dict or list).
            depth: Current recursion depth (max 5).

        Returns:
            Dict mapping PII type to count.
        """
        if depth > 5:
            return {}

        found: dict[str, int] = {}

        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower().replace("-", "_")
                if key_lower in PII_KEYS or any(pk in key_lower for pk in PII_KEYS):
                    pii_type = self._classify_key(key_lower)
                    if pii_type:
                        found[pii_type] = found.get(pii_type, 0) + 1

                # Recurse into nested structures
                if isinstance(value, (dict, list)):
                    nested = self._scan_json_keys(value, depth + 1)
                    for k, v in nested.items():
                        found[k] = found.get(k, 0) + v

        elif isinstance(data, list):
            # Only scan first 5 items to limit work
            for item in data[:5]:
                if isinstance(item, (dict, list)):
                    nested = self._scan_json_keys(item, depth + 1)
                    for k, v in nested.items():
                        found[k] = found.get(k, 0) + v

        return found

    def _classify_key(self, key: str) -> str | None:
        """Classify a JSON key into a PII category."""
        if any(k in key for k in ("email", "mail")):
            return "email"
        if any(k in key for k in ("phone", "mobile", "tel")):
            return "phone"
        if any(k in key for k in ("card", "cvv", "expir")):
            return "financial"
        if any(k in key for k in ("name", "first", "last", "full")):
            return "name"
        if any(k in key for k in ("address", "street", "city", "zip", "postal")):
            return "address"
        if any(k in key for k in ("balance", "amount", "price", "total", "salary", "income")):
            return "financial"
        if any(k in key for k in ("ssn", "social_security", "tax_id", "national_id")):
            return "government_id"
        if any(k in key for k in ("password", "secret", "token", "api_key")):
            return "credential"
        if any(k in key for k in ("dob", "birth", "birthday")):
            return "date_of_birth"
        return None

    def _build_proof(
        self,
        request_info: dict,
        response_info: dict,
        finding_type: str,
    ) -> dict:
        """Build a complete proof-of-concept structure.

        Args:
            request_info: Dict with url, method, headers, body, auth.
            response_info: Dict with status_code, headers, body_preview, body_size.
            finding_type: One of 'broken_access_control', 'idor_horizontal', 'idor_vertical'.

        Returns:
            Complete PoC dict ready for evidence storage.
        """
        return {
            "proven": True,
            "finding_type": finding_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request": {
                "url": request_info.get("url", ""),
                "method": request_info.get("method", "GET"),
                "headers": self._sanitize_headers(request_info.get("headers", {})),
                "body": request_info.get("body"),
                "auth": request_info.get("auth", "none"),
            },
            "response": {
                "status_code": response_info.get("status_code", 0),
                "headers": self._sanitize_response_headers(
                    response_info.get("headers", {})
                ),
                "body_preview": response_info.get("body_preview", "")[:3000],
                "body_size": response_info.get("body_size", 0),
                "content_type": response_info.get("content_type", ""),
            },
            "sensitive_data": {},
            "reproduction_steps": [],
        }

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _filter_api_endpoints(self, endpoints: list[dict]) -> list[dict]:
        """Filter endpoints to those likely to be API/REST resources."""
        api_endpoints = []
        seen_urls = set()

        for ep in endpoints:
            url = ep.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            path = urlparse(url).path.lower()

            # Direct API path match
            is_api = (
                "/api/" in path
                or "/rest/" in path
                or "/v1/" in path
                or "/v2/" in path
                or "/v3/" in path
                or "/graphql" in path
            )

            # JSON content-type in previous response
            content_type = ep.get("content_type", "")
            if "json" in content_type:
                is_api = True

            # REST pattern match
            if not is_api:
                for pattern in REST_PATTERNS:
                    if pattern.search(path):
                        is_api = True
                        break

            # Traditional web app endpoints with parameters are also worth testing
            if not is_api:
                parsed = urlparse(url)
                # Has query parameters with ID-like names
                if parsed.query:
                    param_names = [p.split("=")[0].lower() for p in parsed.query.split("&") if "=" in p]
                    sensitive_params = {"id", "uid", "user", "user_id", "userid", "account", "file",
                                       "page", "action", "admin", "order", "order_id", "profile",
                                       "doc", "report", "download", "cat", "pid", "aid"}
                    if sensitive_params & set(param_names):
                        is_api = True

                # Admin/dashboard/panel paths
                if not is_api and any(seg in path for seg in ("/admin", "/dashboard", "/panel", "/manage", "/settings", "/config", "/user")):
                    is_api = True

                # PHP/JSP/ASP endpoints with query params
                if not is_api and parsed.query and any(path.endswith(ext) for ext in (".php", ".jsp", ".asp", ".aspx")):
                    is_api = True

            if is_api:
                api_endpoints.append(ep)

        # Limit to max 100 endpoints to avoid being too slow
        return api_endpoints[:100]

    def _find_idor_candidates(self, endpoints: list[dict]) -> list[dict]:
        """Find endpoints with ID parameters suitable for IDOR testing."""
        candidates = []

        for ep in endpoints:
            url = ep.get("url", "")
            path = urlparse(url).path

            # Check URL path for IDs
            for pattern in REST_PATTERNS:
                match = pattern.search(path)
                if match and match.lastindex and match.group(1):
                    original_id = match.group(1)
                    # Build template URL with {id} placeholder
                    template = url[:match.start(1)] + "{id}" + url[match.end(1):]
                    candidates.append({
                        "url": template,
                        "original_url": url,
                        "param": "id",
                        "original_id": original_id,
                        "method": ep.get("method", "GET"),
                    })
                    break

            # Check query parameters for IDs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name, values in params.items():
                if param_name.lower().replace("-", "_") in {
                    "id", "user_id", "userid", "uid", "account_id",
                    "accountid", "profile_id", "profileid", "order_id",
                    "orderid", "doc_id", "docid", "file_id", "fileid",
                    "invoice_id", "invoiceid", "payment_id", "paymentid",
                }:
                    candidates.append({
                        "url": url,
                        "param": param_name,
                        "original_id": values[0] if values else None,
                        "method": ep.get("method", "GET"),
                    })

        return candidates

    def _find_sequential_candidates(self, endpoints: list[dict]) -> list[dict]:
        """Find endpoints with numeric IDs suitable for sequential enumeration."""
        candidates = []
        seen = set()

        for ep in endpoints:
            url = ep.get("url", "")
            path = urlparse(url).path

            # Look for numeric IDs in path
            match = re.search(r"/(\d+)(?:/|$|\?)", path)
            if match:
                numeric_id = match.group(1)
                # Build base URL with {id} placeholder
                template = url[:match.start(1)] + "{id}" + url[match.end(1):]
                if template not in seen:
                    seen.add(template)
                    candidates.append({
                        "base_url": template,
                        "param_name": "id",
                        "original_id": int(numeric_id),
                    })

        return candidates

    def _prepare_test_ids(self, ep_info: dict) -> list:
        """Build a list of IDs to test for an endpoint."""
        ids = []

        # Include harvested IDs first (higher chance of being valid)
        if self.harvested_ids:
            ids.extend(self.harvested_ids[:50])

        # Add sequential IDs around the original
        original_id = ep_info.get("original_id")
        if original_id is not None:
            try:
                orig_int = int(original_id)
                # Test IDs near the original
                for offset in range(-5, 20):
                    candidate = orig_int + offset
                    if candidate > 0 and candidate != orig_int:
                        ids.append(candidate)
            except (ValueError, TypeError):
                pass

        # Add common test IDs
        ids.extend([1, 2, 3, 5, 10, 100, 999, 1000])

        # Deduplicate while preserving order
        seen = set()
        unique_ids = []
        for i in ids:
            i_str = str(i)
            if i_str not in seen:
                seen.add(i_str)
                unique_ids.append(i)

        return unique_ids[:100]  # Cap at 100 IDs per endpoint

    def _substitute_id(self, url: str, param: str, new_id: str) -> str | None:
        """Replace an ID in a URL path or query parameter.

        Args:
            url: URL template (may contain {id}) or full URL with query params.
            param: Parameter name to substitute.
            new_id: New ID value.

        Returns:
            Modified URL string, or None if substitution failed.
        """
        # Path placeholder
        if "{id}" in url:
            return url.replace("{id}", new_id)

        # Query parameter substitution
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param in params:
            params[param] = [new_id]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        return None

    def _sanitize_headers(self, headers: dict) -> dict:
        """Remove sensitive auth values from request headers for safe storage."""
        sanitized = {}
        for key, value in headers.items():
            if key.lower() in AUTH_HEADERS:
                sanitized[key] = "[REDACTED]" if value else "none"
            else:
                sanitized[key] = value
        return sanitized

    def _sanitize_response_headers(self, headers: dict) -> dict:
        """Trim response headers to relevant security headers only."""
        relevant = {
            "content-type", "content-length", "server", "x-powered-by",
            "access-control-allow-origin", "x-frame-options",
            "strict-transport-security", "set-cookie", "www-authenticate",
            "cache-control", "x-ratelimit-remaining",
        }
        return {
            k: v for k, v in headers.items()
            if k.lower() in relevant
        }

    def _build_unauth_steps(
        self,
        url: str,
        method: str,
        status: int,
        sensitive: dict,
        body: str,
    ) -> list[str]:
        """Build human-readable reproduction steps for unauthenticated access."""
        steps = [
            f"1. Send {method} request to {url} without Authorization header",
            f"2. Response returns {status} with {len(body)} bytes of data",
        ]

        if sensitive["pii_found"]:
            steps.append(
                f"3. Response contains sensitive data: {', '.join(sensitive['types'])}"
            )
            if sensitive.get("count", 0) > 1:
                steps.append(
                    f"4. Total {sensitive['count']} sensitive data points exposed"
                )
        else:
            steps.append("3. Response contains data that should require authentication")

        return steps

    async def _bounded_test(self, semaphore: asyncio.Semaphore, func, *args, **kwargs):
        """Run a test function with semaphore-bounded concurrency."""
        async with semaphore:
            return await func(*args, **kwargs)
