"""
IDOR (Insecure Direct Object Reference) Proof Engine

Goes beyond detection — PROVES IDOR vulnerabilities with actual response data:
1. ID Cross-Pollination: uses IDs harvested from other endpoints
2. Sequential ID Bruteforce: tries IDs 1-1000 with semaphore-limited concurrency
3. Proof Collection: captures full request/response data as evidence
4. Sensitive Data Detection: identifies PII, financial, auth tokens in leaked data
5. Auth vs Unauth Testing: compares authed, unauthed, and substituted-ID responses
6. Horizontal, Vertical, Parameter Tampering, Auth-Context — all with proof
"""
import asyncio
import base64
import json
import logging
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import httpx

from app.utils.http_client import make_client
from app.utils.spa_detector import is_spa_shell

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IDOR_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "profile_id", "profileid", "order_id", "orderid", "doc_id",
    "docid", "file_id", "fileid", "invoice_id", "invoiceid",
    "payment_id", "paymentid", "transaction_id", "transactionid",
    "report_id", "reportid", "message_id", "messageid",
    "ticket_id", "ticketid", "comment_id", "commentid",
    "ref", "file", "doc", "document", "object", "obj",
    "item_id", "itemid", "project_id", "projectid",
    "org_id", "orgid", "team_id", "teamid",
    "customer_id", "customerid", "member_id", "memberid",
    "subscription_id", "subscriptionid",
}

IDOR_PATH_PATTERNS = [
    (r'/api/(?:v\d+/)?users?/(\d+)', "user"),
    (r'/api/(?:v\d+/)?accounts?/(\d+)', "user"),
    (r'/api/(?:v\d+/)?profiles?/(\d+)', "user"),
    (r'/api/(?:v\d+/)?orders?/(\d+)', "order"),
    (r'/api/(?:v\d+/)?invoices?/(\d+)', "order"),
    (r'/api/(?:v\d+/)?payments?/(\d+)', "order"),
    (r'/api/(?:v\d+/)?transactions?/(\d+)', "order"),
    (r'/api/(?:v\d+/)?documents?/(\d+)', "file"),
    (r'/api/(?:v\d+/)?files?/(\d+)', "file"),
    (r'/api/(?:v\d+/)?reports?/(\d+)', "file"),
    (r'/api/(?:v\d+/)?messages?/(\d+)', "user"),
    (r'/api/(?:v\d+/)?tickets?/(\d+)', "user"),
    (r'/api/(?:v\d+/)?settings?/(\d+)', "settings"),
    (r'/api/(?:v\d+/)?admin/(\d+)', "admin"),
    (r'/api/(?:v\d+/)?[^/]+/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', "user"),
    (r'/api/(?:v\d+/)?[^/]+/(\d+)', "user"),
    (r'/(?:profile|user|account)/(\d+)', "user"),
    (r'/(?:order|invoice|payment)/(\d+)', "order"),
    (r'/(?:download|file|document|attachment)/(\d+)', "file"),
    (r'/(?:download|file|document|attachment)\?.*?(?:id|file|name)=([^&]+)', "file"),
]

PARAM_RESOURCE_MAP = {
    "user_id": "user", "userid": "user", "uid": "user", "account_id": "user",
    "accountid": "user", "profile_id": "user", "profileid": "user",
    "member_id": "user", "memberid": "user", "customer_id": "user",
    "order_id": "order", "orderid": "order", "invoice_id": "order",
    "invoiceid": "order", "payment_id": "order", "paymentid": "order",
    "transaction_id": "order", "transactionid": "order",
    "file_id": "file", "fileid": "file", "doc_id": "file", "docid": "file",
    "document": "file", "file": "file", "doc": "file", "ref": "file",
    "report_id": "file", "reportid": "file",
    "id": "user",
}

ADMIN_PATTERNS = [
    "/admin", "/dashboard/admin", "/api/admin", "/manage",
    "/settings/users", "/settings/roles", "/settings/permissions",
    "/internal", "/superuser", "/staff", "/backoffice",
    "/api/v1/admin", "/api/v2/admin",
]

ESCALATION_PARAMS = {
    "role": ["admin", "administrator", "superuser"],
    "is_admin": ["true", "1"],
    "admin": ["true", "1"],
    "privilege": ["1", "admin"],
    "access_level": ["admin", "10", "99"],
    "user_type": ["admin"],
    "verified": ["true"],
    "active": ["true"],
    "approved": ["true"],
}

INFO_LEAK_PHRASES = [
    "user not found", "no such user", "account does not exist",
    "record not found", "object not found", "invalid user",
    "resource not found", "does not exist", "no results",
]

ACCESS_DENIED_PHRASES = [
    "access denied", "forbidden", "unauthorized", "not authorized",
    "permission denied", "insufficient privileges", "login required",
    "authentication required", "unauthenticated", "not authenticated",
    "token expired", "invalid token", "session expired", "please log in",
    "please login", "sign in required", "must be logged in",
    "requires authentication", "auth required", "no permission",
]

# Sensitive data patterns — grouped by category
SENSITIVE_PATTERNS: dict[str, list[str]] = {
    "pii": [
        "email", "e-mail", "phone", "telephone", "mobile",
        "address", "street", "city", "zip", "postal",
        "name", "first_name", "last_name", "full_name", "username",
        "ssn", "social_security", "passport", "national_id",
        "dob", "date_of_birth", "birthday",
    ],
    "financial": [
        "balance", "credit", "debit", "card_number", "card_num",
        "cvv", "expiry", "payment", "bank_account", "iban",
        "routing_number", "salary", "income", "price", "amount",
        "billing", "invoice_total",
    ],
    "auth": [
        "jwt", "token", "access_token", "refresh_token", "api_key",
        "apikey", "secret", "session", "session_id", "sessionid",
        "password", "passwd", "hash", "salt", "private_key",
        "authorization", "bearer",
    ],
}

# Flat list for quick matching
ALL_SENSITIVE_FIELDS = []
for _fields in SENSITIVE_PATTERNS.values():
    ALL_SENSITIVE_FIELDS.extend(_fields)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _capture_request(url: str, method: str, headers: dict) -> dict:
    """Capture request details for proof, sanitizing sensitive headers."""
    safe_headers = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in ("cookie", "authorization"):
            safe_headers[k] = v[:20] + "...[redacted]" if len(v) > 20 else v
        else:
            safe_headers[k] = v
    return {"url": url, "method": method, "headers": safe_headers}


def _capture_response(resp: httpx.Response, preview_len: int = 3000) -> dict:
    """Capture response details for proof."""
    body = resp.text
    return {
        "status_code": resp.status_code,
        "body_preview": body[:preview_len],
        "size": len(body),
        "content_type": resp.headers.get("content-type", ""),
    }


def _compare_responses(resp_a: httpx.Response, resp_b: httpx.Response) -> dict:
    """Compare two HTTP responses and return a detailed similarity report."""
    body_a = resp_a.text
    body_b = resp_b.text

    result = {
        "status_same": resp_a.status_code == resp_b.status_code,
        "status_a": resp_a.status_code,
        "status_b": resp_b.status_code,
        "len_a": len(body_a),
        "len_b": len(body_b),
        "len_diff": abs(len(body_a) - len(body_b)),
        "body_identical": body_a == body_b,
        "similarity": 0.0,
        "json_keys_same": None,
        "info_leak": False,
        "info_leak_detail": "",
        "different_data": False,
        "new_records_found": 0,
        "sensitive_fields": [],
    }

    a_trunc = body_a[:4000]
    b_trunc = body_b[:4000]
    result["similarity"] = SequenceMatcher(None, a_trunc, b_trunc).ratio()

    # JSON structure comparison
    json_a = json_b = None
    try:
        json_a = json.loads(body_a)
        json_b = json.loads(body_b)
        keys_a = _extract_json_keys(json_a)
        keys_b = _extract_json_keys(json_b)
        result["json_keys_same"] = keys_a == keys_b
        result["different_data"] = (keys_a == keys_b and body_a != body_b)
    except (json.JSONDecodeError, TypeError):
        pass

    # Count records in arrays
    if isinstance(json_b, list):
        result["new_records_found"] = len(json_b)
    elif isinstance(json_b, dict):
        for v in json_b.values():
            if isinstance(v, list):
                result["new_records_found"] = len(v)
                break

    # Detect sensitive fields in response B
    result["sensitive_fields"] = _detect_sensitive_fields(body_b)

    # Info-leak detection
    lower_b = body_b.lower()[:500]
    for phrase in INFO_LEAK_PHRASES:
        if phrase in lower_b:
            result["info_leak"] = True
            result["info_leak_detail"] = phrase
            break

    return result


def _extract_json_keys(obj: Any, prefix: str = "") -> set:
    """Recursively extract all key paths from a JSON object."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.add(path)
            keys.update(_extract_json_keys(v, path))
    elif isinstance(obj, list) and obj:
        keys.update(_extract_json_keys(obj[0], f"{prefix}[]"))
    return keys


def _is_access_denied(body: str) -> bool:
    lower = body.lower()[:500]
    return any(p in lower for p in ACCESS_DENIED_PHRASES)


def _detect_sensitive_fields(body: str) -> list[str]:
    """Return list of sensitive field categories found in the response body."""
    lower = body.lower()
    found: list[str] = []
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pat in patterns:
            if pat in lower:
                found.append(pat)
    return found


def _count_sensitive_by_category(fields: list[str]) -> dict[str, int]:
    """Group detected sensitive fields by category."""
    result: dict[str, int] = {}
    for category, patterns in SENSITIVE_PATTERNS.items():
        count = sum(1 for f in fields if f in patterns)
        if count:
            result[category] = count
    return result


def _detect_id_type(value: str) -> str:
    """Classify an ID value: numeric, uuid, encoded, string."""
    if not value:
        return "string"
    if value.isdigit():
        return "numeric"
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
        return "uuid"
    if re.match(r'^[A-Za-z0-9+/=]{16,}$', value):
        return "encoded"
    return "string"


def _is_meaningful_response(resp: httpx.Response) -> bool:
    """Check if a response contains meaningful data (not empty/error page)."""
    if resp.status_code not in (200, 201):
        return False
    body = resp.text
    if len(body) < 50:
        return False
    if _is_access_denied(body):
        return False
    return True


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class IDOREngine:
    """IDOR Proof Engine — proves vulnerabilities with actual response data.

    Parameters
    ----------
    max_concurrent : int
        Maximum concurrent requests (semaphore size). Default 20.
    max_requests_per_endpoint : int
        Stop testing an endpoint after this many requests. Default 100.
    max_sequential_ids : int
        How far to bruteforce sequential IDs (1..N). Default 1000.
    max_idor_proofs : int
        Stop after finding this many confirmed IDORs per endpoint. Default 10.
    """

    def __init__(
        self,
        max_concurrent: int = 20,
        max_requests_per_endpoint: int = 100,
        max_sequential_ids: int = 1000,
        max_idor_proofs: int = 10,
        rate_limit: asyncio.Semaphore = None,
    ):
        self.semaphore = rate_limit or asyncio.Semaphore(max_concurrent)
        self.max_requests_per_endpoint = max_requests_per_endpoint
        self.max_sequential_ids = max_sequential_ids
        self.max_idor_proofs = max_idor_proofs
        self._seen: set[str] = set()
        self._request_counts: dict[str, int] = {}  # endpoint → request count

    # ---- public entry point ----

    async def test_all(self, endpoints: list, context: dict) -> list[dict]:
        """Run all IDOR tests and return findings with proof data.

        Parameters
        ----------
        endpoints : list
            Endpoint dicts (or plain URL strings) from the endpoint phase.
        context : dict
            Pipeline context. Expected keys:
            - base_url / domain
            - auth_cookie
            - harvested_ids (optional): dict mapping resource_type → list[str]
              e.g. {"user": ["42", "99", "abc-uuid"], "order": ["1001"]}
        """
        base_url = context.get("base_url", f"https://{context.get('domain', '')}")
        auth_cookie = context.get("auth_cookie")
        harvested_ids: dict[str, list[str]] = context.get("harvested_ids") or {}

        headers = self._build_headers(auth_cookie)
        classified = self.classify_endpoints(endpoints, base_url)
        logger.info(
            f"IDOREngine: classified {len(classified)} targets from {len(endpoints)} endpoints "
            f"| harvested IDs: {sum(len(v) for v in harvested_ids.values())} across "
            f"{len(harvested_ids)} resource types"
        )

        findings: list[dict] = []

        async with make_client(extra_headers=headers) as authed_client:
            # 1) Horizontal escalation (with harvested IDs + sequential bruteforce)
            horiz = await self._run_horizontal(classified, authed_client, harvested_ids)
            findings.extend(horiz)

            # 2) Vertical escalation (with proof)
            vert = await self._run_vertical(endpoints, base_url, authed_client, headers)
            findings.extend(vert)

            # 3) Parameter tampering (with response comparison proof)
            tamp = await self._run_param_tampering(classified, authed_client)
            findings.extend(tamp)

            # 4) Auth-context testing (authed vs unauthed vs substituted)
            if auth_cookie:
                auth_ctx = await self._run_auth_context(classified, headers, harvested_ids)
                findings.extend(auth_ctx)

        logger.info(f"IDOREngine: total proven findings = {len(findings)}")
        return findings

    # ------------------------------------------------------------------
    # 1. Endpoint Classification
    # ------------------------------------------------------------------

    def classify_endpoints(self, endpoints: list, base_url: str) -> list[dict]:
        """Detect endpoints with ID-like parameters and classify by resource type."""
        targets = []
        seen = set()

        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url:
                continue
            if url.startswith("/"):
                url = urljoin(base_url, url)

            parsed = urlparse(url)

            # --- Path-based IDs ---
            for pattern, resource in IDOR_PATH_PATTERNS:
                m = re.search(pattern, url, re.I)
                if m:
                    id_val = m.group(1)
                    key = f"path:{parsed.path}:{id_val}"
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append({
                        "url": url,
                        "param": None,
                        "original_value": id_val,
                        "id_type": _detect_id_type(id_val),
                        "resource_type": resource,
                        "location": "path",
                    })
                    break

            # --- Query-parameter IDs ---
            params = parse_qs(parsed.query, keep_blank_values=True)
            for pname, pvals in params.items():
                pname_lower = pname.lower()
                if (pname_lower in IDOR_PARAM_NAMES
                        or pname_lower.endswith("_id")
                        or pname_lower.endswith("id")):
                    val = pvals[0] if pvals else ""
                    key = f"param:{parsed.path}:{pname}:{val}"
                    if key in seen:
                        continue
                    seen.add(key)
                    resource = PARAM_RESOURCE_MAP.get(pname_lower, "user")
                    targets.append({
                        "url": url,
                        "param": pname,
                        "original_value": val,
                        "id_type": _detect_id_type(val),
                        "resource_type": resource,
                        "location": "query",
                    })

        return targets

    # ------------------------------------------------------------------
    # 2. Horizontal Escalation (with cross-pollination + sequential)
    # ------------------------------------------------------------------

    async def _run_horizontal(
        self,
        targets: list[dict],
        client: httpx.AsyncClient,
        harvested_ids: dict[str, list[str]],
    ) -> list[dict]:
        """Test horizontal IDOR with harvested IDs and sequential bruteforce."""
        findings: list[dict] = []
        tasks = []
        for t in targets[:40]:
            tasks.append(self._test_horizontal(t, client, harvested_ids))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug(f"IDOREngine horizontal gather error: {r}")
        return findings

    async def _test_horizontal(
        self,
        target: dict,
        client: httpx.AsyncClient,
        harvested_ids: dict[str, list[str]],
    ) -> list[dict]:
        """Test a single target for horizontal IDOR with full proof collection."""
        url = target["url"]
        original_value = target["original_value"]
        id_type = target["id_type"]
        resource_type = target["resource_type"]
        findings: list[dict] = []
        endpoint_key = self._endpoint_key(target)

        try:
            # 1. Fetch baseline response (our own data)
            baseline_resp = await self._safe_get(client, url)
            if not baseline_resp or not _is_meaningful_response(baseline_resp):
                return findings

            baseline_capture = _capture_response(baseline_resp)

            # 2. Build ID candidates: harvested + generated + sequential
            candidate_ids = self._build_candidate_ids(
                original_value, id_type, resource_type, harvested_ids
            )

            confirmed_count = 0

            for alt_id in candidate_ids:
                # Respect per-endpoint limits
                if self._request_counts.get(endpoint_key, 0) >= self.max_requests_per_endpoint:
                    logger.debug(f"IDOREngine: request limit reached for {endpoint_key}")
                    break
                if confirmed_count >= self.max_idor_proofs:
                    logger.debug(f"IDOREngine: proof limit reached for {endpoint_key}")
                    break

                tampered_url = self._substitute_id(target, str(alt_id))
                dedup = f"horiz:{tampered_url}"
                if dedup in self._seen:
                    continue
                self._seen.add(dedup)

                tampered_resp = await self._safe_get(client, tampered_url)
                self._request_counts[endpoint_key] = self._request_counts.get(endpoint_key, 0) + 1

                if not tampered_resp:
                    continue

                # Check for info-leak in error responses
                if tampered_resp.status_code in (400, 404, 500):
                    body_lower = tampered_resp.text.lower()[:500]
                    for phrase in INFO_LEAK_PHRASES:
                        if phrase in body_lower:
                            findings.append(self._make_proven_finding(
                                title="IDOR Info Leak: error reveals object existence",
                                url=tampered_url,
                                param=target.get("param") or "path_id",
                                idor_type="horizontal",
                                severity="low",
                                original_value=original_value,
                                tampered_value=str(alt_id),
                                request_capture=_capture_request(
                                    tampered_url, "GET", dict(client.headers)
                                ),
                                response_capture=_capture_response(tampered_resp),
                                baseline_capture=baseline_capture,
                                comparison={"info_leak": True, "leak_phrase": phrase},
                                impact="Error messages reveal whether objects exist, enabling enumeration",
                                remediation="Return generic error messages regardless of object existence",
                            ))
                            break
                    continue

                if tampered_resp.status_code not in (200, 201):
                    continue

                if _is_access_denied(tampered_resp.text):
                    continue

                cmp = _compare_responses(baseline_resp, tampered_resp)

                # PROVEN IDOR: different data returned for different ID
                is_idor = False

                # Case 1: clearly different body, not identical, substantial size
                if (cmp["status_same"]
                        and not cmp["body_identical"]
                        and cmp["len_b"] > 100
                        and cmp["similarity"] < 0.90):
                    is_idor = True

                # Case 2: same JSON structure, different values (same keys, diff data)
                if (cmp["status_same"]
                        and cmp.get("json_keys_same") is True
                        and not cmp["body_identical"]
                        and cmp["len_b"] > 50):
                    is_idor = True

                if not is_idor:
                    continue

                # Determine severity from sensitive data
                sensitive = cmp["sensitive_fields"]
                categories = _count_sensitive_by_category(sensitive)
                has_pii = categories.get("pii", 0) >= 1
                has_financial = categories.get("financial", 0) >= 1
                has_auth = categories.get("auth", 0) >= 1

                if has_auth or has_financial:
                    severity = "critical"
                elif has_pii and len(sensitive) >= 3:
                    severity = "critical"
                elif has_pii:
                    severity = "high"
                else:
                    severity = "high"

                confirmed_count += 1

                findings.append(self._make_proven_finding(
                    title=f"IDOR Proven: horizontal access to {resource_type} data (ID={alt_id})",
                    url=tampered_url,
                    param=target.get("param") or "path_id",
                    idor_type="horizontal",
                    severity=severity,
                    original_value=original_value,
                    tampered_value=str(alt_id),
                    request_capture=_capture_request(tampered_url, "GET", dict(client.headers)),
                    response_capture=_capture_response(tampered_resp),
                    baseline_capture=baseline_capture,
                    comparison={
                        "different_data": True,
                        "similarity": round(cmp["similarity"], 3),
                        "new_records_found": cmp["new_records_found"],
                        "sensitive_fields": sensitive,
                        "sensitive_categories": categories,
                        "size_baseline": cmp["len_a"],
                        "size_tampered": cmp["len_b"],
                    },
                    impact=(
                        f"Attacker can access any {resource_type}'s data by changing "
                        f"{'parameter' if target['location'] == 'query' else 'path'} ID. "
                        f"Sensitive data exposed: {', '.join(sensitive[:10]) if sensitive else 'unknown fields'}. "
                        f"Records found: {cmp['new_records_found']}"
                    ),
                    remediation=(
                        "Implement server-side authorization: verify the requesting user "
                        "owns or has permission to access the requested resource. "
                        "Use indirect references (e.g., map user-specific tokens to internal IDs)."
                    ),
                ))

        except Exception as e:
            logger.debug(f"IDOREngine horizontal test error for {url}: {e}")
        return findings

    def _build_candidate_ids(
        self,
        original_value: str,
        id_type: str,
        resource_type: str,
        harvested_ids: dict[str, list[str]],
    ) -> list[str]:
        """Build prioritized list of candidate IDs to test.

        Order: harvested cross-pollination → adjacent IDs → sequential bruteforce.
        """
        candidates: list[str] = []
        seen_candidates: set[str] = {original_value}

        def _add(val: str):
            if val not in seen_candidates:
                seen_candidates.add(val)
                candidates.append(val)

        # 1. Cross-pollination: IDs from other endpoints for same resource type
        for harvested_val in (harvested_ids.get(resource_type) or []):
            _add(str(harvested_val))

        # Also try IDs from ALL resource types (cross-type pollination)
        for rtype, ids in harvested_ids.items():
            if rtype != resource_type:
                for hid in ids[:5]:
                    _add(str(hid))

        # 2. Adjacent IDs (close neighbors are most likely to exist)
        if id_type == "numeric" and original_value.isdigit():
            n = int(original_value)
            for offset in [1, -1, 2, -2, 3, -3, 5, -5, 10, -10, 50, 100]:
                v = n + offset
                if v > 0:
                    _add(str(v))

        # 3. Common/well-known IDs
        if id_type == "numeric":
            for common in [0, 1, 2, 3, 5, 10, 100, 999, 1000]:
                _add(str(common))

        if id_type == "uuid":
            if original_value and original_value[-1] in "0123456789abcdef":
                last = int(original_value[-1], 16)
                for i in range(1, 6):
                    new_last = (last + i) % 16
                    _add(original_value[:-1] + format(new_last, 'x'))
            _add("00000000-0000-0000-0000-000000000001")
            _add("00000000-0000-0000-0000-000000000000")

        if id_type == "encoded":
            for test_val in ["1", "2", "admin", "0", "root"]:
                try:
                    _add(base64.b64encode(test_val.encode()).decode())
                except Exception:
                    pass

        if id_type == "string":
            for test_val in ["admin", "root", "test", "user1", "1", "guest", "default", "system"]:
                _add(test_val)

        # 4. Sequential bruteforce for numeric IDs
        if id_type == "numeric":
            for seq_id in range(1, self.max_sequential_ids + 1):
                _add(str(seq_id))

        return candidates

    # ------------------------------------------------------------------
    # 3. Vertical Escalation (with proof)
    # ------------------------------------------------------------------

    async def _run_vertical(
        self,
        endpoints: list,
        base_url: str,
        authed_client: httpx.AsyncClient,
        auth_headers: dict,
    ) -> list[dict]:
        """Test admin-only endpoints for broken access control with proof."""
        findings: list[dict] = []

        admin_urls: set[str] = set()
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url:
                continue
            url_lower = url.lower()
            for pat in ADMIN_PATTERNS:
                if pat in url_lower:
                    full = url if url.startswith("http") else urljoin(base_url, url)
                    admin_urls.add(full)
                    break

        for pat in ADMIN_PATTERNS[:8]:
            admin_urls.add(urljoin(base_url, pat))

        logger.info(f"IDOREngine vertical: testing {len(admin_urls)} admin endpoints")

        async with make_client() as unauthed_client:
            for url in list(admin_urls)[:20]:
                dedup = f"vert:{url}"
                if dedup in self._seen:
                    continue
                self._seen.add(dedup)

                result = await self._test_vertical_endpoint(
                    url, authed_client, unauthed_client
                )
                if result:
                    findings.append(result)

        # Privilege escalation via parameter injection
        param_findings = await self._test_privilege_params(endpoints, base_url, authed_client)
        findings.extend(param_findings)

        return findings

    async def _test_vertical_endpoint(
        self,
        url: str,
        authed_client: httpx.AsyncClient,
        unauthed_client: httpx.AsyncClient,
    ) -> dict | None:
        """Test one admin endpoint with full proof collection."""
        try:
            authed_resp = await self._safe_get(authed_client, url)
            unauthed_resp = await self._safe_get(unauthed_client, url)
            if not authed_resp or not unauthed_resp:
                return None

            authed_capture = _capture_response(authed_resp)
            unauthed_capture = _capture_response(unauthed_resp)

            # Case 1: Both return 200, content is similar or identical
            if unauthed_resp.status_code == 200 and authed_resp.status_code == 200:
                if _is_access_denied(unauthed_resp.text):
                    return None
                if len(unauthed_resp.text) < 50:
                    return None
                # SPA shell — React/Vue/Angular index.html, not real admin access
                if is_spa_shell(unauthed_resp.text, unauthed_resp.headers.get("content-type", "")):
                    return None

                cmp = _compare_responses(authed_resp, unauthed_resp)

                if cmp["body_identical"] and cmp["len_a"] > 100:
                    return self._make_proven_finding(
                        title="Broken Access Control: admin endpoint fully accessible without auth",
                        url=url,
                        param="authorization",
                        idor_type="vertical",
                        severity="critical",
                        original_value="authenticated",
                        tampered_value="unauthenticated",
                        request_capture=_capture_request(url, "GET", {}),
                        response_capture=unauthed_capture,
                        baseline_capture=authed_capture,
                        comparison={
                            "different_data": False,
                            "identical_response": True,
                            "sensitive_fields": cmp["sensitive_fields"],
                            "size": cmp["len_a"],
                        },
                        impact="Admin functionality fully accessible to unauthenticated users",
                        remediation=(
                            "Implement proper role-based access control (RBAC). "
                            "Verify admin privileges server-side on every request."
                        ),
                    )

                if cmp["similarity"] > 0.7 and not cmp["body_identical"]:
                    return self._make_proven_finding(
                        title="Broken Access Control: admin endpoint leaks data without auth",
                        url=url,
                        param="authorization",
                        idor_type="vertical",
                        severity="critical",
                        original_value="authenticated",
                        tampered_value="unauthenticated",
                        request_capture=_capture_request(url, "GET", {}),
                        response_capture=unauthed_capture,
                        baseline_capture=authed_capture,
                        comparison={
                            "different_data": True,
                            "similarity": round(cmp["similarity"], 3),
                            "sensitive_fields": cmp["sensitive_fields"],
                        },
                        impact="Admin endpoint returns similar content without authentication",
                        remediation=(
                            "Implement proper role-based access control (RBAC). "
                            "Verify admin privileges server-side on every request."
                        ),
                    )

            # Case 2: Unauthed gets 200 but authed gets redirect/deny
            if (unauthed_resp.status_code == 200
                    and authed_resp.status_code in (301, 302, 401, 403)):
                if not _is_access_denied(unauthed_resp.text) and len(unauthed_resp.text) > 100:
                    sensitive = _detect_sensitive_fields(unauthed_resp.text)
                    return self._make_proven_finding(
                        title="Access Control Bypass: endpoint accessible without credentials",
                        url=url,
                        param="authorization",
                        idor_type="vertical",
                        severity="high",
                        original_value="authenticated",
                        tampered_value="unauthenticated",
                        request_capture=_capture_request(url, "GET", {}),
                        response_capture=unauthed_capture,
                        baseline_capture=authed_capture,
                        comparison={
                            "different_data": True,
                            "authed_status": authed_resp.status_code,
                            "unauthed_status": 200,
                            "sensitive_fields": sensitive,
                        },
                        impact="Endpoint accessible without authentication",
                        remediation="Fix authentication middleware to consistently require credentials",
                    )

        except Exception as e:
            logger.debug(f"IDOREngine vertical test error for {url}: {e}")
        return None

    async def _test_privilege_params(
        self,
        endpoints: list,
        base_url: str,
        client: httpx.AsyncClient,
    ) -> list[dict]:
        """Inject role=admin / is_admin=true and collect proof."""
        findings: list[dict] = []
        candidate_urls: list[str] = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url:
                continue
            lower = url.lower()
            if any(k in lower for k in ("/profile", "/account", "/settings", "/me", "/user")):
                full = url if url.startswith("http") else urljoin(base_url, url)
                candidate_urls.append(full)

        for url in candidate_urls[:10]:
            # Get baseline response first
            baseline_resp = await self._safe_get(client, url)
            if not baseline_resp or baseline_resp.status_code not in (200, 201):
                continue
            baseline_capture = _capture_response(baseline_resp)

            for param_name, values in ESCALATION_PARAMS.items():
                for val in values[:1]:
                    dedup = f"privesc:{url}:{param_name}"
                    if dedup in self._seen:
                        continue
                    self._seen.add(dedup)

                    try:
                        # GET with injected param
                        sep = "&" if "?" in url else "?"
                        test_url = f"{url}{sep}{param_name}={val}"

                        resp = await self._safe_get(client, test_url)
                        if not resp or resp.status_code != 200 or len(resp.text) < 50:
                            continue
                        if _is_access_denied(resp.text):
                            continue

                        admin_indicators = [
                            "admin", "superuser", "staff",
                            "role\":\"admin", "is_admin\":true",
                            "privilege", "permission",
                        ]
                        body_lower = resp.text.lower()
                        hits = sum(1 for i in admin_indicators if i in body_lower)
                        if hits >= 2:
                            findings.append(self._make_proven_finding(
                                title=f"Privilege Escalation via {param_name}={val}",
                                url=test_url,
                                param=param_name,
                                idor_type="vertical",
                                severity="critical",
                                original_value="(not set)",
                                tampered_value=val,
                                request_capture=_capture_request(
                                    test_url, "GET", dict(client.headers)
                                ),
                                response_capture=_capture_response(resp),
                                baseline_capture=baseline_capture,
                                comparison={
                                    "different_data": True,
                                    "admin_indicators_found": hits,
                                    "sensitive_fields": _detect_sensitive_fields(resp.text),
                                },
                                impact=(
                                    f"Attacker can escalate privileges by adding "
                                    f"{param_name}={val} to requests"
                                ),
                                remediation=(
                                    "Never trust client-supplied role/privilege params. "
                                    "Derive authorization from server-side session."
                                ),
                            ))
                            break

                        # Also test via POST body
                        post_resp = await self._safe_request(
                            client, "POST", url,
                            json={param_name: val},
                            headers={"Content-Type": "application/json"},
                        )
                        if (post_resp
                                and post_resp.status_code == 200
                                and len(post_resp.text) > 50):
                            body_lower = post_resp.text.lower()
                            hits = sum(1 for i in admin_indicators if i in body_lower)
                            if hits >= 2:
                                findings.append(self._make_proven_finding(
                                    title=f"Mass Assignment: {param_name}={val} via POST",
                                    url=url,
                                    param=param_name,
                                    idor_type="vertical",
                                    severity="critical",
                                    original_value="(not set)",
                                    tampered_value=val,
                                    request_capture=_capture_request(
                                        url, "POST", dict(client.headers)
                                    ),
                                    response_capture=_capture_response(post_resp),
                                    baseline_capture=baseline_capture,
                                    comparison={
                                        "different_data": True,
                                        "admin_indicators_found": hits,
                                        "sensitive_fields": _detect_sensitive_fields(post_resp.text),
                                    },
                                    impact="Attacker can escalate privileges via mass assignment",
                                    remediation=(
                                        "Whitelist allowed fields in update operations. "
                                        "Never bind role/privilege fields from user input."
                                    ),
                                ))
                                break
                    except Exception as e:
                        logger.debug(f"IDOREngine privesc test error: {e}")

        return findings

    # ------------------------------------------------------------------
    # 4. Parameter Tampering (with proof)
    # ------------------------------------------------------------------

    async def _run_param_tampering(
        self, targets: list[dict], client: httpx.AsyncClient
    ) -> list[dict]:
        """Test parameter tampering with response comparison proof."""
        findings: list[dict] = []
        query_targets = [t for t in targets if t["location"] == "query"]

        for target in query_targets[:20]:
            url = target["url"]
            param = target["param"]
            orig_val = target["original_value"]
            dedup = f"tamp:{url}:{param}"
            if dedup in self._seen:
                continue
            self._seen.add(dedup)

            try:
                original_resp = await self._safe_get(client, url)
                if not original_resp or original_resp.status_code not in (200, 201):
                    continue
                baseline_capture = _capture_response(original_resp)

                # --- HTTP Parameter Pollution ---
                parsed = urlparse(url)
                qs = parsed.query
                hpp_url = urlunparse(parsed._replace(
                    query=f"{qs}&{param}=1" if qs else f"{param}=1"
                ))

                hpp_resp = await self._safe_get(client, hpp_url)
                if hpp_resp and hpp_resp.status_code == 200:
                    cmp = _compare_responses(original_resp, hpp_resp)
                    if (not cmp["body_identical"]
                            and cmp["len_b"] > 100
                            and cmp["similarity"] < 0.85
                            and not _is_access_denied(hpp_resp.text)):
                        findings.append(self._make_proven_finding(
                            title=f"HTTP Parameter Pollution on {param}",
                            url=hpp_url,
                            param=param,
                            idor_type="param_tampering",
                            severity="medium",
                            original_value=orig_val,
                            tampered_value=f"{orig_val}&{param}=1",
                            request_capture=_capture_request(hpp_url, "GET", dict(client.headers)),
                            response_capture=_capture_response(hpp_resp),
                            baseline_capture=baseline_capture,
                            comparison={
                                "different_data": True,
                                "similarity": round(cmp["similarity"], 3),
                                "sensitive_fields": cmp["sensitive_fields"],
                                "size_baseline": cmp["len_a"],
                                "size_tampered": cmp["len_b"],
                            },
                            impact=(
                                "Server processes duplicate parameters inconsistently, "
                                "potentially bypassing authorization"
                            ),
                            remediation=(
                                "Normalize query parameters server-side. "
                                "Reject or deduplicate repeated parameters."
                            ),
                        ))

                # --- Mass assignment via query ---
                for extra_param, vals in list(ESCALATION_PARAMS.items())[:3]:
                    test_val = vals[0]
                    sep = "&" if "?" in url else "?"
                    mass_url = f"{url}{sep}{extra_param}={test_val}"

                    mass_resp = await self._safe_get(client, mass_url)
                    if not mass_resp or mass_resp.status_code != 200:
                        continue

                    cmp = _compare_responses(original_resp, mass_resp)
                    if (not cmp["body_identical"]
                            and cmp["similarity"] < 0.85
                            and cmp["len_b"] > 100
                            and not _is_access_denied(mass_resp.text)):
                        findings.append(self._make_proven_finding(
                            title=f"Parameter Tampering: {extra_param}={test_val} changes response",
                            url=mass_url,
                            param=extra_param,
                            idor_type="param_tampering",
                            severity="medium",
                            original_value="(not set)",
                            tampered_value=test_val,
                            request_capture=_capture_request(
                                mass_url, "GET", dict(client.headers)
                            ),
                            response_capture=_capture_response(mass_resp),
                            baseline_capture=baseline_capture,
                            comparison={
                                "different_data": True,
                                "similarity": round(cmp["similarity"], 3),
                                "sensitive_fields": cmp["sensitive_fields"],
                            },
                            impact="Server accepts unexpected parameters that modify behavior",
                            remediation="Whitelist expected parameters. Ignore unknown params.",
                        ))
                        break

            except Exception as e:
                logger.debug(f"IDOREngine param tampering error: {e}")

        return findings

    # ------------------------------------------------------------------
    # 5. Auth-Context Testing (authed vs unauthed vs substituted)
    # ------------------------------------------------------------------

    async def _run_auth_context(
        self,
        targets: list[dict],
        auth_headers: dict,
        harvested_ids: dict[str, list[str]],
    ) -> list[dict]:
        """Three-way comparison: authed vs unauthed vs substituted-ID."""
        findings: list[dict] = []
        test_targets = targets[:15]

        async with make_client(extra_headers=auth_headers) as authed_client:
            async with make_client() as unauthed_client:
                for target in test_targets:
                    url = target["url"]
                    dedup = f"auth:{url}"
                    if dedup in self._seen:
                        continue
                    self._seen.add(dedup)

                    try:
                        # 1. Authed request (baseline)
                        authed_resp = await self._safe_get(authed_client, url)
                        if not authed_resp:
                            continue
                        authed_capture = _capture_response(authed_resp)

                        # 2. Unauthed request
                        unauthed_resp = await self._safe_get(unauthed_client, url)
                        if not unauthed_resp:
                            continue
                        unauthed_capture = _capture_response(unauthed_resp)

                        # 3. Substituted-ID request (if we have harvested IDs)
                        substituted_capture = None
                        substituted_resp = None
                        resource_ids = harvested_ids.get(target["resource_type"]) or []
                        if resource_ids:
                            alt_id = resource_ids[0]
                            sub_url = self._substitute_id(target, str(alt_id))
                            substituted_resp = await self._safe_get(authed_client, sub_url)
                            if substituted_resp:
                                substituted_capture = _capture_response(substituted_resp)

                        # Analysis: unauthed gets same data as authed
                        if (authed_resp.status_code == 200
                                and unauthed_resp.status_code == 200):
                            cmp = _compare_responses(authed_resp, unauthed_resp)

                            if (cmp["similarity"] > 0.8
                                    and cmp["len_b"] > 100
                                    and not _is_access_denied(unauthed_resp.text)):
                                sensitive = cmp["sensitive_fields"]
                                categories = _count_sensitive_by_category(sensitive)

                                if sensitive:
                                    severity = "critical" if len(sensitive) >= 3 else "high"

                                    comparison_data = {
                                        "different_data": not cmp["body_identical"],
                                        "authed_vs_unauthed_similarity": round(cmp["similarity"], 3),
                                        "sensitive_fields": sensitive,
                                        "sensitive_categories": categories,
                                        "new_records_found": cmp["new_records_found"],
                                    }
                                    if substituted_capture:
                                        comparison_data["substituted_id_response"] = substituted_capture

                                    findings.append(self._make_proven_finding(
                                        title="Broken Access Control: sensitive data accessible without auth",
                                        url=url,
                                        param="authorization",
                                        idor_type="auth_context",
                                        severity=severity,
                                        original_value="with_auth",
                                        tampered_value="without_auth",
                                        request_capture=_capture_request(url, "GET", {}),
                                        response_capture=unauthed_capture,
                                        baseline_capture=authed_capture,
                                        comparison=comparison_data,
                                        impact=(
                                            f"Sensitive data accessible without authentication. "
                                            f"Exposed fields: {', '.join(sensitive[:10])}"
                                        ),
                                        remediation=(
                                            "Require authentication for endpoints serving "
                                            "user-specific data. Implement proper session validation."
                                        ),
                                    ))

                            if cmp.get("info_leak"):
                                findings.append(self._make_proven_finding(
                                    title="Info Leak via IDOR error message",
                                    url=url,
                                    param="authorization",
                                    idor_type="auth_context",
                                    severity="low",
                                    original_value="with_auth",
                                    tampered_value="without_auth",
                                    request_capture=_capture_request(url, "GET", {}),
                                    response_capture=unauthed_capture,
                                    baseline_capture=authed_capture,
                                    comparison={"info_leak": True, "detail": cmp["info_leak_detail"]},
                                    impact="Error messages reveal internal object state",
                                    remediation="Use generic error messages",
                                ))

                        # Analysis: substituted ID returns different user's data
                        if (substituted_resp
                                and substituted_resp.status_code == 200
                                and authed_resp.status_code == 200):
                            sub_cmp = _compare_responses(authed_resp, substituted_resp)
                            if (not sub_cmp["body_identical"]
                                    and sub_cmp["len_b"] > 100
                                    and not _is_access_denied(substituted_resp.text)):
                                sensitive = sub_cmp["sensitive_fields"]
                                if sensitive:
                                    findings.append(self._make_proven_finding(
                                        title=(
                                            f"IDOR Proven: substituted ID returns other "
                                            f"{target['resource_type']}'s data"
                                        ),
                                        url=self._substitute_id(target, str(resource_ids[0])),
                                        param=target.get("param") or "path_id",
                                        idor_type="auth_context",
                                        severity="critical" if len(sensitive) >= 3 else "high",
                                        original_value=target["original_value"],
                                        tampered_value=str(resource_ids[0]),
                                        request_capture=_capture_request(
                                            self._substitute_id(target, str(resource_ids[0])),
                                            "GET", dict(authed_client.headers),
                                        ),
                                        response_capture=substituted_capture,
                                        baseline_capture=authed_capture,
                                        comparison={
                                            "different_data": True,
                                            "similarity": round(sub_cmp["similarity"], 3),
                                            "sensitive_fields": sensitive,
                                            "sensitive_categories": _count_sensitive_by_category(sensitive),
                                            "new_records_found": sub_cmp["new_records_found"],
                                        },
                                        impact=(
                                            f"With valid auth, changing ID exposes other user's data. "
                                            f"Leaked: {', '.join(sensitive[:10])}"
                                        ),
                                        remediation=(
                                            "Implement object-level authorization. Verify the "
                                            "authenticated user has permission to access the "
                                            "requested resource ID."
                                        ),
                                    ))

                    except Exception as e:
                        logger.debug(f"IDOREngine auth-context error: {e}")

        return findings

    # ------------------------------------------------------------------
    # HTTP helpers (with semaphore + error handling)
    # ------------------------------------------------------------------

    async def _safe_get(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> httpx.Response | None:
        """GET with semaphore and error handling."""
        try:
            async with self.semaphore:
                return await client.get(url)
        except Exception as e:
            logger.debug(f"IDOREngine HTTP GET error {url}: {e}")
            return None

    async def _safe_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response | None:
        """Arbitrary method request with semaphore and error handling."""
        try:
            async with self.semaphore:
                return await client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug(f"IDOREngine HTTP {method} error {url}: {e}")
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_headers(auth_cookie: str | None) -> dict:
        headers: dict[str, str] = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie
        return headers

    @staticmethod
    def _endpoint_key(target: dict) -> str:
        """Unique key for an endpoint (ignoring the specific ID value)."""
        parsed = urlparse(target["url"])
        # Replace numeric segments with {id} for grouping
        path = re.sub(r'/\d+', '/{id}', parsed.path)
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}', path, flags=re.I,
        )
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _substitute_id(self, target: dict, new_id: str) -> str:
        """Replace the ID in the target URL with new_id."""
        url = target["url"]
        original = target["original_value"]

        if target["location"] == "path":
            return url.replace(original, new_id, 1)
        else:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[target["param"]] = [new_id]
            flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            return urlunparse(parsed._replace(query=urlencode(flat)))

    @staticmethod
    def _make_proven_finding(
        *,
        title: str,
        url: str,
        param: str,
        idor_type: str,
        severity: str,
        original_value: str,
        tampered_value: str,
        request_capture: dict,
        response_capture: dict,
        baseline_capture: dict,
        comparison: dict,
        impact: str,
        remediation: str,
    ) -> dict:
        """Create a finding dict with full proof data."""
        # Build reproduction steps
        method = request_capture.get("method", "GET")
        reproduction_steps = [
            f"1. Authenticate to the application and note your session/cookie",
            f"2. Access the original resource: {method} {request_capture.get('url', url)} "
            f"(original ID: {original_value})",
            f"3. Change the ID to {tampered_value}: {method} {url}",
            f"4. Observe that the server returns {response_capture.get('status_code', '200')} "
            f"with {response_capture.get('size', 0)} bytes of data",
        ]
        sensitive = comparison.get("sensitive_fields", [])
        if sensitive:
            reproduction_steps.append(
                f"5. Response contains sensitive data: {', '.join(sensitive[:10])}"
            )

        return {
            "title": title,
            "url": url,
            "param": param,
            "vuln_type": "idor",
            "severity": severity,
            "idor_type": idor_type,
            "original_value": original_value,
            "tampered_value": tampered_value,
            "proven": True,
            "proof": {
                "request": request_capture,
                "response": response_capture,
                "baseline": baseline_capture,
                "comparison": comparison,
            },
            "reproduction_steps": reproduction_steps,
            "impact": impact,
            "remediation": remediation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
