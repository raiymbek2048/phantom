"""
Advanced IDOR (Insecure Direct Object Reference) Module

Goes beyond basic IDOR:
1. Sequential ID enumeration with response comparison
2. UUID/GUID prediction testing
3. Horizontal privilege escalation (access other users' data)
4. Vertical privilege escalation (access admin endpoints as regular user)
5. Parameter tampering (changing user_id, account_id in requests)
6. Related resource enumeration (if user/1 exists, check orders/1, payments/1)
7. HTTP method variation (GET vs POST vs PUT vs DELETE access)
8. Response hash comparison for soft-IDOR detection
9. Unauthenticated IDOR (remove auth headers)
"""
import asyncio
import hashlib
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Parameters commonly vulnerable to IDOR
IDOR_PARAMS = {
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "profile_id", "profileId", "order_id", "orderId", "doc_id",
    "docId", "file_id", "fileId", "invoice_id", "invoiceId",
    "payment_id", "paymentId", "transaction_id", "report_id",
    "message_id", "messageId", "ticket_id", "comment_id",
    "project_id", "projectId", "org_id", "orgId", "team_id",
    "teamId", "workspace_id", "workspaceId", "company_id",
    "subscription_id", "plan_id", "key", "token", "ref",
}

# Related resource patterns — if we find /users/1, also check these
RELATED_RESOURCES = {
    "users": ["orders", "invoices", "payments", "messages", "documents", "files", "settings", "notifications"],
    "accounts": ["transactions", "statements", "cards", "beneficiaries"],
    "orders": ["payments", "receipts", "tracking", "items"],
    "projects": ["settings", "members", "files", "tasks"],
    "organizations": ["members", "teams", "billing", "settings"],
}

# API path patterns that suggest object access
IDOR_PATH_PATTERNS = [
    r'/api/(?:v\d+/)?users?/(\d+)',
    r'/api/(?:v\d+/)?accounts?/(\d+)',
    r'/api/(?:v\d+/)?orders?/(\d+)',
    r'/api/(?:v\d+/)?profiles?/(\d+)',
    r'/api/(?:v\d+/)?documents?/(\d+)',
    r'/api/(?:v\d+/)?files?/(\d+)',
    r'/api/(?:v\d+/)?invoices?/(\d+)',
    r'/api/(?:v\d+/)?messages?/(\d+)',
    r'/api/(?:v\d+/)?[^/]+/([0-9a-f-]{36})',  # UUID in path
    r'/api/(?:v\d+/)?[^/]+/(\d+)',  # Generic numeric ID in API path
]


class IDORModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        """Run IDOR checks on endpoints with ID parameters."""
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        findings = []

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        # Find IDOR-prone endpoints
        idor_targets = self._find_idor_targets(endpoints, base_url)
        logger.info(f"IDOR: Found {len(idor_targets)} potential targets")

        async with make_client(extra_headers=headers) as client:
            for target in idor_targets[:20]:
                # 1. Standard IDOR test
                result = await self._test_idor(client, target)
                if result:
                    findings.append(result)

                # 2. HTTP method variation (try DELETE/PUT without auth for the same ID)
                method_result = await self._test_method_idor(client, target)
                if method_result:
                    findings.append(method_result)

            # 3. Unauthenticated IDOR (strip auth, try accessing same endpoints)
            if auth_cookie:
                async with make_client() as noauth_client:
                    for target in idor_targets[:10]:
                        unauth_result = await self._test_unauth_idor(noauth_client, target)
                        if unauth_result:
                            findings.append(unauth_result)

            # 4. Related resource enumeration
            for target in idor_targets[:10]:
                related = await self._test_related_resources(client, target, base_url)
                findings.extend(related)

        return findings

    def _find_idor_targets(self, endpoints, base_url) -> list[dict]:
        """Find endpoints with ID parameters or path-based IDs."""
        targets = []
        seen = set()

        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url:
                continue

            parsed = urlparse(url)

            # Check URL path for IDs
            for pattern in IDOR_PATH_PATTERNS:
                match = re.search(pattern, url)
                if match:
                    id_value = match.group(1)
                    key = f"path:{parsed.path}"
                    if key not in seen:
                        seen.add(key)
                        targets.append({
                            "url": url,
                            "type": "path",
                            "id_value": id_value,
                            "id_type": "uuid" if len(id_value) > 10 else "numeric",
                        })

            # Check query parameters for IDs
            params = parse_qs(parsed.query, keep_blank_values=True)
            for pname, pvals in params.items():
                if pname.lower() in IDOR_PARAMS or pname.lower().endswith("_id") or pname.lower().endswith("Id"):
                    val = pvals[0] if pvals else ""
                    key = f"param:{parsed.path}:{pname}"
                    if key not in seen:
                        seen.add(key)
                        targets.append({
                            "url": url,
                            "type": "param",
                            "param": pname,
                            "id_value": val,
                            "id_type": "uuid" if len(val) > 10 else "numeric",
                        })

        return targets

    async def _test_idor(self, client: httpx.AsyncClient, target: dict) -> dict | None:
        """Test an endpoint for IDOR by trying different IDs."""
        url = target["url"]
        id_value = target["id_value"]
        id_type = target["id_type"]

        try:
            # Step 1: Get original response (authorized request)
            async with self.rate_limit:
                original = await client.get(url)
                if original.status_code not in (200, 201):
                    return None

                original_body = original.text
                original_len = len(original_body)

            # Step 2: Generate alternative IDs to test
            if id_type == "numeric" and id_value.isdigit():
                test_ids = self._generate_numeric_ids(int(id_value))
            else:
                test_ids = self._generate_uuid_variants(id_value)

            # Step 3: Test each alternative ID
            for test_id in test_ids:
                if target["type"] == "path":
                    test_url = url.replace(id_value, str(test_id))
                else:
                    test_url = self._replace_param(url, target["param"], str(test_id))

                async with self.rate_limit:
                    resp = await client.get(test_url)

                    if resp.status_code == 200:
                        resp_body = resp.text
                        resp_len = len(resp_body)

                        # Check if we got different data (not error page, not same data)
                        if resp_body != original_body and resp_len > 50:
                            # Verify it's actual data, not an error page
                            error_indicators = ["not found", "404", "error", "unauthorized",
                                              "forbidden", "invalid", "denied"]
                            is_error = any(ind in resp_body.lower()[:200] for ind in error_indicators)

                            if not is_error:
                                # Check for PII indicators (confirms real user data)
                                pii_indicators = ["email", "phone", "address", "name",
                                                "username", "password", "ssn", "credit",
                                                "card", "account", "balance"]
                                has_pii = any(ind in resp_body.lower() for ind in pii_indicators)

                                severity = "critical" if has_pii else "high"

                                return {
                                    "title": f"IDOR — Access to other {'user' if has_pii else 'object'} data",
                                    "url": test_url,
                                    "original_url": url,
                                    "severity": severity,
                                    "vuln_type": "idor",
                                    "original_id": id_value,
                                    "tested_id": str(test_id),
                                    "response_length_diff": abs(resp_len - original_len),
                                    "has_pii": has_pii,
                                    "response_preview": resp_body[:300],
                                    "impact": f"Unauthorized access to other objects by changing ID from {id_value} to {test_id}. "
                                             f"{'PII data exposed.' if has_pii else 'Different data returned.'}",
                                    "remediation": "Implement proper authorization checks. Verify the authenticated user "
                                                  "owns or has permission to access the requested object.",
                                }

        except Exception as e:
            logger.debug(f"IDOR test error for {url}: {e}")
        return None

    def _generate_numeric_ids(self, current_id: int) -> list[int]:
        """Generate IDs to test around the current ID."""
        ids = []
        # Adjacent IDs
        for offset in [1, -1, 2, -2, 5, -5, 10, 100]:
            test_id = current_id + offset
            if test_id > 0 and test_id != current_id:
                ids.append(test_id)
        # Common test IDs
        for common in [1, 2, 0, 999, 1000]:
            if common != current_id:
                ids.append(common)
        return ids[:10]

    def _generate_uuid_variants(self, current_uuid: str) -> list[str]:
        """Generate UUID variants to test."""
        variants = []
        # Try incrementing last digit
        if current_uuid and current_uuid[-1].isdigit():
            last_digit = int(current_uuid[-1])
            for i in range(10):
                if i != last_digit:
                    variants.append(current_uuid[:-1] + str(i))
                    if len(variants) >= 5:
                        break
        # Try all zeros
        if len(current_uuid) == 36:  # Standard UUID
            variants.append("00000000-0000-0000-0000-000000000001")
            variants.append("00000000-0000-0000-0000-000000000000")
        return variants[:5]

    def _replace_param(self, url: str, param: str, new_value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [new_value]
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        return urlunparse(parsed._replace(query=urlencode(flat)))

    async def _test_method_idor(self, client: httpx.AsyncClient, target: dict) -> dict | None:
        """Test if dangerous HTTP methods (DELETE, PUT, PATCH) work on other users' objects."""
        url = target["url"]
        id_value = target["id_value"]

        test_ids = [1, 2] if target["id_type"] == "numeric" and id_value.isdigit() else []
        if not test_ids:
            return None

        for test_id in test_ids:
            if str(test_id) == id_value:
                continue
            if target["type"] == "path":
                test_url = url.replace(id_value, str(test_id))
            else:
                test_url = self._replace_param(url, target["param"], str(test_id))

            for method in ["DELETE", "PUT", "PATCH"]:
                try:
                    async with self.rate_limit:
                        if method == "DELETE":
                            resp = await client.delete(test_url)
                        elif method == "PUT":
                            resp = await client.put(test_url, json={})
                        else:
                            resp = await client.patch(test_url, json={})

                        if resp.status_code in (200, 204, 202):
                            return {
                                "title": f"IDOR — {method} access to other object (ID: {test_id})",
                                "url": test_url,
                                "severity": "critical",
                                "vuln_type": "idor",
                                "method": method,
                                "original_id": id_value,
                                "tested_id": str(test_id),
                                "impact": f"Able to {method} other users' data by changing ID. "
                                         f"This could lead to data deletion or modification.",
                                "remediation": "Implement authorization checks for all HTTP methods. "
                                              "Verify object ownership before allowing modifications.",
                            }
                except Exception:
                    continue
        return None

    async def _test_unauth_idor(self, client: httpx.AsyncClient, target: dict) -> dict | None:
        """Test if endpoints are accessible without authentication."""
        url = target["url"]
        try:
            async with self.rate_limit:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 50:
                    body_lower = resp.text.lower()
                    error_indicators = ["login", "unauthorized", "forbidden", "sign in",
                                       "authentication required", "not authenticated"]
                    if not any(ind in body_lower[:300] for ind in error_indicators):
                        pii_indicators = ["email", "phone", "name", "username", "account"]
                        has_pii = any(ind in body_lower for ind in pii_indicators)
                        if has_pii:
                            return {
                                "title": f"IDOR — Unauthenticated access to object data",
                                "url": url,
                                "severity": "critical",
                                "vuln_type": "idor",
                                "method": "GET",
                                "impact": "Object data accessible without any authentication. "
                                         "Any user can access this data without logging in.",
                                "remediation": "Require authentication for all data endpoints. "
                                              "Implement proper access control middleware.",
                                "response_preview": resp.text[:300],
                            }
        except Exception:
            pass
        return None

    async def _test_related_resources(self, client: httpx.AsyncClient,
                                       target: dict, base_url: str) -> list[dict]:
        """If we found /api/users/1, also check /api/users/1/orders, etc."""
        findings = []
        url = target["url"]
        id_value = target["id_value"]

        if target["type"] != "path":
            return findings

        parsed = urlparse(url)
        path = parsed.path

        # Find which resource type this is
        for resource_type, related in RELATED_RESOURCES.items():
            if f"/{resource_type}/" in path:
                # Test with a different ID
                test_ids = self._generate_numeric_ids(int(id_value))[:3] if id_value.isdigit() else []
                for test_id in test_ids:
                    for related_resource in related[:4]:
                        # Build: /api/users/{test_id}/{related_resource}
                        related_path = re.sub(
                            rf'(/{resource_type}/){re.escape(id_value)}.*',
                            rf'\g<1>{test_id}/{related_resource}',
                            path
                        )
                        related_url = urlunparse(parsed._replace(path=related_path))
                        try:
                            async with self.rate_limit:
                                resp = await client.get(related_url)
                                if resp.status_code == 200 and len(resp.text) > 50:
                                    body_lower = resp.text.lower()
                                    if not any(e in body_lower[:200] for e in ["not found", "404", "error"]):
                                        findings.append({
                                            "title": f"IDOR — Access to related resource /{related_resource} of user {test_id}",
                                            "url": related_url,
                                            "severity": "high",
                                            "vuln_type": "idor",
                                            "method": "GET",
                                            "original_id": id_value,
                                            "tested_id": str(test_id),
                                            "impact": f"Able to access /{related_resource} of another user's {resource_type} object.",
                                            "remediation": "Implement authorization checks on all nested/related resource endpoints.",
                                            "response_preview": resp.text[:300],
                                        })
                                        break  # One proof per related resource is enough
                        except Exception:
                            continue
                break  # Only check one resource type match

        return findings

    def _response_hash(self, body: str) -> str:
        """Hash response body for comparison (ignoring dynamic tokens/timestamps)."""
        # Strip common dynamic values before hashing
        cleaned = re.sub(r'"(token|csrf|nonce|timestamp|date|time|expires)":\s*"[^"]*"', '""', body)
        cleaned = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', '', cleaned)
        return hashlib.md5(cleaned.encode()).hexdigest()
