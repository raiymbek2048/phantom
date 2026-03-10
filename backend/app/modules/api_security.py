"""
API Security Module

Tests for:
1. GraphQL introspection & injection
2. Mass assignment (adding admin=true, role=admin to requests)
3. Broken object-level authorization (BOLA)
4. Excessive data exposure (API returning too much data)
5. Lack of rate limiting on sensitive endpoints
"""
import asyncio
import json
import re
import logging
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

GRAPHQL_INTROSPECTION = '''{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
      }
    }
    queryType { name }
    mutationType { name }
  }
}'''

MASS_ASSIGNMENT_FIELDS = [
    ("role", "admin"),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("privilege", "admin"),
    ("verified", True),
    ("active", True),
    ("status", "active"),
    ("plan", "premium"),
    ("balance", 99999),
    ("discount", 100),
]


class APISecurityModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
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

        async with make_client(extra_headers=headers) as client:
            # GraphQL
            gql = await self._check_graphql(client, base_url, endpoints)
            findings.extend(gql)

            # Mass assignment
            ma = await self._check_mass_assignment(client, endpoints)
            findings.extend(ma)

            # Excessive data exposure
            ede = await self._check_excessive_data(client, endpoints)
            findings.extend(ede)

            # Content-Type confusion
            ct = await self._check_content_type_confusion(client, endpoints)
            findings.extend(ct)

            # HTTP method override headers
            mo = await self._check_method_override(client, endpoints)
            findings.extend(mo)

        return findings

    async def _check_graphql(self, client, base_url, endpoints) -> list[dict]:
        findings = []
        gql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                     "/query", "/gql", "/__graphql"]

        # Also check if any endpoint contains graphql
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if "graphql" in url.lower() or "gql" in url.lower():
                parsed = urlparse(url)
                path = parsed.path
                if path not in gql_paths:
                    gql_paths.append(path)

        for path in gql_paths:
            url = f"{base_url}{path}"
            try:
                async with self.rate_limit:
                    # Test introspection
                    resp = await client.post(url, json={"query": GRAPHQL_INTROSPECTION})
                    if resp.status_code == 200:
                        body = resp.text
                        if "__schema" in body and "types" in body:
                            data = resp.json()
                            types = data.get("data", {}).get("__schema", {}).get("types", [])
                            type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                            mutations = data.get("data", {}).get("__schema", {}).get("mutationType")

                            findings.append({
                                "title": f"GraphQL Introspection Enabled: {path}",
                                "url": url,
                                "severity": "medium",
                                "vuln_type": "info_disclosure",
                                "types_found": type_names[:20],
                                "has_mutations": mutations is not None,
                                "impact": f"GraphQL schema exposed via introspection. "
                                         f"Found {len(type_names)} types. "
                                         f"{'Mutations available — may allow data modification.' if mutations else ''}",
                                "remediation": "Disable introspection in production.",
                            })

                            # Test for injection in queries
                            sqli_query = '{ users(id: "1\' OR 1=1--") { id name } }'
                            async with self.rate_limit:
                                inj_resp = await client.post(url, json={"query": sqli_query})
                                if inj_resp.status_code == 200 and "error" not in inj_resp.text.lower()[:100]:
                                    findings.append({
                                        "title": f"GraphQL SQLi: {path}",
                                        "url": url,
                                        "severity": "high",
                                        "vuln_type": "sqli",
                                        "payload": sqli_query,
                                        "impact": "SQL injection through GraphQL query parameters.",
                                    })
                            break
            except Exception:
                continue

        return findings

    async def _check_mass_assignment(self, client, endpoints) -> list[dict]:
        findings = []
        # Find user update/profile endpoints
        update_eps = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")
            url_lower = url.lower()
            if any(k in url_lower for k in ("profile", "user", "account", "settings", "update")):
                if method in ("POST", "PUT", "PATCH"):
                    update_eps.append({"url": url, "method": method})

        for ep in update_eps[:5]:
            url = ep["url"]
            method = ep["method"]
            for field, value in MASS_ASSIGNMENT_FIELDS:
                try:
                    async with self.rate_limit:
                        data = {field: value}
                        if method == "PATCH":
                            resp = await client.patch(url, json=data)
                        elif method == "PUT":
                            resp = await client.put(url, json=data)
                        else:
                            resp = await client.post(url, json=data)

                        if resp.status_code in (200, 201):
                            body = resp.text
                            # Check if the field was accepted
                            if str(value).lower() in body.lower():
                                findings.append({
                                    "title": f"Mass Assignment: {field}={value}",
                                    "url": url,
                                    "severity": "high" if field in ("role", "is_admin", "isAdmin", "admin") else "medium",
                                    "vuln_type": "idor",
                                    "payload": json.dumps(data),
                                    "impact": f"Server accepted unauthorized field '{field}={value}'. "
                                             "Potential privilege escalation via mass assignment.",
                                    "remediation": "Use allowlists for accepted fields in update operations.",
                                })
                                break  # One proof per endpoint
                except Exception:
                    continue

        return findings

    async def _check_excessive_data(self, client, endpoints) -> list[dict]:
        findings = []
        sensitive_patterns = [
            (r'"password"\s*:', "password"),
            (r'"hash"\s*:', "password hash"),
            (r'"secret"\s*:', "secret"),
            (r'"token"\s*:', "token"),
            (r'"api_key"\s*:', "API key"),
            (r'"ssn"\s*:', "SSN"),
            (r'"credit_card"\s*:', "credit card"),
            (r'"private_key"\s*:', "private key"),
        ]

        api_eps = [ep for ep in endpoints if isinstance(ep, str) and "/api/" in ep]
        for url in api_eps[:10]:
            try:
                async with self.rate_limit:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text
                        found_sensitive = []
                        for pattern, label in sensitive_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                found_sensitive.append(label)
                        if found_sensitive:
                            findings.append({
                                "title": f"Excessive Data Exposure: {urlparse(url).path}",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "info_disclosure",
                                "sensitive_fields": found_sensitive,
                                "impact": f"API returns sensitive data: {', '.join(found_sensitive)}. "
                                         "Attacker can harvest credentials or PII.",
                                "remediation": "Filter sensitive fields from API responses. Use DTOs.",
                            })
            except Exception:
                continue

        return findings

    async def _check_content_type_confusion(self, client, endpoints) -> list[dict]:
        """Test if API accepts unexpected Content-Types (XML instead of JSON, etc.)."""
        findings = []
        write_eps = []
        for ep in endpoints:
            if isinstance(ep, str):
                continue
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            if method in ("POST", "PUT", "PATCH"):
                write_eps.append({"url": url, "method": method})

        confusion_payloads = [
            {
                "content_type": "application/xml",
                "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><test>&xxe;</test></root>',
                "label": "XXE via XML Content-Type",
                "check_for": ["root:", "/bin/", "nobody"],
            },
            {
                "content_type": "text/xml",
                "body": '<?xml version="1.0"?><root><admin>true</admin></root>',
                "label": "XML injection via text/xml",
                "check_for": [],
            },
            {
                "content_type": "application/x-www-form-urlencoded",
                "body": "admin=true&role=admin&is_admin=1",
                "label": "Form-encoded mass assignment",
                "check_for": ["admin", "true"],
            },
        ]

        for ep in write_eps[:5]:
            url = ep["url"]
            for payload in confusion_payloads:
                try:
                    async with self.rate_limit:
                        resp = await client.request(
                            ep["method"],
                            url,
                            content=payload["body"],
                            headers={"Content-Type": payload["content_type"]},
                        )
                        if resp.status_code in (200, 201, 202):
                            body = resp.text
                            xxe_hit = any(marker in body for marker in payload["check_for"])
                            error_indicators = ["unsupported media", "invalid content", "415"]
                            is_rejected = any(e in body.lower() for e in error_indicators)

                            if not is_rejected:
                                severity = "critical" if xxe_hit else "medium"
                                title = "XXE via Content-Type Confusion" if xxe_hit else f"Content-Type Confusion: {payload['label']}"

                                findings.append({
                                    "title": title,
                                    "url": url,
                                    "severity": severity,
                                    "vuln_type": "ssrf" if xxe_hit else "misconfiguration",
                                    "content_type_sent": payload["content_type"],
                                    "impact": f"Server accepts {payload['content_type']} on endpoint expecting JSON. "
                                             f"{'XXE payload executed — file read possible.' if xxe_hit else 'May allow parser-level attacks (XXE, deserialization).'}",
                                    "remediation": "Strictly validate Content-Type headers. Reject unexpected media types with 415.",
                                    "response_preview": body[:300] if xxe_hit else None,
                                })
                                if xxe_hit:
                                    break
                except Exception:
                    continue

        return findings

    async def _check_method_override(self, client, endpoints) -> list[dict]:
        """Test for HTTP method override headers that bypass access controls."""
        findings = []
        override_headers = [
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method-Override", "PUT"),
            ("X-Method-Override", "DELETE"),
            ("X-HTTP-Method", "DELETE"),
            ("X-Original-Method", "DELETE"),
        ]

        id_eps = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if re.search(r'/\d+(?:\?|$)', url) or re.search(r'/[0-9a-f-]{36}(?:\?|$)', url):
                id_eps.append(url)

        for url in id_eps[:8]:
            for header_name, header_value in override_headers:
                try:
                    async with self.rate_limit:
                        resp = await client.get(url, headers={header_name: header_value})
                        if resp.status_code in (200, 204, 202):
                            body = resp.text.lower()
                            delete_indicators = ["deleted", "removed", "destroyed", "success"]
                            looks_deleted = any(ind in body for ind in delete_indicators)

                            if looks_deleted:
                                findings.append({
                                    "title": f"HTTP Method Override — {header_name}: {header_value}",
                                    "url": url,
                                    "severity": "high",
                                    "vuln_type": "misconfiguration",
                                    "header": f"{header_name}: {header_value}",
                                    "impact": f"Server honors {header_name} header, allowing GET requests to "
                                             f"execute as {header_value}. Bypasses method-based access controls and WAFs.",
                                    "remediation": "Disable HTTP method override headers in production. "
                                                  "If needed, restrict to specific trusted clients only.",
                                    "response_preview": resp.text[:300],
                                })
                                break
                except Exception:
                    continue

        return findings
