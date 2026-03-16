"""
Vulnerability Scanner Module

Uses nuclei templates + custom checks + lightweight payload probing to find vulnerabilities.
Tools: nuclei, nikto, custom HTTP checks
"""
import asyncio
import json
import logging
import secrets
import tempfile
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from app.utils.tool_runner import run_command
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    async def run(self, context: dict) -> list[dict]:
        """Run vulnerability scanners against discovered endpoints."""
        self._custom_headers = context.get("custom_headers", {})
        domain = context["domain"]
        subdomains = context.get("subdomains", [])
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", f"https://{domain}")

        findings = []

        # Run multiple scanners in parallel
        tasks = [
            self._nuclei_scan(domain, subdomains),
            self._check_security_headers(base_url),
            self._check_cors(base_url, endpoints),
            self._check_sensitive_files(base_url, endpoints),
            self._quick_param_probe(endpoints),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _nuclei_scan(self, domain: str, subdomains: list[str]) -> list[dict]:
        """Run nuclei scanner with multiple template categories."""
        # Create target list
        targets = [domain] + subdomains[:20]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_path = f.name

        try:
            output = await run_command(
                [
                    "nuclei",
                    "-l", targets_path,
                    "-severity", "low,medium,high,critical",
                    "-type", "http",
                    "-json",
                    "-silent",
                    "-rate-limit", "50",
                    "-timeout", "10",
                    "-retries", "2",
                ],
                timeout=600,
            )

            findings = []
            if output:
                for line in output.strip().split("\n"):
                    try:
                        data = json.loads(line)
                        findings.append({
                            "source": "nuclei",
                            "template_id": data.get("template-id", ""),
                            "name": data.get("info", {}).get("name", ""),
                            "severity": data.get("info", {}).get("severity", "info"),
                            "url": data.get("matched-at", ""),
                            "type": data.get("type", ""),
                            "description": data.get("info", {}).get("description", ""),
                            "matched": data.get("matcher-name", ""),
                            "curl_command": data.get("curl-command", ""),
                        })
                    except json.JSONDecodeError:
                        continue

            return findings
        finally:
            os.unlink(targets_path)

    async def _check_security_headers(self, base_url: str) -> list[dict]:
        """Check for missing security headers."""
        findings = []
        required_headers = {
            "strict-transport-security": "Missing HSTS header",
            "x-content-type-options": "Missing X-Content-Type-Options header",
            "x-frame-options": "Missing X-Frame-Options header (clickjacking risk)",
            "content-security-policy": "Missing Content-Security-Policy header",
            "x-xss-protection": "Missing X-XSS-Protection header",
            "referrer-policy": "Missing Referrer-Policy header",
            "permissions-policy": "Missing Permissions-Policy header",
        }

        try:
            async with make_client(extra_headers=dict(self._custom_headers)) as client:
                resp = await client.get(base_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                for header, description in required_headers.items():
                    if header not in headers:
                        findings.append({
                            "source": "header_check",
                            "name": description,
                            "severity": "info",
                            "url": base_url,
                            "type": "misconfiguration",
                            "missing_header": header,
                        })
        except Exception:
            pass

        return findings

    async def _check_cors(self, base_url: str, endpoints: list[dict]) -> list[dict]:
        """Check for CORS misconfigurations."""
        findings = []
        targets = [e["url"] for e in endpoints[:20] if e.get("type") in ("api", "page")]
        if not targets:
            targets = [base_url]

        async with make_client(extra_headers=dict(self._custom_headers)) as client:
            for url in targets[:10]:
                try:
                    # Test with evil origin
                    resp = await client.get(
                        url,
                        headers={"Origin": "https://evil.com"},
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if acao == "https://evil.com" or acao == "*":
                        severity = "high" if acac.lower() == "true" else "medium"
                        findings.append({
                            "source": "cors_check",
                            "name": f"CORS Misconfiguration - Origin reflected",
                            "severity": severity,
                            "url": url,
                            "type": "cors_misconfiguration",
                            "details": {
                                "acao": acao,
                                "acac": acac,
                            },
                        })
                except Exception:
                    continue

        return findings

    async def _check_sensitive_files(self, base_url: str, endpoints: list[dict]) -> list[dict]:
        """Check for exposed sensitive files."""
        findings = []
        sensitive = [e for e in endpoints if e.get("type") == "sensitive"]

        async with make_client(extra_headers=dict(self._custom_headers)) as client:
            for endpoint in sensitive[:20]:
                try:
                    resp = await client.get(endpoint["url"])
                    if resp.status_code == 200:
                        body = resp.text[:1000]
                        # Check if it's actually sensitive content
                        is_sensitive = any(
                            indicator in body.lower()
                            for indicator in [
                                "password", "secret", "api_key", "database",
                                "db_host", "aws_", "private_key", "[core]",
                                "connectionstring", "smtp",
                            ]
                        )
                        if is_sensitive:
                            findings.append({
                                "source": "sensitive_file",
                                "name": f"Sensitive file exposed: {endpoint['url']}",
                                "severity": "critical",
                                "url": endpoint["url"],
                                "type": "info_disclosure",
                            })
                except Exception:
                    continue

        return findings

    async def _quick_param_probe(self, endpoints: list[dict]) -> list[dict]:
        """Lightweight probe of parameterized URLs for reflection (XSS) and SQL errors.

        Not a full exploit — just signals to flag endpoints for deeper testing.
        Tests at most 30 endpoints with 1 payload each.
        """
        findings = []

        # Collect endpoints that have query parameters
        param_endpoints = []
        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params and parsed.scheme in ("http", "https"):
                param_endpoints.append((url, parsed, params))

        if not param_endpoints:
            return findings

        marker = f"ph4nt0m{secrets.token_hex(4)}"

        sql_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "pg_query", "pg_exec",
            "mysql_fetch", "mysql_num_rows",
            "sqlite3.operationalerror",
            "microsoft ole db provider",
            "ora-01756", "ora-00933",
            "sqlstate[",
            "syntax error at or near",
            "warning: mysql",
            "valid mysql result",
        ]

        async with make_client(extra_headers=dict(self._custom_headers)) as client:
            sem = asyncio.Semaphore(5)

            async def _probe_one(url: str, parsed, params: dict):
                async with sem:
                    results = []
                    param_name = next(iter(params))
                    original_val = params[param_name][0] if params[param_name] else ""

                    # XSS reflection probe
                    try:
                        xss_payload = f'{marker}<"\'>'
                        new_params = dict(params)
                        new_params[param_name] = [xss_payload]
                        probe_url = urlunparse(parsed._replace(
                            query=urlencode(new_params, doseq=True)
                        ))
                        resp = await client.get(probe_url, timeout=8)
                        body = resp.text
                        if marker in body:
                            reflects_html = f'{marker}<' in body or f"{marker}\"" in body
                            if reflects_html:
                                results.append({
                                    "source": "param_probe",
                                    "name": f"Reflected XSS candidate: {param_name} on {parsed.path}",
                                    "severity": "medium",
                                    "url": url,
                                    "type": "xss",
                                    "parameter": param_name,
                                    "details": "Unencoded reflection of HTML special characters",
                                })
                    except Exception:
                        pass

                    # SQL error probe
                    try:
                        sqli_payload = f"{original_val}'\""
                        new_params = dict(params)
                        new_params[param_name] = [sqli_payload]
                        probe_url = urlunparse(parsed._replace(
                            query=urlencode(new_params, doseq=True)
                        ))
                        resp = await client.get(probe_url, timeout=8)
                        body_lower = resp.text.lower()
                        for err in sql_errors:
                            if err in body_lower:
                                results.append({
                                    "source": "param_probe",
                                    "name": f"SQL error triggered: {param_name} on {parsed.path}",
                                    "severity": "high",
                                    "url": url,
                                    "type": "sqli",
                                    "parameter": param_name,
                                    "details": f"SQL error pattern: {err}",
                                })
                                break
                    except Exception:
                        pass

                    return results

            tasks = [
                _probe_one(url, parsed, params)
                for url, parsed, params in param_endpoints[:30]
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)

        logger.info(f"Quick param probe: {len(param_endpoints[:30])} endpoints tested, {len(findings)} signals found")
        return findings
