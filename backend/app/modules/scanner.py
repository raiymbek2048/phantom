"""
Vulnerability Scanner Module

Uses nuclei templates + custom checks to find vulnerabilities.
Tools: nuclei, nikto, custom HTTP checks
"""
import asyncio
import json
import tempfile
import os

from app.utils.tool_runner import run_command
from app.utils.http_client import make_client


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
