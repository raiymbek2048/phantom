"""
Nuclei Deep Scan Module

Runs nuclei against discovered endpoints with:
1. Authentication support (cookies, headers, tokens)
2. Template category selection based on fingerprint results
3. Smart severity filtering per scan type
4. Rate limiting and stealth mode
5. Finding deduplication and classification
6. Custom template support
"""
import asyncio
import json
import logging
import os
import re
import tempfile
from urllib.parse import urlparse

from app.utils.tool_runner import run_command

logger = logging.getLogger(__name__)

# Map fingerprinted technologies to nuclei template tags
TECH_TO_TEMPLATES = {
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "magento": ["magento"],
    "shopify": ["shopify"],
    "laravel": ["laravel"],
    "django": ["django"],
    "spring": ["springboot", "spring"],
    "asp.net": ["aspnet", "iis"],
    "tomcat": ["tomcat", "apache"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "kibana": ["kibana"],
    "elasticsearch": ["elasticsearch"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes"],
    "aws": ["aws", "amazon"],
    "azure": ["azure"],
    "google cloud": ["gcloud"],
    "php": ["php"],
    "node": ["nodejs"],
}


class NucleiModule:
    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    VULN_TYPE_MAP = {
        "xss": "xss",
        "sqli": "sqli",
        "ssrf": "ssrf",
        "ssti": "ssrf",
        "lfi": "sqli",
        "rfi": "sqli",
        "rce": "sqli",
        "command-injection": "sqli",
        "cve": "misconfiguration",
        "default-login": "auth_bypass",
        "exposure": "info_disclosure",
        "misconfiguration": "misconfiguration",
        "misconfig": "misconfiguration",
        "file-upload": "misconfiguration",
        "redirect": "xss",
        "open-redirect": "xss",
        "cors": "misconfiguration",
        "crlf": "xss",
        "xxe": "ssrf",
        "idor": "auth_bypass",
        "auth-bypass": "auth_bypass",
        "token": "info_disclosure",
        "credential": "info_disclosure",
        "disclosure": "info_disclosure",
        "takeover": "misconfiguration",
        "subdomain-takeover": "misconfiguration",
    }

    _templates_ready = False

    async def _ensure_templates(self):
        """Download nuclei templates if not already present."""
        if NucleiModule._templates_ready:
            return
        templates_dir = os.path.expanduser("~/.local/nuclei-templates")
        if os.path.isdir(templates_dir) and len(os.listdir(templates_dir)) > 10:
            NucleiModule._templates_ready = True
            return
        logger.info("Nuclei templates not found, downloading...")
        try:
            result = await run_command(
                ["nuclei", "-update-templates", "-ud", templates_dir],
                timeout=300,
            )
            logger.info(f"Nuclei templates downloaded: {result[:200]}")
            NucleiModule._templates_ready = True
        except Exception as e:
            logger.error(f"Failed to download nuclei templates: {e}")
            # Try default location as fallback
            try:
                await run_command(["nuclei", "-update-templates"], timeout=300)
                NucleiModule._templates_ready = True
            except Exception as e2:
                logger.error(f"Nuclei template fallback also failed: {e2}")

    async def run(self, context: dict) -> list[dict]:
        """Run nuclei against all discovered endpoints with auth."""
        # Ensure templates are available
        await self._ensure_templates()

        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        technologies = context.get("technologies", [])
        scan_type = context.get("scan_type", "full")

        # Build URL list — include base URL + unique endpoint URLs
        urls = set()
        if base_url:
            urls.add(base_url)
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url:
                parsed = urlparse(url)
                # Add both full URL and base path (nuclei works better with paths)
                urls.add(url)
                if parsed.path and parsed.path != "/":
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    urls.add(base)
        # Always add common paths for the base domain
        if base_url:
            parsed_base = urlparse(base_url)
            for path in ["/", "/api", "/admin", "/login", "/wp-admin", "/wp-login.php"]:
                urls.add(f"{parsed_base.scheme}://{parsed_base.netloc}{path}")

        if not urls:
            logger.warning("Nuclei: no URLs to scan")
            return []

        logger.info(f"Nuclei: scanning {len(urls)} unique URLs")

        # Write URLs to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            targets_path = f.name

        try:
            # Run general scan
            findings = await self._run_nuclei(targets_path, auth_cookie, context)
            logger.info(f"Nuclei general scan: {len(findings)} findings")

            # Run tech-specific templates if we have fingerprint data
            tech_tags = self._get_tech_tags(technologies)
            if tech_tags:
                logger.info(f"Nuclei tech scan: tags={tech_tags}")
                tech_findings = await self._run_nuclei_tags(
                    targets_path, auth_cookie, context, tech_tags
                )
                findings.extend(tech_findings)
                logger.info(f"Nuclei tech scan: {len(tech_findings)} findings")

            # Run CVE templates separately (focused scan)
            if scan_type in ("full", "deep"):
                cve_findings = await self._run_nuclei_cves(targets_path, auth_cookie, context)
                findings.extend(cve_findings)
                logger.info(f"Nuclei CVE scan: {len(cve_findings)} findings")

            # Deduplicate
            findings = self._deduplicate(findings)

            logger.info(f"Nuclei TOTAL: {len(findings)} unique findings across {len(urls)} URLs")
            return findings
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []
        finally:
            try:
                os.unlink(targets_path)
            except OSError:
                pass

    def _get_tech_tags(self, technologies: list) -> list[str]:
        """Convert fingerprinted technologies to nuclei template tags."""
        tags = set()
        if isinstance(technologies, dict):
            tech_list = list(technologies.get("summary", {}).keys())
        elif isinstance(technologies, list):
            tech_list = technologies
        else:
            return []

        for tech in tech_list:
            tech_lower = tech.lower().split()[0]  # "WordPress 6.1" -> "wordpress"
            for key, template_tags in TECH_TO_TEMPLATES.items():
                if key in tech_lower:
                    tags.update(template_tags)

        return list(tags)

    async def _run_nuclei(self, targets_path: str, auth_cookie: str | None,
                          context: dict) -> list[dict]:
        """Run nuclei with general templates."""
        is_stealth = context.get("stealth", False)
        scan_type = context.get("scan_type", "full")

        # Determine severity filter based on scan type
        if scan_type == "quick":
            severity = "critical,high"
        elif scan_type == "stealth":
            severity = "critical,high,medium"
        else:
            severity = "low,medium,high,critical"

        cmd = [
            "nuclei",
            "-l", targets_path,
            "-severity", severity,
            "-json",
            "-silent",
            "-timeout", "10",
            "-retries", "1",
            "-no-color",
            "-exclude-tags", "dos,fuzz",  # Never run DoS or heavy fuzzing
        ]

        if is_stealth:
            cmd.extend(["-rate-limit", "10", "-bulk-size", "5", "-concurrency", "5"])
        else:
            cmd.extend(["-rate-limit", "100", "-bulk-size", "25", "-concurrency", "25"])

        if auth_cookie:
            if auth_cookie.startswith("token="):
                token = auth_cookie.split("=", 1)[1]
                cmd.extend(["-header", f"Authorization: Bearer {token}"])
            else:
                cmd.extend(["-header", f"Cookie: {auth_cookie}"])

        # Add custom templates directory if exists
        custom_templates = "/app/nuclei-templates-custom"
        if os.path.isdir(custom_templates):
            cmd.extend(["-t", custom_templates])

        try:
            output = await run_command(cmd, timeout=900)
            if not output or not output.strip():
                logger.warning("Nuclei general scan returned empty output")
            return self._parse_output(output)
        except Exception as e:
            logger.error(f"Nuclei general scan error: {e}")
            return []

    async def _run_nuclei_tags(self, targets_path: str, auth_cookie: str | None,
                                context: dict, tags: list[str]) -> list[dict]:
        """Run nuclei with specific technology tags."""
        if not tags:
            return []

        cmd = [
            "nuclei",
            "-l", targets_path,
            "-tags", ",".join(tags[:10]),
            "-severity", "low,medium,high,critical",
            "-json",
            "-silent",
            "-timeout", "10",
            "-retries", "1",
            "-no-color",
            "-exclude-tags", "dos,fuzz",
            "-rate-limit", "50",
            "-bulk-size", "10",
        ]

        if auth_cookie:
            if auth_cookie.startswith("token="):
                token = auth_cookie.split("=", 1)[1]
                cmd.extend(["-header", f"Authorization: Bearer {token}"])
            else:
                cmd.extend(["-header", f"Cookie: {auth_cookie}"])

        try:
            output = await run_command(cmd, timeout=600)
            return self._parse_output(output)
        except Exception as e:
            logger.error(f"Nuclei tech scan error: {e}")
            return []

    async def _run_nuclei_cves(self, targets_path: str, auth_cookie: str | None,
                                context: dict) -> list[dict]:
        """Run nuclei CVE-specific templates."""
        cmd = [
            "nuclei",
            "-l", targets_path,
            "-tags", "cve",
            "-severity", "critical,high",
            "-json",
            "-silent",
            "-timeout", "10",
            "-retries", "1",
            "-no-color",
            "-exclude-tags", "dos,fuzz",
            "-rate-limit", "30",
            "-bulk-size", "10",
        ]

        if auth_cookie:
            if auth_cookie.startswith("token="):
                token = auth_cookie.split("=", 1)[1]
                cmd.extend(["-header", f"Authorization: Bearer {token}"])
            else:
                cmd.extend(["-header", f"Cookie: {auth_cookie}"])

        try:
            output = await run_command(cmd, timeout=600)
            return self._parse_output(output)
        except Exception as e:
            logger.error(f"Nuclei CVE scan error: {e}")
            return []

    def _parse_output(self, output: str | None) -> list[dict]:
        """Parse nuclei JSON output into findings."""
        findings = []
        if not output:
            return findings

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            template_id = data.get("template-id", "unknown")
            matched_url = data.get("matched-at", "")
            severity = info.get("severity", "info").lower()
            name = info.get("name", template_id)
            description = info.get("description", "")
            remediation = info.get("remediation", "")
            reference = info.get("reference", [])

            # Map to our vuln type
            vuln_type = self._classify(template_id, info)

            # Build CVE reference
            cve_id = None
            if isinstance(reference, list):
                for ref in reference:
                    if isinstance(ref, str) and "cve" in ref.lower():
                        cve_match = re.search(r'CVE-\d{4}-\d+', ref, re.IGNORECASE) if re else None
                        if cve_match:
                            cve_id = cve_match.group()
                            break
            elif template_id.upper().startswith("CVE-"):
                cve_id = template_id.upper()

            # Extract CVSS if available
            classification = info.get("classification", {})
            cvss_score = classification.get("cvss-score")
            cvss_metrics = classification.get("cvss-metrics")
            cwe_id = classification.get("cwe-id", [])

            finding = {
                "title": f"[Nuclei] {name}",
                "url": matched_url,
                "severity": self.SEVERITY_MAP.get(severity, "medium"),
                "vuln_type": vuln_type,
                "description": description,
                "remediation": remediation,
                "source": "nuclei",
                "template_id": template_id,
                "matched": data.get("matcher-name", ""),
                "curl_command": data.get("curl-command", ""),
                "request_data": {
                    "template": template_id,
                    "matcher": data.get("matcher-name", ""),
                    "extracted": data.get("extracted-results", []),
                    "type": data.get("type", ""),
                },
            }

            if cve_id:
                finding["cve_id"] = cve_id
            if cvss_score:
                finding["cvss_score"] = cvss_score
            if cvss_metrics:
                finding["cvss_metrics"] = cvss_metrics
            if cwe_id:
                finding["cwe_id"] = cwe_id
            if reference:
                finding["references"] = reference if isinstance(reference, list) else [reference]

            findings.append(finding)

        return findings

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings by template+url."""
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('template_id', '')}|{f.get('url', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _classify(self, template_id: str, info: dict) -> str:
        """Classify nuclei finding into our vulnerability type."""
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        # Check tags first (more specific)
        for tag in tags:
            tag_lower = tag.lower()
            for key, vtype in self.VULN_TYPE_MAP.items():
                if key == tag_lower:
                    return vtype

        # Partial match on tags
        for tag in tags:
            tag_lower = tag.lower()
            for key, vtype in self.VULN_TYPE_MAP.items():
                if key in tag_lower:
                    return vtype

        # Check template ID
        tid = template_id.lower()
        for key, vtype in self.VULN_TYPE_MAP.items():
            if key in tid:
                return vtype

        # Check name/description
        name = info.get("name", "").lower()
        for key, vtype in self.VULN_TYPE_MAP.items():
            if key in name:
                return vtype

        return "misconfiguration"
