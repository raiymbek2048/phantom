"""
Reconnaissance Module — gathers initial intelligence about the target.

Tools: whois, dig, theHarvester, Shodan, Google Dorking, Wayback Machine
"""
import asyncio
import json
import re

from app.utils.tool_runner import run_command
from app.utils.http_client import make_client
from app.config import get_settings
from app.modules.response_analyzer import ResponseAnalyzer

settings = get_settings()


class ReconModule:
    async def run(self, domain: str, base_url: str = None, context: dict = None) -> dict:
        """Run full reconnaissance on a domain."""
        self._custom_headers = (context or {}).get("custom_headers", {})
        results = {}
        if base_url is None:
            base_url = f"https://{domain}"

        is_internal = ":" in domain or domain.replace(".", "").isdigit() or "." not in domain

        if is_internal:
            # Internal/IP target — skip DNS/whois, just check robots/sitemap
            tasks = [
                self._check_robots_sitemap(domain, base_url),
                self._analyze_main_page(base_url),
            ]
            task_names = ["robots_sitemap", "main_page_intel"]
        else:
            tasks = [
                self._whois(domain),
                self._dns_records(domain),
                self._wayback_urls(domain),
                self._check_robots_sitemap(domain, base_url),
                self._certificate_transparency(domain),
                self._check_security_txt(base_url),
                self._analyze_main_page(base_url),
            ]
            task_names = ["whois", "dns_records", "wayback_urls", "robots_sitemap",
                         "ct_subdomains", "security_txt", "main_page_intel"]
            if settings.shodan_api_key:
                tasks.append(self._shodan_lookup(domain))
                task_names.append("shodan")

        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for name, result in zip(task_names, gathered):
            if isinstance(result, Exception):
                results[name] = {"error": str(result)}
            else:
                results[name] = result

        return results

    async def _whois(self, domain: str) -> dict:
        """Get WHOIS information."""
        output = await run_command(["whois", domain], timeout=30)
        return self._parse_whois(output)

    async def _dns_records(self, domain: str) -> list[dict]:
        """Get DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA)."""
        records = []
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

        tasks = []
        for rtype in record_types:
            tasks.append(self._dig_record(domain, rtype))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for rtype, result in zip(record_types, results):
            if not isinstance(result, Exception) and result:
                for value in result:
                    records.append({"type": rtype, "value": value})

        return records

    async def _dig_record(self, domain: str, record_type: str) -> list[str]:
        """Get specific DNS record type."""
        output = await run_command(
            ["dig", "+short", domain, record_type],
            timeout=10,
        )
        if output:
            return [line.strip() for line in output.strip().split("\n") if line.strip()]
        return []

    async def _wayback_urls(self, domain: str) -> list[str]:
        """Get historical URLs from Wayback Machine via gau."""
        try:
            output = await run_command(
                ["gau", "--threads", "5", "--subs", domain],
                timeout=60,
            )
            if output:
                urls = list(set(output.strip().split("\n")))
                return urls[:500]  # Limit
        except Exception:
            pass
        return []

    async def _check_robots_sitemap(self, domain: str, base_url: str = None) -> dict:
        """Check robots.txt and sitemap.xml."""
        if base_url is None:
            base_url = f"https://{domain}"

        result = {"robots_txt": None, "sitemap": None, "interesting_paths": []}

        async with make_client(extra_headers=dict(self._custom_headers)) as client:
            try:
                resp = await client.get(f"{base_url}/robots.txt")
                if resp.status_code == 200:
                    result["robots_txt"] = resp.text[:5000]
                    for line in resp.text.split("\n"):
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                result["interesting_paths"].append(path)
            except Exception:
                pass

            try:
                resp = await client.get(f"{base_url}/sitemap.xml")
                if resp.status_code == 200:
                    result["sitemap"] = resp.text[:10000]
            except Exception:
                pass

        return result

    async def _shodan_lookup(self, domain: str) -> dict:
        """Query Shodan for target information."""
        async with make_client(extra_headers=dict(self._custom_headers), timeout=15.0) as client:
            resp = await client.get(
                f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={settings.shodan_api_key}"
            )
            if resp.status_code != 200:
                return {"error": "Shodan API error"}

            ip_data = resp.json()
            ip = ip_data.get(domain)
            if not ip:
                return {"error": "Could not resolve IP"}

            # Get host info
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={settings.shodan_api_key}"
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": ip,
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                }
            return {"ip": ip}

    async def _certificate_transparency(self, domain: str) -> list[str]:
        """Query crt.sh for subdomains from certificate transparency logs."""
        subdomains = set()
        try:
            async with make_client(timeout=30.0) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code == 200:
                    certs = resp.json()
                    for cert in certs:
                        name = cert.get("name_value", "")
                        for line in name.split("\n"):
                            line = line.strip().lower()
                            if line.endswith(f".{domain}") or line == domain:
                                if "*" not in line:
                                    subdomains.add(line)
        except Exception:
            pass

        return list(subdomains)[:200]

    async def _check_security_txt(self, base_url: str) -> dict | None:
        """Check .well-known/security.txt for security contact and policy info."""
        try:
            async with make_client(extra_headers=dict(self._custom_headers)) as client:
                for path in ["/.well-known/security.txt", "/security.txt"]:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200 and "contact" in resp.text.lower():
                        return {
                            "found": True,
                            "url": f"{base_url}{path}",
                            "content": resp.text[:2000],
                        }
        except Exception:
            pass
        return None

    async def _analyze_main_page(self, base_url: str) -> dict:
        """Fetch main page and run ResponseAnalyzer for WAF, tech leaks, and secrets."""
        result = {"waf": None, "tech_leaks": [], "secrets": []}
        try:
            async with make_client(extra_headers=dict(self._custom_headers)) as client:
                resp = await client.get(base_url, follow_redirects=True)
                headers = dict(resp.headers)
                body = resp.text
                status_code = resp.status_code

                # 1. WAF detection
                result["waf"] = ResponseAnalyzer.detect_waf(headers, body, status_code)

                # 2. Technology leak extraction
                result["tech_leaks"] = ResponseAnalyzer.extract_tech_leaks(headers, body)

                # 3. Secret scan on main page body
                result["secrets"] = ResponseAnalyzer.find_secrets(body)
        except Exception:
            pass
        return result

    def _parse_whois(self, raw: str) -> dict:
        """Parse WHOIS output into structured data."""
        data = {"raw": raw[:3000]}
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiry_date": r"Registry Expiry Date:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "registrant_org": r"Registrant Organization:\s*(.+)",
            "registrant_country": r"Registrant Country:\s*(.+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if matches:
                data[key] = matches if len(matches) > 1 else matches[0]
        return data
