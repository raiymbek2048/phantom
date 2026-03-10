"""
External API Integrations

Enriches scan data with Shodan, SecurityTrails, and VirusTotal.
"""
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class ShodanClient:
    """Query Shodan for host information, open ports, and known vulnerabilities."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self):
        self.api_key = settings.shodan_api_key

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def host_info(self, ip: str) -> dict | None:
        """Get host information from Shodan."""
        if not self.available:
            return None
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/shodan/host/{ip}",
                    params={"key": self.api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": data.get("ip_str"),
                        "org": data.get("org"),
                        "os": data.get("os"),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "hostnames": data.get("hostnames", []),
                        "services": [
                            {
                                "port": s.get("port"),
                                "transport": s.get("transport"),
                                "product": s.get("product"),
                                "version": s.get("version"),
                            }
                            for s in data.get("data", [])[:20]
                        ],
                    }
        except Exception as e:
            logger.warning(f"Shodan API error: {e}")
        return None

    async def search(self, query: str) -> list[dict]:
        """Search Shodan for hosts matching a query."""
        if not self.available:
            return []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/shodan/host/search",
                    params={"key": self.api_key, "query": query},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        {
                            "ip": m.get("ip_str"),
                            "port": m.get("port"),
                            "org": m.get("org"),
                            "product": m.get("product"),
                        }
                        for m in data.get("matches", [])[:20]
                    ]
        except Exception as e:
            logger.warning(f"Shodan search error: {e}")
        return []


class SecurityTrailsClient:
    """Query SecurityTrails for DNS and subdomain data."""

    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(self):
        self.api_key = settings.securitytrails_api_key

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def subdomains(self, domain: str) -> list[str]:
        """Get subdomains from SecurityTrails."""
        if not self.available:
            return []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/domain/{domain}/subdomains",
                    headers={"APIKEY": self.api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        f"{sub}.{domain}"
                        for sub in data.get("subdomains", [])
                    ]
        except Exception as e:
            logger.warning(f"SecurityTrails API error: {e}")
        return []

    async def dns_history(self, domain: str) -> dict | None:
        """Get DNS history for a domain."""
        if not self.available:
            return None
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/history/{domain}/dns/a",
                    headers={"APIKEY": self.api_key},
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.warning(f"SecurityTrails DNS history error: {e}")
        return None


class ExternalAPIs:
    """Unified interface for all external API integrations."""

    def __init__(self):
        self.shodan = ShodanClient()
        self.securitytrails = SecurityTrailsClient()

    async def enrich_recon(self, domain: str, ip: str = None) -> dict:
        """Enrich recon data with external API results."""
        enrichment = {"sources": []}

        if self.shodan.available and ip:
            shodan_data = await self.shodan.host_info(ip)
            if shodan_data:
                enrichment["shodan"] = shodan_data
                enrichment["sources"].append("shodan")

        if self.securitytrails.available:
            st_subs = await self.securitytrails.subdomains(domain)
            if st_subs:
                enrichment["securitytrails_subdomains"] = st_subs
                enrichment["sources"].append("securitytrails")

        return enrichment
