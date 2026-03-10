"""
Subdomain Takeover Detection Module

Checks discovered subdomains for:
1. Dangling CNAME records pointing to unclaimed services
2. Common cloud service fingerprints (S3, Heroku, GitHub Pages, Azure, etc.)
3. Expired/unclaimed domains in CNAME chains
"""
import asyncio
import logging
import re

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Service fingerprints for subdomain takeover
TAKEOVER_FINGERPRINTS = {
    "aws_s3": {
        "cnames": ["s3.amazonaws.com", ".s3.amazonaws.com", "s3-website"],
        "indicators": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
    },
    "github_pages": {
        "cnames": ["github.io", "github.com"],
        "indicators": ["There isn't a GitHub Pages site here", "For root URLs"],
        "severity": "high",
    },
    "heroku": {
        "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "indicators": ["No such app", "no-such-app", "herokucdn.com/error-pages"],
        "severity": "high",
    },
    "azure": {
        "cnames": ["azurewebsites.net", "cloudapp.net", "azure-api.net",
                    "azurefd.net", "blob.core.windows.net", "trafficmanager.net"],
        "indicators": ["404 Web Site not found", "This Azure App Service is not available"],
        "severity": "high",
    },
    "shopify": {
        "cnames": ["myshopify.com"],
        "indicators": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "severity": "medium",
    },
    "fastly": {
        "cnames": ["fastly.net", "fastlylb.net"],
        "indicators": ["Fastly error: unknown domain"],
        "severity": "high",
    },
    "pantheon": {
        "cnames": ["pantheonsite.io"],
        "indicators": ["The gods are wise", "404 error unknown site"],
        "severity": "medium",
    },
    "surge": {
        "cnames": ["surge.sh"],
        "indicators": ["project not found"],
        "severity": "medium",
    },
    "netlify": {
        "cnames": ["netlify.app", "netlify.com"],
        "indicators": ["Not Found - Request ID"],
        "severity": "medium",
    },
    "zendesk": {
        "cnames": ["zendesk.com"],
        "indicators": ["Help Center Closed", "this help center no longer exists"],
        "severity": "medium",
    },
}


class SubdomainTakeoverModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)

    async def check(self, context: dict) -> list[dict]:
        subdomains = context.get("subdomains", [])
        if not subdomains:
            return []

        findings = []
        logger.info(f"Subdomain takeover: checking {len(subdomains)} subdomains")

        tasks = [self._check_subdomain(sub) for sub in subdomains[:50]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                findings.append(result)

        return findings

    async def _check_subdomain(self, subdomain: str) -> dict | None:
        try:
            # Step 1: DNS CNAME lookup
            import subprocess
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname = stdout.decode().strip().rstrip(".")

            if not cname:
                return None

            # Step 2: Check against known takeover fingerprints
            for service, config in TAKEOVER_FINGERPRINTS.items():
                if any(cn in cname.lower() for cn in config["cnames"]):
                    # Step 3: Verify by fetching the page
                    async with self.rate_limit:
                        async with make_client() as client:
                            try:
                                for scheme in ("https", "http"):
                                    resp = await client.get(f"{scheme}://{subdomain}")
                                    body = resp.text
                                    if any(ind in body for ind in config["indicators"]):
                                        return {
                                            "title": f"Subdomain Takeover: {subdomain} → {service}",
                                            "url": f"https://{subdomain}",
                                            "severity": config["severity"],
                                            "vuln_type": "subdomain_takeover",
                                            "subdomain": subdomain,
                                            "cname": cname,
                                            "service": service,
                                            "indicator": next(i for i in config["indicators"] if i in body),
                                            "impact": f"Subdomain {subdomain} has CNAME to {cname} ({service}) "
                                                     f"but the service is unclaimed. Attacker can claim it and "
                                                     f"serve malicious content on your domain.",
                                            "remediation": f"Either claim the {service} resource or remove the CNAME record.",
                                        }
                            except httpx.ConnectError:
                                # Connection refused = service doesn't exist = potential takeover
                                return {
                                    "title": f"Potential Subdomain Takeover: {subdomain} → {service}",
                                    "url": f"https://{subdomain}",
                                    "severity": "medium",
                                    "vuln_type": "subdomain_takeover",
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": service,
                                    "impact": f"Subdomain {subdomain} points to {cname} but connection refused.",
                                }
                            except Exception:
                                pass

            # Step 4: Check if CNAME target domain is expired/available
            if "." in cname:
                try:
                    proc2 = await asyncio.create_subprocess_exec(
                        "dig", "+short", "A", cname,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                    if not stdout2.decode().strip():
                        return {
                            "title": f"Dangling CNAME: {subdomain} → {cname} (NXDOMAIN)",
                            "url": f"https://{subdomain}",
                            "severity": "medium",
                            "vuln_type": "subdomain_takeover",
                            "subdomain": subdomain,
                            "cname": cname,
                            "impact": f"CNAME target {cname} has no DNS records. "
                                     "If the domain is available, attacker can register it.",
                        }
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Subdomain takeover check error for {subdomain}: {e}")
        return None
