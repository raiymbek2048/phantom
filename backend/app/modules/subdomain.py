"""
Subdomain Discovery Module

Multi-source subdomain enumeration:
1. subfinder — passive enumeration from multiple data sources
2. assetfinder — certificate transparency + web archives
3. crt.sh — Certificate Transparency logs via API
4. DNS brute-force — common subdomain wordlist
5. httpx — alive host verification
6. Wildcard detection — filters false positives
"""
import asyncio
import json
import logging
import re
from urllib.parse import urlparse

import httpx

from app.utils.tool_runner import run_command
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Common subdomains for DNS brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "portal", "vpn", "remote", "gateway",
    "api", "api2", "api3", "rest", "graphql",
    "dev", "development", "staging", "stage", "stg", "qa", "uat", "test", "testing",
    "beta", "alpha", "demo", "sandbox", "preview",
    "app", "apps", "mobile", "m",
    "cdn", "static", "assets", "media", "images", "img",
    "blog", "cms", "wp", "wordpress",
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "ci", "cd", "jenkins", "travis", "drone", "build",
    "monitor", "monitoring", "grafana", "prometheus", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "mongo", "redis", "memcached",
    "mq", "rabbit", "rabbitmq", "kafka", "queue",
    "auth", "sso", "login", "oauth", "identity", "id",
    "docs", "documentation", "help", "support", "wiki", "kb",
    "internal", "intranet", "corp", "corporate",
    "backup", "bak", "old", "legacy", "archive",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay",
    "panel", "cpanel", "control", "dashboard",
    "shop", "store", "pay", "payment", "billing", "checkout",
    "status", "health", "ping",
    "jira", "confluence", "slack", "teams",
    "s3", "storage", "files", "upload",
    "proxy", "lb", "loadbalancer",
]


class SubdomainModule:
    async def run(self, domain: str) -> list[str]:
        """Discover subdomains using multiple tools, then verify which are alive."""
        # Step 1: Check for wildcard DNS
        is_wildcard = await self._check_wildcard(domain)
        if is_wildcard:
            logger.info(f"Wildcard DNS detected for {domain}")

        # Step 2: Run all discovery sources in parallel
        tasks = [
            self._subfinder(domain),
            self._assetfinder(domain),
            self._crtsh(domain),
            self._dns_bruteforce(domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge all subdomains
        all_subdomains = set()
        source_counts = {}
        source_names = ["subfinder", "assetfinder", "crt.sh", "dns_brute"]
        for i, result in enumerate(results):
            if isinstance(result, list):
                count = len(result)
                all_subdomains.update(result)
                source_counts[source_names[i]] = count
            elif isinstance(result, Exception):
                logger.warning(f"Subdomain source {source_names[i]} failed: {result}")
                source_counts[source_names[i]] = 0

        logger.info(f"Subdomain discovery for {domain}: {len(all_subdomains)} unique "
                    f"(sources: {source_counts})")

        if not all_subdomains:
            return []

        # Step 3: Clean and deduplicate
        cleaned = self._clean_subdomains(all_subdomains, domain)

        # Step 4: Filter wildcard false positives
        if is_wildcard:
            cleaned = await self._filter_wildcard(cleaned, domain)

        # Step 5: Verify alive hosts with httpx
        alive = await self._check_alive(list(cleaned))

        logger.info(f"Subdomain results for {domain}: {len(cleaned)} discovered, {len(alive)} alive")
        return sorted(alive)

    async def _check_wildcard(self, domain: str) -> bool:
        """Detect wildcard DNS by resolving a random subdomain."""
        import random
        import string
        random_sub = "".join(random.choices(string.ascii_lowercase, k=12))
        test_domain = f"{random_sub}.{domain}"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(test_domain, 80),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _subfinder(self, domain: str) -> list[str]:
        """Passive subdomain enumeration with subfinder."""
        from app.utils.http_client import get_proxy_url
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        proxy_url = get_proxy_url()
        if proxy_url:
            cmd.extend(["-proxy", proxy_url])
        output = await run_command(cmd, timeout=120)
        if output:
            return [s.strip() for s in output.strip().split("\n") if s.strip()]
        return []

    async def _assetfinder(self, domain: str) -> list[str]:
        """Find subdomains with assetfinder."""
        output = await run_command(
            ["assetfinder", "--subs-only", domain],
            timeout=60,
        )
        if output:
            return [s.strip() for s in output.strip().split("\n") if s.strip()]
        return []

    async def _crtsh(self, domain: str) -> list[str]:
        """Query crt.sh Certificate Transparency logs."""
        subdomains = []
        try:
            async with make_client() as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=30,
                )
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        name = entry.get("name_value", "")
                        # crt.sh can return multi-line names
                        for line in name.split("\n"):
                            sub = line.strip().lower()
                            if sub and "*" not in sub and sub.endswith(f".{domain}"):
                                subdomains.append(sub)
        except Exception as e:
            logger.debug(f"crt.sh query failed for {domain}: {e}")

        return list(set(subdomains))

    async def _dns_bruteforce(self, domain: str) -> list[str]:
        """Brute-force common subdomain names via DNS resolution."""
        found = []
        sem = asyncio.Semaphore(20)

        async def check_sub(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                async with sem:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(fqdn, 80),
                        timeout=3,
                    )
                    writer.close()
                    await writer.wait_closed()
                    found.append(fqdn)
            except Exception:
                # Also try DNS resolution via getaddrinfo
                try:
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.getaddrinfo(fqdn, None),
                        timeout=3,
                    )
                    found.append(fqdn)
                except Exception:
                    pass

        tasks = [check_sub(sub) for sub in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks)

        return found

    def _clean_subdomains(self, subdomains: set[str], parent_domain: str) -> set[str]:
        """Clean and validate discovered subdomains."""
        cleaned = set()
        parent_lower = parent_domain.lower()

        for sub in subdomains:
            sub = sub.strip().lower()
            # Remove protocol if present
            sub = re.sub(r'^https?://', '', sub)
            # Remove path/port
            sub = sub.split("/")[0].split(":")[0]
            # Must end with parent domain
            if not sub.endswith(f".{parent_lower}") and sub != parent_lower:
                continue
            # Must be valid hostname
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', sub):
                continue
            # Skip wildcard entries
            if "*" in sub:
                continue
            cleaned.add(sub)

        return cleaned

    async def _filter_wildcard(self, subdomains: set[str], domain: str) -> set[str]:
        """Filter out wildcard false positives by comparing response sizes."""
        import random
        import string

        # Get wildcard response fingerprint
        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        wildcard_host = f"{random_sub}.{domain}"

        wildcard_len = None
        try:
            async with make_client() as client:
                resp = await client.get(f"http://{wildcard_host}", timeout=5)
                wildcard_len = len(resp.text)
        except Exception:
            return subdomains  # Can't determine wildcard, return all

        # Filter: keep subdomains with different response lengths
        filtered = set()
        async with make_client() as client:
            sem = asyncio.Semaphore(10)
            async def check(sub: str):
                try:
                    async with sem:
                        resp = await client.get(f"http://{sub}", timeout=5)
                        resp_len = len(resp.text)
                        # If response length differs significantly from wildcard, it's real
                        if wildcard_len is None or abs(resp_len - wildcard_len) > 50:
                            filtered.add(sub)
                except Exception:
                    filtered.add(sub)  # Keep if we can't verify

            await asyncio.gather(*[check(sub) for sub in subdomains])

        return filtered

    async def _check_alive(self, subdomains: list[str]) -> list[str]:
        """Check which subdomains are alive using httpx tool or fallback."""
        if not subdomains:
            return []

        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(subdomains))
            tmp_path = f.name

        try:
            output = await run_command(
                ["gohttpx", "-l", tmp_path, "-silent", "-nc", "-timeout", "5"],
                timeout=180,
            )
            if output:
                alive = []
                for line in output.strip().split("\n"):
                    line = line.strip()
                    if line:
                        domain = line.replace("https://", "").replace("http://", "").split("/")[0]
                        alive.append(domain)
                return list(set(alive))
        except Exception:
            logger.debug("gohttpx not available, falling back to async HTTP checks")
            return await self._check_alive_fallback(subdomains)
        finally:
            os.unlink(tmp_path)

        return []

    async def _check_alive_fallback(self, subdomains: list[str]) -> list[str]:
        """Fallback alive check using httpx library."""
        alive = []
        sem = asyncio.Semaphore(20)

        async def check(sub: str):
            async with sem:
                for scheme in ("https", "http"):
                    try:
                        async with httpx.AsyncClient(
                            verify=False,
                            timeout=httpx.Timeout(5),
                            follow_redirects=True,
                        ) as client:
                            resp = await client.get(f"{scheme}://{sub}")
                            if resp.status_code < 500:
                                alive.append(sub)
                                return
                    except Exception:
                        continue

        await asyncio.gather(*[check(sub) for sub in subdomains])
        return alive
