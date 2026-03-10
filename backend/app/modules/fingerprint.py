"""
Technology Fingerprinting Module

Detects web technologies, frameworks, CMS, servers, CDNs, WAFs.
Also analyzes security headers and extracts version info.
"""
import asyncio
import re
import logging

import httpx as httpx_lib

from app.utils.tool_runner import run_command

logger = logging.getLogger(__name__)

# Technology signatures based on response headers, body patterns, cookies
TECH_SIGNATURES = {
    # CMS
    "WordPress": {
        "body": [r"wp-content", r"wp-includes", r"wp-json", r"/wp-login\.php"],
        "headers": {"x-powered-by": "WordPress"},
        "meta": [r'name="generator"\s+content="WordPress\s*([\d.]+)?'],
    },
    "Joomla": {
        "body": [r"/media/jui/", r"Joomla!", r"/administrator/"],
        "meta": [r'name="generator"\s+content="Joomla!\s*([\d.]+)?'],
    },
    "Drupal": {
        "body": [r"Drupal\.settings", r"sites/default/files", r"/misc/drupal\.js"],
        "headers": {"x-generator": "Drupal", "x-drupal-cache": ""},
    },
    "Magento": {
        "body": [r"Mage\.Cookies", r"/skin/frontend/", r"varien/js\.js"],
        "cookies": ["frontend", "adminhtml"],
    },
    "Shopify": {
        "body": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"x-shopify-stage": ""},
    },
    "Ghost": {
        "body": [r"ghost-url", r"content/themes/"],
        "headers": {"x-powered-by": "Ghost"},
    },

    # JS Frameworks
    "React": {
        "body": [r"__NEXT_DATA__", r"react-root", r"_reactRoot", r"data-reactroot",
                 r"react\.production\.min\.js", r"__REACT_DEVTOOLS"],
    },
    "Next.js": {
        "body": [r"__NEXT_DATA__", r"/_next/static", r"__next"],
        "headers": {"x-powered-by": "Next.js"},
    },
    "Nuxt.js": {
        "body": [r"__NUXT__", r"/_nuxt/", r"nuxt-link"],
    },
    "Angular": {
        "body": [r"ng-version", r"ng-app", r"ng-controller", r"angular\.min\.js"],
    },
    "Vue.js": {
        "body": [r"__vue__", r"vue-router", r"v-bind", r"v-model"],
    },
    "Svelte": {
        "body": [r"__svelte", r"svelte-"],
    },
    "jQuery": {
        "body": [r"jquery[\.-][\d.]+\.(?:min\.)?js", r"jQuery\s*v?([\d.]+)"],
    },

    # Backend Frameworks
    "Django": {
        "headers": {},
        "body": [r"csrfmiddlewaretoken", r"__debug__", r"django"],
        "cookies": ["csrftoken", "sessionid"],
    },
    "Flask": {
        "headers": {},
        "cookies": ["session"],
        "body": [r"Werkzeug"],
    },
    "FastAPI": {
        "body": [r"/docs", r"/openapi\.json", r"swagger-ui"],
    },
    "Laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body": [r"laravel"],
    },
    "Rails": {
        "headers": {"x-powered-by": "Phusion Passenger"},
        "cookies": ["_session_id"],
        "body": [r"csrf-token", r"csrf-param"],
        "meta": [r'name="csrf-token"'],
    },
    "Express.js": {
        "headers": {"x-powered-by": "Express"},
    },
    "Spring Boot": {
        "body": [r"Whitelabel Error Page", r"spring-boot"],
        "headers": {},
    },
    "ASP.NET": {
        "headers": {"x-powered-by": "ASP.NET", "x-aspnet-version": ""},
        "cookies": ["ASP.NET_SessionId", ".AspNetCore."],
        "body": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
    },

    # Languages
    "PHP": {
        "headers": {"x-powered-by": "PHP"},
    },
    "Java": {
        "headers": {"x-powered-by": "Servlet"},
        "cookies": ["JSESSIONID"],
    },
    "Python": {
        "headers": {"x-powered-by": "Python"},
    },

    # Web Servers
    "Nginx": {
        "headers": {"server": "nginx"},
    },
    "Apache": {
        "headers": {"server": "Apache"},
    },
    "IIS": {
        "headers": {"server": "Microsoft-IIS"},
    },
    "LiteSpeed": {
        "headers": {"server": "LiteSpeed"},
    },
    "Caddy": {
        "headers": {"server": "Caddy"},
    },

    # CDN & Proxy
    "Cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": ""},
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": "", "server": "AkamaiGHost"},
    },
    "Fastly": {
        "headers": {"x-served-by": "", "x-cache": "", "via": "varnish"},
    },
    "AWS CloudFront": {
        "headers": {"x-amz-cf-id": "", "via": "CloudFront"},
    },
    "Vercel": {
        "headers": {"x-vercel-id": "", "server": "Vercel"},
    },
    "Netlify": {
        "headers": {"x-nf-request-id": "", "server": "Netlify"},
    },

    # Cloud
    "AWS S3": {
        "headers": {"server": "AmazonS3", "x-amz-request-id": ""},
    },
    "Google Cloud": {
        "headers": {"x-goog-": "", "server": "GSE"},
    },
    "Azure": {
        "headers": {"x-ms-request-id": "", "x-azure-ref": ""},
    },
    "Heroku": {
        "headers": {"via": "heroku"},
    },

    # WAF
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "body": [r"ModSecurity", r"mod_security"],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": "", "server": "Sucuri"},
    },
    "Imperva": {
        "headers": {"x-iinfo": ""},
        "cookies": ["incap_ses_", "visid_incap_"],
    },
    "AWS WAF": {
        "headers": {"x-amzn-waf-": ""},
    },

    # Analytics & Marketing
    "Google Analytics": {
        "body": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"googletagmanager\.com"],
    },
    "Google Tag Manager": {
        "body": [r"googletagmanager\.com/gtm\.js"],
    },
    "Hotjar": {
        "body": [r"static\.hotjar\.com"],
    },
    "Sentry": {
        "body": [r"sentry\.io", r"Sentry\.init"],
    },
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "present": True,
        "missing_severity": "medium",
        "missing_impact": "No HSTS header — vulnerable to SSL stripping attacks.",
    },
    "Content-Security-Policy": {
        "present": True,
        "missing_severity": "medium",
        "missing_impact": "No CSP header — increased XSS risk.",
        "dangerous_values": ["unsafe-inline", "unsafe-eval", "*"],
    },
    "X-Content-Type-Options": {
        "present": True,
        "expected": "nosniff",
        "missing_severity": "low",
        "missing_impact": "Missing X-Content-Type-Options — MIME sniffing possible.",
    },
    "X-Frame-Options": {
        "present": True,
        "missing_severity": "medium",
        "missing_impact": "Missing X-Frame-Options — clickjacking possible.",
    },
    "X-XSS-Protection": {
        "present": True,
        "missing_severity": "info",
        "missing_impact": "Missing X-XSS-Protection header (legacy, but still useful for older browsers).",
    },
    "Referrer-Policy": {
        "present": True,
        "missing_severity": "low",
        "missing_impact": "Missing Referrer-Policy — referrer leakage to third parties.",
    },
    "Permissions-Policy": {
        "present": True,
        "missing_severity": "low",
        "missing_impact": "Missing Permissions-Policy — browser features not restricted.",
    },
    "X-Powered-By": {
        "present": False,
        "present_severity": "low",
        "present_impact": "X-Powered-By header exposes technology stack.",
    },
    "Server": {
        "check_version": True,
        "version_severity": "low",
        "version_impact": "Server header exposes version information.",
    },
}


class FingerprintModule:
    async def run(self, domain: str, subdomains: list[str], base_url: str = None) -> dict:
        """Fingerprint technologies for domain and subdomains."""
        self._base_url = base_url
        targets = [domain] + subdomains[:10]
        results = {}
        security_findings = []

        semaphore = asyncio.Semaphore(10)

        async def scan(target):
            async with semaphore:
                return target, await self._fingerprint(target)

        tasks = [scan(t) for t in targets]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        all_techs = {}
        all_versions = {}
        for result in gathered:
            if isinstance(result, tuple):
                target, fp_result = result
                results[target] = fp_result.get("technologies", [])
                security_findings.extend(fp_result.get("security_issues", []))
                for tech in fp_result.get("technologies", []):
                    all_techs[tech] = all_techs.get(tech, 0) + 1
                for tech, ver in fp_result.get("versions", {}).items():
                    all_versions[tech] = ver

        return {
            "by_host": results,
            "summary": all_techs,
            "versions": all_versions,
            "security_issues": security_findings,
        }

    async def _fingerprint(self, target: str) -> dict:
        """Identify technologies for a single target."""
        detected = []
        versions = {}
        security_issues = []

        urls_to_try = []
        if self._base_url and target == self._base_url.split("//")[1].split("/")[0].split(":")[0]:
            urls_to_try = [self._base_url]
        else:
            urls_to_try = [f"https://{target}", f"http://{target}"]

        for url in urls_to_try:
            try:
                async with httpx_lib.AsyncClient(
                    timeout=10.0, verify=False, follow_redirects=True
                ) as client:
                    resp = await client.get(url)

                    # Tech detection
                    techs, vers = self._match_signatures(resp)
                    detected.extend(techs)
                    versions.update(vers)

                    # Security header analysis
                    issues = self._check_security_headers(resp, url)
                    security_issues.extend(issues)

                    # Check robots.txt and sitemap for tech clues
                    extra = await self._check_meta_files(client, url)
                    detected.extend(extra)

                    break
            except Exception:
                continue

        return {
            "technologies": list(set(detected)),
            "versions": versions,
            "security_issues": security_issues,
        }

    def _match_signatures(self, response) -> tuple[list[str], dict]:
        """Match response against known technology signatures."""
        detected = []
        versions = {}
        body = response.text[:100000]
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = {c.name.lower(): c.value for c in response.cookies.jar}

        for tech, sigs in TECH_SIGNATURES.items():
            matched = False

            # Check headers
            for header_key, header_val in sigs.get("headers", {}).items():
                for actual_key, actual_val in headers.items():
                    if header_key in actual_key:
                        if not header_val or header_val.lower() in actual_val:
                            matched = True
                            # Try to extract version from header
                            ver_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', actual_val)
                            if ver_match:
                                versions[tech] = ver_match.group()
                            break
                if matched:
                    break

            # Check body patterns
            if not matched:
                for pattern in sigs.get("body", []):
                    m = re.search(pattern, body, re.IGNORECASE)
                    if m:
                        matched = True
                        # If pattern has a capture group, use it as version
                        if m.groups():
                            ver = m.group(1)
                            if ver:
                                versions[tech] = ver
                        break

            # Check meta tags
            if not matched:
                for pattern in sigs.get("meta", []):
                    m = re.search(pattern, body, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups():
                            ver = m.group(1)
                            if ver:
                                versions[tech] = ver
                        break

            # Check cookies
            if not matched:
                for cookie_name in sigs.get("cookies", []):
                    for actual_cookie in cookies:
                        if cookie_name.lower() in actual_cookie:
                            matched = True
                            break
                    if matched:
                        break

            if matched:
                ver_str = f" {versions[tech]}" if tech in versions else ""
                detected.append(f"{tech}{ver_str}")

        # Extract server header with version
        if "server" in headers:
            server_raw = response.headers.get("server", "")
            if server_raw and server_raw.lower() not in [t.lower() for t in detected]:
                detected.append(f"Server: {server_raw}")

        return detected, versions

    def _check_security_headers(self, response, url: str) -> list[dict]:
        """Analyze security headers and return findings."""
        issues = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, config in SECURITY_HEADERS.items():
            header_lower = header.lower()
            value = headers.get(header_lower)

            if config.get("present"):
                # Header SHOULD be present
                if value is None:
                    issues.append({
                        "title": f"Missing Security Header: {header}",
                        "url": url,
                        "severity": config.get("missing_severity", "low"),
                        "vuln_type": "misconfiguration",
                        "impact": config.get("missing_impact", f"Missing {header} header."),
                        "remediation": f"Add the {header} response header.",
                    })
                else:
                    # Check for dangerous values
                    dangerous = config.get("dangerous_values", [])
                    found_dangerous = [d for d in dangerous if d in value.lower()]
                    if found_dangerous:
                        issues.append({
                            "title": f"Weak {header}: {', '.join(found_dangerous)}",
                            "url": url,
                            "severity": "medium",
                            "vuln_type": "misconfiguration",
                            "impact": f"{header} contains unsafe directives: {', '.join(found_dangerous)}",
                            "remediation": f"Remove unsafe directives from {header}.",
                            "header_value": value,
                        })
            elif config.get("present") is False:
                # Header should NOT be present
                if value is not None:
                    issues.append({
                        "title": f"Information Leak: {header}",
                        "url": url,
                        "severity": config.get("present_severity", "info"),
                        "vuln_type": "info_disclosure",
                        "impact": config.get("present_impact", f"{header} header reveals technology."),
                        "remediation": f"Remove the {header} header from responses.",
                        "header_value": value,
                    })

            # Version check
            if config.get("check_version") and value:
                if re.search(r'[\d]+\.[\d]+', value):
                    issues.append({
                        "title": f"Version Disclosure: {header}: {value}",
                        "url": url,
                        "severity": config.get("version_severity", "info"),
                        "vuln_type": "info_disclosure",
                        "impact": config.get("version_impact", "Server version exposed."),
                        "remediation": f"Remove version information from {header} header.",
                        "header_value": value,
                    })

        # Check for CORS misconfiguration
        acao = headers.get("access-control-allow-origin")
        if acao == "*":
            acac = headers.get("access-control-allow-credentials")
            severity = "high" if acac and acac.lower() == "true" else "medium"
            issues.append({
                "title": "CORS Misconfiguration: Wildcard Origin",
                "url": url,
                "severity": severity,
                "vuln_type": "misconfiguration",
                "impact": "Access-Control-Allow-Origin set to *. "
                         f"{'Combined with Allow-Credentials, this allows credential theft.' if severity == 'high' else 'Cross-origin requests unrestricted.'}",
                "remediation": "Restrict CORS to specific trusted origins.",
            })

        return issues

    async def _check_meta_files(self, client: httpx_lib.AsyncClient, base_url: str) -> list[str]:
        """Check robots.txt, sitemap.xml for technology clues."""
        detected = []

        try:
            resp = await client.get(f"{base_url}/robots.txt", timeout=5)
            if resp.status_code == 200:
                body = resp.text.lower()
                if "wp-admin" in body or "wp-includes" in body:
                    detected.append("WordPress (robots.txt)")
                if "administrator" in body:
                    detected.append("Joomla (robots.txt)")
                if "/admin/" in body and "magento" in body:
                    detected.append("Magento (robots.txt)")
        except Exception:
            pass

        try:
            resp = await client.get(f"{base_url}/.well-known/security.txt", timeout=5)
            if resp.status_code == 200 and "contact" in resp.text.lower():
                detected.append("security.txt present")
        except Exception:
            pass

        return detected
