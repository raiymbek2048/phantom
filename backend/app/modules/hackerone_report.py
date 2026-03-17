"""
HackerOne Report Generator

Generates vulnerability reports in HackerOne submission format:
- Summary
- Vulnerability Type (CWE)
- Severity (CVSS if possible)
- Steps to Reproduce
- Impact Statement
- PoC (request/response)
- Remediation Suggestion
"""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Map PHANTOM vuln types to CWE IDs (HackerOne uses CWE classification)
VULN_TYPE_TO_CWE = {
    "sqli": {"cwe": "CWE-89", "name": "SQL Injection"},
    "sqli_blind": {"cwe": "CWE-89", "name": "Blind SQL Injection"},
    "xss": {"cwe": "CWE-79", "name": "Cross-Site Scripting (XSS)"},
    "xss_reflected": {"cwe": "CWE-79", "name": "Reflected Cross-Site Scripting (XSS)"},
    "xss_stored": {"cwe": "CWE-79", "name": "Stored Cross-Site Scripting (XSS)"},
    "xss_dom": {"cwe": "CWE-79", "name": "DOM-Based Cross-Site Scripting (XSS)"},
    "cmd_injection": {"cwe": "CWE-78", "name": "OS Command Injection"},
    "rce": {"cwe": "CWE-94", "name": "Remote Code Execution"},
    "ssrf": {"cwe": "CWE-918", "name": "Server-Side Request Forgery (SSRF)"},
    "xxe": {"cwe": "CWE-611", "name": "XML External Entity (XXE)"},
    "idor": {"cwe": "CWE-639", "name": "Insecure Direct Object Reference (IDOR)"},
    "csrf": {"cwe": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)"},
    "lfi": {"cwe": "CWE-98", "name": "Local File Inclusion"},
    "rfi": {"cwe": "CWE-98", "name": "Remote File Inclusion"},
    "open_redirect": {"cwe": "CWE-601", "name": "Open Redirect"},
    "auth_bypass": {"cwe": "CWE-287", "name": "Authentication Bypass"},
    "info_disclosure": {"cwe": "CWE-200", "name": "Information Disclosure"},
    "misconfiguration": {"cwe": "CWE-16", "name": "Security Misconfiguration"},
    "deserialization": {"cwe": "CWE-502", "name": "Insecure Deserialization"},
    "race_condition": {"cwe": "CWE-362", "name": "Race Condition"},
    "file_upload": {"cwe": "CWE-434", "name": "Unrestricted File Upload"},
    "cors": {"cwe": "CWE-942", "name": "CORS Misconfiguration"},
    "cors_misconfiguration": {"cwe": "CWE-942", "name": "CORS Misconfiguration"},
    "jwt_vulnerability": {"cwe": "CWE-345", "name": "JWT Token Vulnerability"},
    "prototype_pollution": {"cwe": "CWE-1321", "name": "Prototype Pollution"},
    "cache_poisoning": {"cwe": "CWE-444", "name": "Web Cache Poisoning"},
    "subdomain_takeover": {"cwe": "CWE-284", "name": "Subdomain Takeover"},
    "ssti": {"cwe": "CWE-1336", "name": "Server-Side Template Injection (SSTI)"},
    "path_traversal": {"cwe": "CWE-22", "name": "Path Traversal"},
    "header_injection": {"cwe": "CWE-113", "name": "HTTP Response Splitting"},
    "business_logic": {"cwe": "CWE-840", "name": "Business Logic Error"},
    "graphql": {"cwe": "CWE-200", "name": "GraphQL Information Disclosure"},
    "mass_assignment": {"cwe": "CWE-915", "name": "Mass Assignment"},
    "request_smuggling": {"cwe": "CWE-444", "name": "HTTP Request Smuggling"},
    "account_enumeration": {"cwe": "CWE-204", "name": "Account Enumeration"},
    "mfa_bypass": {"cwe": "CWE-308", "name": "MFA Bypass"},
}

# CVSS 3.1 estimates by vuln type (more accurate than severity-only mapping)
VULN_TYPE_CVSS = {
    "xss":                 {"score": 6.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "xss_reflected":       {"score": 6.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "xss_stored":          {"score": 8.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"},
    "xss_dom":             {"score": 6.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "sqli":                {"score": 9.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "sqli_blind":          {"score": 8.6,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "ssrf":                {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "rce":                 {"score": 9.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "cmd_injection":       {"score": 9.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "idor":                {"score": 6.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "auth_bypass":         {"score": 9.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "csrf":                {"score": 4.3,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "lfi":                 {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "rfi":                 {"score": 9.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ssti":                {"score": 8.6,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "xxe":                 {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "deserialization":     {"score": 9.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "open_redirect":       {"score": 4.7,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"},
    "file_upload":         {"score": 8.8,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "info_disclosure":     {"score": 5.3,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "misconfiguration":    {"score": 4.3,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "cors":                {"score": 5.3,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "cors_misconfiguration": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "path_traversal":      {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "subdomain_takeover":  {"score": 8.2,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"},
    "race_condition":      {"score": 5.9,  "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"},
    "mass_assignment":     {"score": 6.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "request_smuggling":   {"score": 8.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "cache_poisoning":     {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
    "account_enumeration": {"score": 5.3,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "mfa_bypass":          {"score": 8.1,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
}

# Severity to CVSS approximate mapping
SEVERITY_CVSS = {
    "critical": {"score": "9.0-10.0", "rating": "Critical"},
    "high": {"score": "7.0-8.9", "rating": "High"},
    "medium": {"score": "4.0-6.9", "rating": "Medium"},
    "low": {"score": "0.1-3.9", "rating": "Low"},
    "info": {"score": "0.0", "rating": "None"},
}


class HackerOneReport:
    """Generates HackerOne-compatible vulnerability reports."""

    def generate(self, vuln: dict) -> dict:
        """Generate a HackerOne report from a vulnerability dict.

        vuln should have: vuln_type, title, url, method, parameter,
        payload_used, request_data, response_data, severity, remediation, description
        """
        vuln_type = vuln.get("vuln_type", "")
        if hasattr(vuln_type, "value"):
            vuln_type = vuln_type.value

        severity = vuln.get("severity", "medium")
        if hasattr(severity, "value"):
            severity = severity.value

        cwe_info = VULN_TYPE_TO_CWE.get(vuln_type, {"cwe": "CWE-0", "name": vuln_type})
        # Type-specific CVSS first, then severity fallback
        cvss_type = VULN_TYPE_CVSS.get(vuln_type)
        cvss_info = (
            {"score": str(cvss_type["score"]), "rating": _cvss_rating(cvss_type["score"]), "vector": cvss_type["vector"]}
            if cvss_type
            else {**SEVERITY_CVSS.get(severity, SEVERITY_CVSS["medium"]), "vector": "N/A"}
        )

        title = vuln.get("title", f"{cwe_info['name']} on {vuln.get('url', 'target')}")
        url = vuln.get("url", "")
        method = vuln.get("method", "GET")
        parameter = vuln.get("parameter", "")
        payload = vuln.get("payload_used", "")
        request_data = vuln.get("request_data", {})
        response_data = vuln.get("response_data", {})

        # Build the markdown report
        summary = self._build_summary(title, cwe_info, url, vuln)
        steps = self._build_steps_to_reproduce(url, method, parameter, payload, request_data)
        impact = self._build_impact(vuln_type, cwe_info, severity, vuln)
        poc = self._build_poc(request_data, response_data, payload)
        remediation = self._build_remediation(vuln.get("remediation", ""), vuln_type)
        curl_cmd = self._build_curl(url, method, parameter, payload, request_data)
        cwe_num = cwe_info["cwe"].split("-")[1] if "-" in cwe_info["cwe"] else "0"
        owasp_ref = _get_owasp_reference(vuln_type)
        cvss_vector_str = cvss_info.get("vector", "N/A")

        markdown = f"""## Summary

{summary}

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Type** | {cwe_info['name']} |
| **CWE** | [{cwe_info['cwe']}](https://cwe.mitre.org/data/definitions/{cwe_num}.html) |
| **CVSS Score** | {cvss_info['score']} ({cvss_info['rating']}) |
| **CVSS Vector** | `{cvss_vector_str}` |
| **URL** | `{url}` |
| **Parameter** | `{parameter or 'N/A'}` |
| **Method** | {method} |

## Steps to Reproduce

{steps}

{f"## cURL Command{chr(10)}{chr(10)}```bash{chr(10)}{curl_cmd}{chr(10)}```" if curl_cmd else ""}

## Impact

{impact}

## Proof of Concept

{poc}

## Remediation

{remediation}

## References

- [{cwe_info['cwe']}: {cwe_info['name']}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)
{f'- {owasp_ref}' if owasp_ref else ''}
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1#{cvss_vector_str.replace("CVSS:3.1/", "")})

---
*Report generated by PHANTOM Security Scanner — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*
"""

        return {
            "title": title,
            "vuln_type_cwe": cwe_info["cwe"],
            "severity": severity,
            "cvss_score": cvss_info["score"],
            "cvss_vector": cvss_vector_str,
            "cvss_rating": cvss_info["rating"],
            "markdown": markdown.strip(),
            "sections": {
                "summary": summary,
                "steps_to_reproduce": steps,
                "impact": impact,
                "poc": poc,
                "curl_command": curl_cmd,
                "remediation": remediation,
            },
        }

    def _build_summary(self, title: str, cwe_info: dict, url: str, vuln: dict) -> str:
        desc = vuln.get("description", "")
        parameter = vuln.get("parameter", "")
        payload = vuln.get("payload_used", "")

        if desc and len(desc) > 50:
            return desc

        param_str = f" via the `{parameter}` parameter" if parameter else ""
        payload_str = f" The payload `{payload[:80]}` was used to confirm the issue." if payload else ""

        return (
            f"A **{cwe_info['name']}** ({cwe_info['cwe']}) vulnerability was identified at `{url}`{param_str}. "
            f"This issue allows an attacker to exploit the application through the identified attack vector.{payload_str}"
        )

    def _build_steps_to_reproduce(self, url: str, method: str, parameter: str,
                                    payload: str, request_data: dict) -> str:
        steps = []
        steps.append(f"1. Navigate to: `{url}`")

        if method.upper() == "POST" and parameter:
            steps.append(f"2. In the `{parameter}` parameter, inject the following payload:")
            steps.append(f"   ```\n   {payload}\n   ```")
            steps.append(f"3. Submit the form using {method} method")
        elif parameter:
            steps.append(f"2. Modify the `{parameter}` parameter with the following payload:")
            steps.append(f"   ```\n   {payload}\n   ```")
            steps.append(f"3. Send the request")
        elif payload:
            steps.append(f"2. Use the following payload:")
            steps.append(f"   ```\n   {payload}\n   ```")
            steps.append(f"3. Observe the response")

        if request_data:
            curl_cmd = self._build_curl(url, method, parameter, payload, request_data)
            if curl_cmd:
                steps.append(f"\n**cURL command:**\n```bash\n{curl_cmd}\n```")

        steps.append(f"\n4. Observe that the vulnerability is triggered as shown in the PoC section below.")

        return "\n".join(steps)

    def _build_impact(self, vuln_type: str, cwe_info: dict, severity: str, vuln: dict) -> str:
        impact_map = {
            "sqli": "An attacker can extract, modify, or delete data from the database. In severe cases, this can lead to full database compromise, authentication bypass, or remote code execution via SQL injection techniques.",
            "sqli_blind": "An attacker can extract sensitive data from the database using blind SQL injection techniques (boolean-based or time-based). This can lead to full database enumeration and data exfiltration.",
            "xss": "An attacker can execute arbitrary JavaScript in a victim's browser session. This can be used to steal session cookies, perform actions on behalf of the user, or redirect to phishing pages.",
            "xss_reflected": "An attacker can execute arbitrary JavaScript in a victim's browser session by crafting a malicious URL. This can be used to steal session cookies, perform actions on behalf of the user, or redirect to phishing pages.",
            "xss_stored": "An attacker can permanently inject malicious JavaScript that executes for all users viewing the affected page. This can lead to mass session hijacking, credential theft, or malware distribution.",
            "xss_dom": "An attacker can execute arbitrary JavaScript through DOM manipulation, potentially bypassing server-side security controls.",
            "cmd_injection": "An attacker can execute arbitrary operating system commands on the server, potentially leading to full server compromise, data theft, or lateral movement within the infrastructure.",
            "rce": "An attacker can execute arbitrary code on the server, leading to complete system compromise, data exfiltration, and persistent backdoor installation.",
            "ssrf": "An attacker can make the server perform requests to internal services, potentially accessing internal APIs, cloud metadata endpoints (AWS/GCP/Azure credentials), or other restricted resources behind the firewall.",
            "xxe": "An attacker can read arbitrary files from the server, perform SSRF attacks, or cause denial of service through XML External Entity injection.",
            "idor": "An attacker can access or modify resources belonging to other users by manipulating object references, leading to unauthorized data access, privacy violations, or account takeover.",
            "csrf": "An attacker can perform actions on behalf of authenticated users without their consent, potentially changing account settings, making purchases, or modifying data.",
            "auth_bypass": "An attacker can bypass authentication mechanisms and gain unauthorized access to protected resources or administrative functions, potentially compromising the entire application.",
            "deserialization": "An attacker can execute arbitrary code or manipulate application logic through insecure deserialization of user-controlled data, leading to remote code execution.",
            "subdomain_takeover": "An attacker can take control of a subdomain and serve arbitrary content, potentially stealing cookies, conducting phishing attacks, or bypassing CSP protections.",
            "lfi": "An attacker can read arbitrary files from the server, including configuration files, credentials, and source code. Combined with log poisoning or PHP wrappers, this can escalate to remote code execution.",
            "rfi": "An attacker can include remote files for execution on the server, leading to remote code execution and complete system compromise.",
            "ssti": "An attacker can inject template directives that execute on the server, potentially leading to remote code execution, file system access, and full server compromise.",
            "open_redirect": "An attacker can redirect users to malicious sites, facilitating phishing attacks, credential theft, or OAuth token hijacking.",
            "file_upload": "An attacker can upload malicious files (web shells, malware) to the server, potentially achieving remote code execution and persistent access.",
            "info_disclosure": "Sensitive information is exposed to unauthorized parties, including internal paths, API keys, credentials, or user data that can be leveraged for further attacks.",
            "misconfiguration": "Security misconfiguration exposes the application to various attacks, including unauthorized access, information leakage, or denial of service.",
            "cors": "Misconfigured CORS policy allows attacker-controlled websites to read sensitive data from the application on behalf of authenticated users.",
            "path_traversal": "An attacker can read arbitrary files outside the intended directory, potentially accessing credentials, configuration files, and other sensitive data.",
            "race_condition": "An attacker can exploit timing-dependent operations to bypass limits, duplicate transactions, or escalate privileges through concurrent requests.",
            "mass_assignment": "An attacker can modify restricted object properties by injecting additional parameters, potentially escalating privileges or modifying protected fields.",
            "request_smuggling": "An attacker can desynchronize frontend and backend request parsing, potentially bypassing security controls, hijacking other users' requests, or poisoning the web cache.",
            "cache_poisoning": "An attacker can inject malicious content into the web cache, causing it to be served to other users, potentially leading to XSS or phishing at scale.",
            "account_enumeration": "An attacker can determine valid usernames/emails through differential responses, enabling targeted brute-force, credential stuffing, or social engineering attacks.",
            "mfa_bypass": "An attacker can bypass multi-factor authentication, undermining a critical security layer and gaining unauthorized access to protected accounts.",
            "business_logic": "An attacker can exploit flaws in the business logic to perform unauthorized actions such as bypassing payment, manipulating prices, or escalating privileges.",
        }

        impact_text = impact_map.get(vuln_type,
            f"This {cwe_info['name']} vulnerability ({cwe_info['cwe']}) can be exploited "
            f"to compromise the security of the application and its users.")

        return impact_text

    def _build_poc(self, request_data: dict, response_data: dict, payload: str) -> str:
        parts = []

        if request_data:
            req_str = ""
            if isinstance(request_data, dict):
                method = request_data.get("method", "GET")
                url = request_data.get("url", "")
                headers = request_data.get("headers", {})
                body = request_data.get("body", "")

                req_str = f"{method} {url} HTTP/1.1\n"
                for k, v in headers.items():
                    req_str += f"{k}: {v}\n"
                if body:
                    req_str += f"\n{body}"
            else:
                req_str = str(request_data)

            if req_str.strip():
                parts.append(f"**Request:**\n```http\n{req_str.strip()}\n```")

        if response_data:
            resp_str = ""
            if isinstance(response_data, dict):
                status = response_data.get("status_code", "")
                body = response_data.get("body", "")
                # Truncate long responses
                if body and len(body) > 500:
                    body = body[:500] + "\n... (truncated)"
                resp_str = f"HTTP/1.1 {status}\n\n{body}" if status else (body or "")
            else:
                resp_str = str(response_data)[:500]

            if resp_str.strip():
                parts.append(f"**Response (relevant portion):**\n```http\n{resp_str.strip()}\n```")

        if not parts and payload:
            parts.append(f"**Payload used:**\n```\n{payload}\n```")

        if not parts:
            parts.append("*Proof of concept details are available in the full scan report.*")

        return "\n\n".join(parts)

    def _build_remediation(self, existing: str, vuln_type: str) -> str:
        if existing:
            return existing

        remediation_map = {
            "sqli": "Use parameterized queries (prepared statements) for all database interactions. Implement input validation and escape special characters. Consider using an ORM. Apply the principle of least privilege to database accounts.",
            "sqli_blind": "Use parameterized queries (prepared statements) for all database interactions. Implement input validation and escape special characters. Monitor and alert on slow queries.",
            "xss": "Encode all user input before reflecting it in HTML responses. Implement a strict Content Security Policy (CSP). Use framework-provided auto-escaping (e.g., React JSX, Django templates).",
            "xss_reflected": "Encode all user input before reflecting it in HTML responses. Implement Content Security Policy (CSP) headers. Use framework-provided auto-escaping.",
            "xss_stored": "Sanitize and encode all user input before storing and displaying it. Implement CSP headers. Use allowlists for permitted HTML tags if rich text is needed.",
            "xss_dom": "Avoid using dangerous DOM APIs (innerHTML, document.write). Use textContent instead. Implement a strict CSP with no unsafe-inline/unsafe-eval.",
            "cmd_injection": "Avoid passing user input to system commands. If necessary, use allowlists for permitted values and parameterized command execution (e.g., subprocess.run with array args, not shell=True).",
            "rce": "Eliminate code execution paths from user input. Use sandboxed execution environments. Apply the principle of least privilege to application processes.",
            "ssrf": "Validate and sanitize all URLs provided by users. Implement allowlists for permitted domains/IPs. Block access to internal network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254) and disable file:// and gopher:// schemes.",
            "xxe": "Disable external entity processing in XML parsers. Use JSON instead of XML where possible. If XML is required, use a properly configured parser with DTD processing disabled.",
            "idor": "Implement proper authorization checks for all object access. Use indirect reference maps or UUIDs instead of sequential IDs. Verify user permissions server-side on every request.",
            "csrf": "Implement anti-CSRF tokens for all state-changing operations. Use SameSite=Strict or SameSite=Lax cookie attribute. Verify Origin/Referer headers.",
            "lfi": "Validate file paths against a strict allowlist. Use chroot or sandboxed file access. Never pass user input directly to file system operations. Disable PHP wrappers (allow_url_include=Off).",
            "rfi": "Disable remote file inclusion (allow_url_include=Off in PHP). Validate file paths against a strict allowlist. Use static file mappings instead of dynamic includes.",
            "ssti": "Never pass user input directly into template strings. Use sandboxed template rendering. Prefer logic-less templates (Mustache). Apply input validation.",
            "open_redirect": "Validate redirect URLs against an allowlist of trusted domains. Use relative paths instead of full URLs. Never use user input directly in Location headers or meta refresh tags.",
            "file_upload": "Validate file type using magic bytes (not just extension). Store uploads outside the webroot. Use a CDN or separate domain for serving uploads. Scan for malware.",
            "info_disclosure": "Remove sensitive data from API responses. Use DTOs to control output fields. Disable debug mode, stack traces, and verbose error messages in production. Remove server version headers.",
            "misconfiguration": "Review and harden server configuration per CIS benchmarks. Implement security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options). Remove default credentials.",
            "cors": "Configure Access-Control-Allow-Origin to specific trusted domains only. Never reflect arbitrary origins. Do not combine wildcard origins with Access-Control-Allow-Credentials.",
            "path_traversal": "Validate file paths against an allowlist. Use chroot or sandboxed file access. Resolve canonical paths and verify they stay within the intended directory.",
            "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON). Implement integrity checks (HMAC) on serialized objects. Use allowlist-based deserialization filters.",
            "auth_bypass": "Implement proper authentication verification on every protected endpoint. Use established authentication frameworks. Enforce MFA. Validate tokens server-side.",
            "subdomain_takeover": "Remove dangling DNS records pointing to deprovisioned services. Monitor DNS records for unclaimed third-party services. Implement subdomain inventory management.",
            "race_condition": "Use database-level locking (SELECT FOR UPDATE) or atomic operations. Implement idempotency keys for sensitive operations. Use Redis distributed locks for critical sections.",
            "mass_assignment": "Use allowlists to explicitly define which fields can be set by user input. Never pass raw request data directly to model updates. Use DTOs or serializers with explicit field declarations.",
            "request_smuggling": "Normalize HTTP parsing between frontend and backend. Reject ambiguous requests with both Content-Length and Transfer-Encoding. Use HTTP/2 end-to-end.",
            "cache_poisoning": "Ensure all inputs that affect response content are included in the cache key. Validate Host and X-Forwarded-Host headers. Use Vary headers appropriately.",
            "account_enumeration": "Return identical responses for valid and invalid usernames. Use generic error messages. Implement rate limiting and CAPTCHA on authentication endpoints.",
            "mfa_bypass": "Implement MFA checks server-side before granting access. Do not expose MFA state in client-side code. Rate-limit MFA attempts. Invalidate MFA sessions on suspicious activity.",
            "business_logic": "Implement server-side validation for all business rules. Do not rely on client-side controls. Add monitoring and alerting for anomalous business transactions.",
        }

        return remediation_map.get(vuln_type,
            "Review the vulnerability details and implement appropriate security controls. "
            "Consult OWASP guidelines for recommended mitigations.")

    def _build_curl(self, url: str, method: str, parameter: str, payload: str,
                     request_data: dict) -> str:
        """Build a cURL command for the PoC."""
        parts = ["curl"]

        if method.upper() != "GET":
            parts.append(f"-X {method.upper()}")

        # Add headers from request_data
        if isinstance(request_data, dict):
            for k, v in request_data.get("headers", {}).items():
                parts.append(f'-H "{k}: {v}"')

            body = request_data.get("body", "")
            if body:
                # Escape single quotes in body
                body_escaped = body.replace("'", "'\\''")
                parts.append(f"-d '{body_escaped}'")
            elif method.upper() == "POST" and parameter and payload:
                payload_escaped = payload.replace("'", "'\\''")
                parts.append(f"-d '{parameter}={payload_escaped}'")

        parts.append(f'"{url}"')

        return " \\\n  ".join(parts)


def _cvss_rating(score) -> str:
    """Convert numeric CVSS score to severity rating string."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Medium"
    if s >= 9.0:
        return "Critical"
    elif s >= 7.0:
        return "High"
    elif s >= 4.0:
        return "Medium"
    elif s >= 0.1:
        return "Low"
    return "None"


def _get_owasp_reference(vuln_type: str) -> str:
    """Get OWASP reference URL for a vuln type."""
    owasp_map = {
        "sqli": "[OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)",
        "sqli_blind": "[OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)",
        "xss": "[OWASP: XSS](https://owasp.org/www-community/attacks/xss/)",
        "xss_reflected": "[OWASP: XSS](https://owasp.org/www-community/attacks/xss/)",
        "xss_stored": "[OWASP: XSS](https://owasp.org/www-community/attacks/xss/)",
        "xss_dom": "[OWASP: DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)",
        "ssrf": "[OWASP: SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)",
        "csrf": "[OWASP: CSRF](https://owasp.org/www-community/attacks/csrf)",
        "xxe": "[OWASP: XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)",
        "idor": "[OWASP: IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)",
        "cmd_injection": "[OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)",
        "rce": "[OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection)",
        "lfi": "[OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)",
        "path_traversal": "[OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)",
        "ssti": "[OWASP: SSTI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)",
        "open_redirect": "[OWASP: Open Redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)",
        "file_upload": "[OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)",
        "deserialization": "[OWASP: Deserialization](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests)",
        "auth_bypass": "[OWASP: Broken Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/)",
        "info_disclosure": "[OWASP: Information Leakage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)",
        "misconfiguration": "[OWASP: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)",
        "cors": "[OWASP: CORS](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)",
        "mass_assignment": "[OWASP: Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)",
        "request_smuggling": "[OWASP: HTTP Request Smuggling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling)",
    }
    return owasp_map.get(vuln_type, "")


def generate_hackerone_report(vuln: dict) -> dict:
    """Convenience function to generate a HackerOne report."""
    return HackerOneReport().generate(vuln)
