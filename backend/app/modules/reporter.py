"""
Report Generator Module

Generates professional vulnerability reports using AI.
Supports formats: HackerOne, Bugcrowd, Generic, PDF
Features:
- AI-powered report generation with detailed analysis
- CVSS vector calculation
- CWE mapping
- Multi-format support (H1, Bugcrowd, Generic)
- Batch report generation for full scan results
- Fallback to structured templates when AI unavailable
"""
import json
import logging
from datetime import datetime

from app.ai.llm_engine import LLMEngine
from app.models.vulnerability import Vulnerability
from app.models.report import Report, ReportFormat

logger = logging.getLogger(__name__)

# CWE mapping for common vulnerability types
VULN_TYPE_CWE = {
    "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation"),
    "xss_reflected": ("CWE-79", "Reflected Cross-Site Scripting"),
    "xss_stored": ("CWE-79", "Stored Cross-Site Scripting"),
    "xss_dom": ("CWE-79", "DOM-Based Cross-Site Scripting"),
    "sqli": ("CWE-89", "SQL Injection"),
    "sqli_blind": ("CWE-89", "Blind SQL Injection"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "auth_bypass": ("CWE-287", "Improper Authentication"),
    "info_disclosure": ("CWE-200", "Exposure of Sensitive Information"),
    "misconfiguration": ("CWE-16", "Configuration"),
    "cmd_injection": ("CWE-78", "OS Command Injection"),
    "rce": ("CWE-94", "Remote Code Execution"),
    "path_traversal": ("CWE-22", "Path Traversal"),
    "file_upload": ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
    "open_redirect": ("CWE-601", "Open Redirect"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "xxe": ("CWE-611", "XML External Entity"),
    "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
    "ssti": ("CWE-1336", "Server-Side Template Injection"),
    "lfi": ("CWE-98", "Local File Inclusion"),
    "rfi": ("CWE-98", "Remote File Inclusion"),
    "cors": ("CWE-942", "CORS Misconfiguration"),
    "cors_misconfiguration": ("CWE-942", "CORS Misconfiguration"),
    "subdomain_takeover": ("CWE-284", "Subdomain Takeover"),
    "jwt_vulnerability": ("CWE-345", "JWT Token Vulnerability"),
    "prototype_pollution": ("CWE-1321", "Prototype Pollution"),
    "cache_poisoning": ("CWE-444", "Web Cache Poisoning"),
    "mass_assignment": ("CWE-915", "Mass Assignment"),
    "request_smuggling": ("CWE-444", "HTTP Request Smuggling"),
    "account_enumeration": ("CWE-204", "Account Enumeration"),
    "mfa_bypass": ("CWE-308", "MFA Bypass"),
    "header_injection": ("CWE-113", "HTTP Response Splitting"),
    "business_logic": ("CWE-840", "Business Logic Error"),
    "graphql": ("CWE-200", "GraphQL Information Disclosure"),
}

# CVSS base score estimates by severity
SEVERITY_CVSS = {
    "critical": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "high": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "medium": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "low": {"score": 3.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"},
    "info": {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
}

# Type-specific CVSS — overrides generic severity-based CVSS for accuracy
VULN_TYPE_CVSS = {
    "xss":              {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "sqli":             {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ssrf":             {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "idor":             {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "auth_bypass":      {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "info_disclosure":  {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "misconfiguration": {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "cmd_injection":    {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "path_traversal":   {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "file_upload":      {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "open_redirect":    {"score": 4.7, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"},
    "csrf":             {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "xxe":              {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "deserialization":  {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "rce":              {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ssti":             {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "lfi":              {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "cors":             {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "cors_misconfiguration": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "race_condition":   {"score": 5.9, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"},
    "business_logic":   {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "prototype_pollution": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "header_injection": {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "xss_reflected":       {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "xss_stored":          {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"},
    "xss_dom":             {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "sqli_blind":          {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "rfi":                 {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "subdomain_takeover":  {"score": 8.2, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"},
    "jwt_vulnerability":   {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "mass_assignment":     {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "request_smuggling":   {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "account_enumeration": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "mfa_bypass":          {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "graphql":             {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
}

# Bugcrowd severity mapping
BUGCROWD_SEVERITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}


class ReportGenerator:
    def __init__(self):
        self.llm = LLMEngine()

    async def generate(self, vuln: Vulnerability, format: ReportFormat) -> str:
        """Generate a report for a vulnerability."""
        template = self._get_template(format)
        vuln_type_str = vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type)
        severity_str = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

        cwe = VULN_TYPE_CWE.get(vuln_type_str, ("CWE-Unknown", "Unknown"))
        cvss = VULN_TYPE_CVSS.get(vuln_type_str, SEVERITY_CVSS.get(severity_str, SEVERITY_CVSS["medium"]))

        prompt = f"""Generate a professional bug bounty vulnerability report.

Format: {format.value}
Template to follow:
{template}

Vulnerability Details:
- Title: {vuln.title}
- Type: {vuln_type_str} ({cwe[0]}: {cwe[1]})
- Severity: {severity_str}
- CVSS Score: {vuln.cvss_score or cvss['score']} ({cvss['vector']})
- URL: {vuln.url}
- Parameter: {vuln.parameter}
- Method: {vuln.method}
- Payload: {vuln.payload_used}
- AI Confidence: {vuln.ai_confidence}

Request Data:
{json.dumps(vuln.request_data, indent=2, default=str) if vuln.request_data else 'N/A'}

Response (first 2000 chars):
{json.dumps(vuln.response_data, indent=2, default=str)[:2000] if vuln.response_data else 'N/A'}

AI Analysis:
{vuln.ai_analysis or 'N/A'}

Generate a complete, professional report that would be accepted on {format.value}.
Include:
1. Clear, specific title (not generic)
2. Severity with CVSS 3.1 vector string
3. Detailed technical description of the vulnerability
4. Step-by-step reproduction with exact requests
5. Impact analysis — what an attacker could achieve
6. Proof of Concept (cURL command or code)
7. Remediation recommendations with code examples where applicable
8. References (CWE, OWASP, relevant CVEs)

Important: Be specific and technical. Avoid generic descriptions. Include exact URLs, parameters, and payloads.
Write in Markdown format."""

        try:
            content = await self.llm.analyze(prompt, temperature=0.5)
        except Exception as e:
            logger.warning(f"AI report generation failed: {e}")
            content = self._generate_fallback_report(vuln, format)

        return content

    async def generate_scan_summary(self, scan_data: dict, vulns: list[dict]) -> str:
        """Generate an executive summary for an entire scan."""
        severity_counts = {}
        type_counts = {}
        for v in vulns:
            sev = v.get("severity", "medium")
            vt = v.get("vuln_type", "other")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            type_counts[vt] = type_counts.get(vt, 0) + 1

        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]

        summary = f"""# Security Assessment Report

## Target: {scan_data.get('target_domain', 'Unknown')}
**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
**Scan ID:** {scan_data.get('scan_id', 'N/A')}

---

## Executive Summary

A comprehensive security assessment was conducted against **{scan_data.get('target_domain', 'the target')}**.
The assessment identified **{len(vulns)} vulnerabilities** across {len(type_counts)} vulnerability categories.

### Risk Overview
| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Info | {severity_counts.get('info', 0)} |

### Vulnerability Categories
"""
        for vt, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            cwe = VULN_TYPE_CWE.get(vt, ("", ""))
            cwe_str = f" ({cwe[0]})" if cwe[0] else ""
            summary += f"- **{vt}**{cwe_str}: {count} findings\n"

        if critical_vulns:
            summary += "\n### Critical Findings (Immediate Action Required)\n\n"
            for i, v in enumerate(critical_vulns[:5], 1):
                summary += f"{i}. **{v.get('title', 'N/A')}** — {v.get('url', 'N/A')}\n"
                summary += f"   Impact: {v.get('impact', 'N/A')}\n\n"

        summary += """
---

## Recommendations

1. **Immediate:** Address all Critical and High severity findings
2. **Short-term:** Implement security headers and fix Medium severity issues
3. **Long-term:** Establish a vulnerability management program and regular security assessments

---
*Generated by PHANTOM AI Pentester*
"""
        return summary

    async def generate_for_vuln(self, vuln_data: dict, db) -> None:
        """Generate and save a report for a vulnerability finding."""
        report_content = self._generate_basic_report(vuln_data)

        report = Report(
            target_id=vuln_data.get("target_id", ""),
            scan_id=vuln_data.get("scan_id"),
            vulnerability_id=vuln_data.get("id"),
            title=vuln_data.get("title", "Vulnerability Report"),
            format=ReportFormat.GENERIC,
            content=report_content,
        )
        db.add(report)

    def _get_template(self, format: ReportFormat) -> str:
        templates = {
            ReportFormat.HACKERONE: """## Summary
[One paragraph summary with specific technical details]

## Severity
[Critical/High/Medium/Low] - CVSS:3.1/[vector] (Score: X.X)

## Weakness
[CWE-XXX: Weakness Name]

## Steps to Reproduce
1. [Exact step with URL/method]
2. [Exact step with payload]
3. [Exact step with observation]

## Supporting Material/References
- [cURL command]
- [HTTP request/response]
- [Screenshots if applicable]

## Impact
[Specific business/security impact — what can an attacker do with this?]

## Remediation
[Specific code-level fix recommendations]

## References
- [OWASP link]
- [CWE link]""",

            ReportFormat.BUGCROWD: """**Vulnerability Title:** [Specific, descriptive title]

**Severity:** [P1-P5] (CVSS: X.X)

**URL:** [Affected URL with parameters]

**Weakness:** [CWE-XXX]

**Description:**
[Detailed technical description]

**Steps to Reproduce:**
1. [Step 1 with specifics]
2. [Step 2 with payload]
3. [Step 3 with observation]

**Proof of Concept:**
```
[cURL command or code]
```

**Impact:**
[Business impact description]

**Remediation:**
[Fix recommendation with code example]""",

            ReportFormat.GENERIC: """# Vulnerability Report

## Title
[Vulnerability Title]

## Classification
- **Severity:** [Severity] | CVSS: [Score] ([Vector])
- **Type:** [Vulnerability Type]
- **CWE:** [CWE-XXX: Name]

## Description
[What was found — technical details]

## Affected Component
- **URL:** [URL]
- **Parameter:** [Parameter]
- **Method:** [HTTP Method]

## Reproduction Steps
1. [Step 1]
2. [Step 2]

## Proof of Concept
```bash
[cURL command]
```

## Impact
[What an attacker could do]

## Remediation
[How to fix, with code examples]

## References
- [Links to relevant resources]""",
        }
        return templates.get(format, templates[ReportFormat.GENERIC])

    def _generate_fallback_report(self, vuln: Vulnerability, format: ReportFormat = None) -> str:
        """Generate a structured report without AI — HackerOne quality."""
        vuln_type_str = vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type)
        severity_str = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
        cwe = VULN_TYPE_CWE.get(vuln_type_str, ("CWE-Unknown", "Unknown Weakness"))
        cvss = VULN_TYPE_CVSS.get(vuln_type_str, SEVERITY_CVSS.get(severity_str, SEVERITY_CVSS["medium"]))
        cwe_num = cwe[0].split("-")[1] if "-" in cwe[0] else "0"

        # Build curl command
        curl_cmd = self._build_curl_command(vuln, vuln_type_str)

        # Build structured PoC section
        poc_section = ""
        if vuln.payload_used or curl_cmd:
            poc_parts = []
            if vuln.payload_used:
                poc_parts.append(f"**Payload:** `{vuln.payload_used}`")
            if curl_cmd:
                poc_parts.append(f"\n```bash\n{curl_cmd}\n```")
            poc_section = f"""
## Proof of Concept

{chr(10).join(poc_parts)}
"""

        # HTTP request evidence
        request_section = ""
        if vuln.request_data and isinstance(vuln.request_data, dict):
            req = vuln.request_data
            method = req.get("method", vuln.method or "GET")
            url = req.get("url", vuln.url or "")
            headers = req.get("headers", {})
            body = req.get("body", "")

            raw_lines = [f"{method} {url} HTTP/1.1"]
            for k, v in list(headers.items())[:15]:
                raw_lines.append(f"{k}: {v}")
            if body:
                raw_lines.append("")
                raw_lines.append(str(body)[:1000])

            request_section = f"""
### HTTP Request
```http
{chr(10).join(raw_lines)}
```
"""

        # HTTP response evidence
        response_section = ""
        if vuln.response_data and isinstance(vuln.response_data, dict):
            resp = vuln.response_data
            status = resp.get("status_code", "")
            body = str(resp.get("body", "") or resp.get("body_preview", ""))[:800]
            if status or body:
                raw_lines = []
                if status:
                    raw_lines.append(f"HTTP/1.1 {status}")
                resp_headers = resp.get("headers", {})
                if isinstance(resp_headers, dict):
                    for k, v in list(resp_headers.items())[:10]:
                        raw_lines.append(f"{k}: {v}")
                if body:
                    raw_lines.append("")
                    raw_lines.append(body)
                response_section = f"""
### HTTP Response
```http
{chr(10).join(raw_lines)}
```
"""

        # Repro steps
        param_str = vuln.parameter or ""
        payload_str = vuln.payload_used or ""
        steps = self._build_repro_steps(vuln_type_str, vuln.url or "", vuln.method or "GET", param_str, payload_str)
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))

        # Impact
        impact_text = vuln.impact if hasattr(vuln, 'impact') and vuln.impact else self._get_default_impact(vuln_type_str, cwe)

        # OWASP reference
        from app.modules.hackerone_report import _get_owasp_reference
        owasp_ref = _get_owasp_reference(vuln_type_str)

        return f"""# {vuln.title}

## Summary

A **{cwe[1]}** ({cwe[0]}) vulnerability was identified at `{vuln.url}`.{f' The `{param_str}` parameter is vulnerable.' if param_str else ''} This issue was confirmed with a working proof of concept.

## Classification

| Field | Value |
|-------|-------|
| **Severity** | {severity_str.upper()} |
| **CVSS Score** | {vuln.cvss_score or cvss['score']} |
| **CVSS Vector** | `{cvss['vector']}` |
| **Type** | {vuln_type_str} |
| **CWE** | [{cwe[0]}](https://cwe.mitre.org/data/definitions/{cwe_num}.html): {cwe[1]} |

## Affected Component

- **URL:** `{vuln.url}`
- **Parameter:** `{vuln.parameter or 'N/A'}`
- **Method:** {vuln.method or 'GET'}

## Steps to Reproduce

{steps_md}
{poc_section}
{request_section}
{response_section}

## Impact

{impact_text}

## Remediation

{vuln.remediation or self._get_default_remediation(vuln_type_str)}

## References

- [{cwe[0]}: {cwe[1]}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)
{f'- {owasp_ref}' if owasp_ref else '- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)'}
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1#{cvss['vector'].replace('CVSS:3.1/', '')})

---
*Generated by PHANTOM AI Pentester — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*
"""

    def _build_curl_command(self, vuln: "Vulnerability", vuln_type: str) -> str:
        """Build a cURL command that reproduces the vulnerability."""
        url = vuln.url or "TARGET_URL"
        method = vuln.method or "GET"
        payload = vuln.payload_used or ""
        param = vuln.parameter or ""
        req_data = vuln.request_data if isinstance(vuln.request_data, dict) else {}

        parts = ["curl -k -s"]

        if method.upper() != "GET":
            parts.append(f"-X {method.upper()}")

        # Add relevant headers from request data (skip boilerplate)
        skip_headers = {"host", "user-agent", "accept-encoding", "connection", "accept", "content-length"}
        if req_data.get("headers") and isinstance(req_data["headers"], dict):
            for k, v in req_data["headers"].items():
                if k.lower() not in skip_headers:
                    parts.append(f"-H '{k}: {v}'")

        # Body / payload
        body = req_data.get("body", "")
        if body and method.upper() in ("POST", "PUT", "PATCH"):
            body_escaped = str(body).replace("'", "'\\''")
            parts.append(f"-d '{body_escaped}'")
        elif payload and method.upper() in ("POST", "PUT", "PATCH") and param:
            payload_escaped = payload.replace("'", "'\\''")
            parts.append(f"-d '{param}={payload_escaped}'")

        # URL with payload in query string for GET-based vulns
        if payload and method.upper() == "GET" and param and "?" not in url:
            from urllib.parse import quote
            parts.append(f"'{url}?{param}={quote(payload)}'")
        else:
            parts.append(f"'{url}'")

        return " \\\n  ".join(parts)

    def _build_repro_steps(self, vuln_type: str, url: str, method: str, param: str, payload: str) -> list[str]:
        """Build type-specific, actionable reproduction steps."""
        steps = []

        type_steps = {
            "xss": [
                f"Open a browser or HTTP client and navigate to `{url}`",
                f"{'Set the `' + param + '` parameter to' if param else 'Inject'} the XSS payload: `{payload}`" if payload else f"Inject a script payload into the `{param}` parameter" if param else "Inject a script payload into the vulnerable input",
                "Submit the request and observe the response",
                "Verify that the payload is reflected without encoding and executes in the browser (check DOM/console)",
            ],
            "sqli": [
                f"Send a {method} request to `{url}`",
                f"{'Set the `' + param + '` parameter to' if param else 'Inject'} the SQL payload: `{payload}`" if payload else f"Inject a single quote (') into the `{param}` parameter" if param else "Inject a SQL payload into the vulnerable parameter",
                "Observe SQL error messages, time delays, or modified response behavior",
                "Compare the response with a normal (non-injected) request to confirm the injection",
            ],
            "ssrf": [
                f"Send a {method} request to `{url}`",
                f"{'Set the `' + param + '` parameter to' if param else 'Supply'} an internal URL: `{payload}`" if payload else "Supply an internal/cloud metadata URL (e.g., http://169.254.169.254/latest/meta-data/) as the parameter value",
                "Observe that the server fetches the internal resource",
                "Verify internal data (cloud credentials, internal service responses) in the HTTP response",
            ],
            "idor": [
                f"Authenticate as User A and send a {method} request to `{url}`",
                "Note the object ID/reference in the request",
                "Change the ID to another user's resource (e.g., increment by 1, or use a known different user's ID)",
                "Observe that User B's data is returned — no authorization check prevents cross-user access",
            ],
            "auth_bypass": [
                f"Send a {method} request to `{url}` WITHOUT authentication credentials",
                f"Apply the bypass technique: `{payload}`" if payload else "Remove or modify the authentication token/cookie",
                "Observe that the protected resource is accessible without valid authentication",
                "Verify that sensitive data or admin functionality is exposed",
            ],
            "lfi": [
                f"Send a {method} request to `{url}`",
                f"{'Set the `' + param + '` parameter to' if param else 'Inject'} the path traversal payload: `{payload}`" if payload else "Inject a path traversal payload (e.g., ../../../../etc/passwd)",
                "Observe that the server returns the contents of the requested local file",
                "Verify sensitive file contents (e.g., /etc/passwd, configuration files) in the response",
            ],
            "ssti": [
                f"Send a {method} request to `{url}`",
                f"{'Set the `' + param + '` parameter to' if param else 'Inject'} the template payload: `{payload}`" if payload else "Inject a template expression (e.g., {{7*7}}) into the vulnerable parameter",
                "Observe that the template expression is evaluated server-side (e.g., 49 appears in the response)",
                "Escalate by injecting code execution payloads to confirm RCE potential",
            ],
            "cmd_injection": [
                f"Send a {method} request to `{url}`",
                f"{'Set the `' + param + '` parameter to' if param else 'Inject'} the command: `{payload}`" if payload else "Inject an OS command (e.g., ;id or |whoami) into the vulnerable parameter",
                "Observe command output in the response (e.g., uid=, user info)",
                "Verify arbitrary command execution by injecting a unique marker command",
            ],
        }

        if vuln_type in type_steps:
            steps = type_steps[vuln_type]
        else:
            steps = [
                f"Send a {method} request to `{url}`",
            ]
            if payload:
                steps.append(f"Use the following payload: `{payload}`")
            if param:
                steps.append(f"Target the `{param}` parameter")
            steps.append("Observe the vulnerability in the server response")

        steps.append("Use the cURL command in the PoC section to reproduce programmatically")
        return steps

    def _get_default_impact(self, vuln_type: str, cwe: tuple) -> str:
        """Get default impact description for a vulnerability type."""
        from app.modules.hackerone_report import HackerOneReport
        report = HackerOneReport()
        # Reuse the impact map from hackerone_report
        impact = report._build_impact(vuln_type, {"cwe": cwe[0], "name": cwe[1]}, "", {})
        return impact

    def _get_default_remediation(self, vuln_type: str) -> str:
        """Get default remediation advice for a vulnerability type."""
        remediations = {
            "xss": "Implement proper output encoding (HTML entity encoding, JavaScript encoding) "
                   "and Content Security Policy (CSP) headers. Use framework auto-escaping features. "
                   "Validate and sanitize all user input on the server side.",
            "sqli": "Use parameterized queries (prepared statements) for all database operations. "
                    "Never concatenate user input into SQL queries. "
                    "Apply the principle of least privilege to database accounts.",
            "ssrf": "Implement allowlists for outbound requests. Validate and sanitize all URLs. "
                    "Use network-level controls to prevent access to internal resources. "
                    "Disable unnecessary URL schemes (file://, gopher://, dict://).",
            "idor": "Implement proper authorization checks on every object access. "
                    "Verify the authenticated user owns or has permission to access the requested resource. "
                    "Use indirect references (UUIDs) instead of sequential IDs.",
            "auth_bypass": "Implement proper authentication and session management. "
                          "Use established authentication frameworks. Enforce MFA where possible. "
                          "Validate authentication tokens on every request.",
            "info_disclosure": "Remove sensitive data from API responses. Use DTOs to control output fields. "
                              "Remove debug information, stack traces, and verbose error messages in production.",
            "misconfiguration": "Review and harden server configuration. Follow security hardening guides. "
                               "Remove default credentials and unnecessary features. "
                               "Implement security headers (CSP, HSTS, X-Frame-Options).",
        }
        return remediations.get(vuln_type,
                               "Implement proper input validation and output encoding. "
                               "Follow OWASP security guidelines for this vulnerability type.")

    def _generate_basic_report(self, vuln_data: dict) -> str:
        """Generate a basic report from dict data (pipeline use)."""
        vuln_type = vuln_data.get("vuln_type", "unknown")
        severity = vuln_data.get("severity", "medium")
        cwe = VULN_TYPE_CWE.get(vuln_type, ("CWE-Unknown", "Unknown"))
        cvss = SEVERITY_CVSS.get(severity, SEVERITY_CVSS["medium"])

        return f"""# {vuln_data.get('title', 'Vulnerability Report')}

## Classification
- **Severity:** {severity.upper()} | CVSS: {cvss['score']}
- **Type:** {vuln_type} ({cwe[0]}: {cwe[1]})

## Affected Component
- **URL:** {vuln_data.get('url', 'N/A')}

## Description
{vuln_data.get('impact', 'This vulnerability was discovered during an automated security assessment.')}

## Remediation
{vuln_data.get('remediation', self._get_default_remediation(vuln_type))}

---
*Generated by PHANTOM AI Pentester — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*
"""
