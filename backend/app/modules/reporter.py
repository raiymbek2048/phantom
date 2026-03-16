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
    "sqli": ("CWE-89", "SQL Injection"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "auth_bypass": ("CWE-287", "Improper Authentication"),
    "info_disclosure": ("CWE-200", "Exposure of Sensitive Information"),
    "misconfiguration": ("CWE-16", "Configuration"),
    "cmd_injection": ("CWE-78", "OS Command Injection"),
    "path_traversal": ("CWE-22", "Path Traversal"),
    "file_upload": ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
    "open_redirect": ("CWE-601", "Open Redirect"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "xxe": ("CWE-611", "XML External Entity"),
    "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
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
        """Generate a structured report without AI."""
        vuln_type_str = vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type)
        severity_str = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
        cwe = VULN_TYPE_CWE.get(vuln_type_str, ("CWE-Unknown", "Unknown Weakness"))
        cvss = VULN_TYPE_CVSS.get(vuln_type_str, SEVERITY_CVSS.get(severity_str, SEVERITY_CVSS["medium"]))

        payload_section = ""
        if vuln.payload_used:
            payload_section = f"""
## Proof of Concept

**Payload:** `{vuln.payload_used}`

```bash
curl -k -X {vuln.method or 'GET'} '{vuln.url}' \\
  -H 'Cookie: YOUR_SESSION' \\
  {f"-d '{vuln.payload_used}'" if vuln.method in ('POST', 'PUT', 'PATCH') else ''}
```
"""

        request_section = ""
        if vuln.request_data:
            request_section = f"""
## HTTP Request Details
```json
{json.dumps(vuln.request_data, indent=2, default=str)[:1500]}
```
"""

        response_section = ""
        if vuln.response_data:
            resp_preview = json.dumps(vuln.response_data, indent=2, default=str)[:1000]
            response_section = f"""
## Response Evidence
```json
{resp_preview}
```
"""

        return f"""# {vuln.title}

## Classification
- **Severity:** {severity_str.upper()}
- **CVSS:** {vuln.cvss_score or cvss['score']} ({cvss['vector']})
- **Type:** {vuln_type_str}
- **{cwe[0]}:** {cwe[1]}

## Affected Component
- **URL:** {vuln.url}
- **Parameter:** {vuln.parameter or 'N/A'}
- **Method:** {vuln.method or 'GET'}

## Description
A **{vuln_type_str}** vulnerability was discovered at `{vuln.url}`. {vuln.impact or f'This vulnerability allows an attacker to exploit {cwe[1].lower()} in the application.'}

## Steps to Reproduce
1. Navigate to: `{vuln.url}`
2. {"Inject the payload: `" + vuln.payload_used + "`" if vuln.payload_used else "Observe the vulnerable response"}
3. Verify the vulnerability in the server response
{payload_section}
{request_section}
{response_section}

## Impact
{vuln.impact or f'An attacker could exploit this {vuln_type_str} vulnerability to compromise the application security. Depending on the context, this could lead to data theft, unauthorized access, or service disruption.'}

## Remediation
{vuln.remediation or self._get_default_remediation(vuln_type_str)}

## References
- [{cwe[0]}: {cwe[1]}](https://cwe.mitre.org/data/definitions/{cwe[0].split("-")[1]}.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---
*Generated by PHANTOM AI Pentester — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*
"""

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
