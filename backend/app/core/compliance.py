"""
Compliance Mapping — Maps vulnerabilities to security standards.

Standards supported:
1. OWASP Top 10 (2021)
2. CWE (Common Weakness Enumeration)
3. PCI DSS v4.0
4. NIST SP 800-53
5. SANS Top 25
"""

# OWASP Top 10 2021
OWASP_TOP_10 = {
    "A01": {"name": "Broken Access Control", "description": "Failures in access control enforcement"},
    "A02": {"name": "Cryptographic Failures", "description": "Failures related to cryptography"},
    "A03": {"name": "Injection", "description": "SQL, NoSQL, OS, LDAP injection"},
    "A04": {"name": "Insecure Design", "description": "Design and architectural flaws"},
    "A05": {"name": "Security Misconfiguration", "description": "Missing or incorrect security configuration"},
    "A06": {"name": "Vulnerable Components", "description": "Using components with known vulnerabilities"},
    "A07": {"name": "Auth Failures", "description": "Authentication and session management flaws"},
    "A08": {"name": "Software & Data Integrity", "description": "Integrity failures in software/data"},
    "A09": {"name": "Logging & Monitoring", "description": "Insufficient logging and monitoring"},
    "A10": {"name": "SSRF", "description": "Server-Side Request Forgery"},
}

# VulnType → OWASP mapping
VULN_TO_OWASP = {
    "xss_reflected": ["A03"],
    "xss_stored": ["A03"],
    "xss_dom": ["A03"],
    "sqli": ["A03"],
    "sqli_blind": ["A03"],
    "cmd_injection": ["A03"],
    "ssti": ["A03"],
    "xxe": ["A03"],
    "ssrf": ["A10"],
    "idor": ["A01"],
    "auth_bypass": ["A01", "A07"],
    "privilege_escalation": ["A01"],
    "csrf": ["A01"],
    "lfi": ["A01", "A03"],
    "rfi": ["A01", "A03"],
    "path_traversal": ["A01"],
    "open_redirect": ["A01"],
    "rce": ["A03"],
    "cors_misconfiguration": ["A05"],
    "misconfiguration": ["A05"],
    "info_disclosure": ["A05"],
    "jwt_vuln": ["A07"],
    "deserialization": ["A08"],
    "subdomain_takeover": ["A05"],
    "race_condition": ["A04"],
    "business_logic": ["A04"],
    "file_upload": ["A04", "A03"],
    "other": ["A05"],
}

# VulnType → CWE mapping
VULN_TO_CWE = {
    "xss_reflected": [{"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation"}],
    "xss_stored": [{"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation"}],
    "xss_dom": [{"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation"}],
    "sqli": [{"id": "CWE-89", "name": "SQL Injection"}],
    "sqli_blind": [{"id": "CWE-89", "name": "SQL Injection"}, {"id": "CWE-209", "name": "Information Exposure Through Error Message"}],
    "cmd_injection": [{"id": "CWE-78", "name": "OS Command Injection"}],
    "ssti": [{"id": "CWE-1336", "name": "Server-Side Template Injection"}, {"id": "CWE-94", "name": "Code Injection"}],
    "ssrf": [{"id": "CWE-918", "name": "Server-Side Request Forgery"}],
    "xxe": [{"id": "CWE-611", "name": "Improper Restriction of XML External Entity Reference"}],
    "idor": [{"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"}, {"id": "CWE-862", "name": "Missing Authorization"}],
    "csrf": [{"id": "CWE-352", "name": "Cross-Site Request Forgery"}],
    "lfi": [{"id": "CWE-22", "name": "Path Traversal"}, {"id": "CWE-98", "name": "PHP Remote File Inclusion"}],
    "rfi": [{"id": "CWE-98", "name": "PHP Remote File Inclusion"}],
    "path_traversal": [{"id": "CWE-22", "name": "Path Traversal"}],
    "rce": [{"id": "CWE-94", "name": "Code Injection"}],
    "open_redirect": [{"id": "CWE-601", "name": "URL Redirection to Untrusted Site"}],
    "auth_bypass": [{"id": "CWE-287", "name": "Improper Authentication"}],
    "privilege_escalation": [{"id": "CWE-269", "name": "Improper Privilege Management"}],
    "cors_misconfiguration": [{"id": "CWE-942", "name": "Permissive Cross-domain Policy with Untrusted Domains"}],
    "misconfiguration": [{"id": "CWE-16", "name": "Configuration"}],
    "info_disclosure": [{"id": "CWE-200", "name": "Exposure of Sensitive Information"}],
    "jwt_vuln": [{"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature"}],
    "deserialization": [{"id": "CWE-502", "name": "Deserialization of Untrusted Data"}],
    "subdomain_takeover": [{"id": "CWE-284", "name": "Improper Access Control"}],
    "race_condition": [{"id": "CWE-362", "name": "Race Condition"}],
    "business_logic": [{"id": "CWE-840", "name": "Business Logic Error"}],
    "file_upload": [{"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type"}],
    "other": [{"id": "CWE-693", "name": "Protection Mechanism Failure"}],
}

# VulnType → PCI DSS v4.0 requirements
VULN_TO_PCI_DSS = {
    "xss_reflected": ["6.2.4", "6.5.7"],
    "xss_stored": ["6.2.4", "6.5.7"],
    "xss_dom": ["6.2.4", "6.5.7"],
    "sqli": ["6.2.4", "6.5.1"],
    "sqli_blind": ["6.2.4", "6.5.1"],
    "cmd_injection": ["6.2.4", "6.5.1"],
    "ssti": ["6.2.4"],
    "ssrf": ["6.2.4"],
    "xxe": ["6.2.4"],
    "idor": ["6.2.4", "7.2.1"],
    "csrf": ["6.2.4", "6.5.9"],
    "lfi": ["6.2.4", "6.5.1"],
    "rfi": ["6.2.4", "6.5.1"],
    "path_traversal": ["6.2.4"],
    "rce": ["6.2.4", "6.5.1"],
    "open_redirect": ["6.2.4"],
    "auth_bypass": ["6.2.4", "8.3.1"],
    "privilege_escalation": ["7.2.1", "7.2.2"],
    "cors_misconfiguration": ["6.2.4", "6.4.1"],
    "misconfiguration": ["2.2.1", "6.4.1"],
    "info_disclosure": ["3.4.1", "6.5.3"],
    "jwt_vuln": ["6.2.4", "8.3.1"],
    "deserialization": ["6.2.4"],
    "subdomain_takeover": ["6.4.1"],
    "race_condition": ["6.2.4"],
    "business_logic": ["6.2.4"],
    "file_upload": ["6.2.4"],
    "other": ["6.2.4"],
}

PCI_DSS_DESCRIPTIONS = {
    "2.2.1": "System configuration standards",
    "3.4.1": "Render PAN unreadable anywhere it is stored",
    "6.2.4": "Software engineering techniques to prevent common vulnerabilities",
    "6.4.1": "Public-facing web applications are protected",
    "6.5.1": "Injection flaws",
    "6.5.3": "Insecure cryptographic storage",
    "6.5.7": "Cross-site scripting (XSS)",
    "6.5.9": "Cross-site request forgery (CSRF)",
    "7.2.1": "Access control system is in place",
    "7.2.2": "Access is assigned based on job function",
    "8.3.1": "Authentication mechanisms are strong",
}

# NIST SP 800-53 controls
VULN_TO_NIST = {
    "xss_reflected": ["SI-10", "SC-18"],
    "xss_stored": ["SI-10", "SC-18"],
    "xss_dom": ["SI-10", "SC-18"],
    "sqli": ["SI-10", "SI-16"],
    "sqli_blind": ["SI-10", "SI-16"],
    "cmd_injection": ["SI-10", "SI-3"],
    "ssrf": ["SC-7", "SI-10"],
    "idor": ["AC-3", "AC-6"],
    "csrf": ["SC-23"],
    "auth_bypass": ["IA-2", "IA-5"],
    "misconfiguration": ["CM-6", "CM-7"],
    "info_disclosure": ["SC-28", "AC-3"],
    "deserialization": ["SI-10", "SI-16"],
}


def get_compliance_for_vuln(vuln_type: str) -> dict:
    """Get all compliance mappings for a vulnerability type."""
    vt = vuln_type if isinstance(vuln_type, str) else vuln_type.value

    owasp_ids = VULN_TO_OWASP.get(vt, ["A05"])
    owasp = [{"id": oid, **OWASP_TOP_10.get(oid, {})} for oid in owasp_ids]

    cwe = VULN_TO_CWE.get(vt, [{"id": "CWE-693", "name": "Protection Mechanism Failure"}])

    pci_reqs = VULN_TO_PCI_DSS.get(vt, ["6.2.4"])
    pci_dss = [{"requirement": r, "description": PCI_DSS_DESCRIPTIONS.get(r, "")} for r in pci_reqs]

    nist_ids = VULN_TO_NIST.get(vt, ["SI-10"])
    nist = [{"control": n} for n in nist_ids]

    return {
        "owasp_top_10": owasp,
        "cwe": cwe,
        "pci_dss": pci_dss,
        "nist_800_53": nist,
    }


def get_compliance_summary(vulns: list[dict]) -> dict:
    """Generate compliance summary for a set of vulnerabilities."""
    owasp_counts = {}
    cwe_counts = {}
    pci_counts = {}

    for v in vulns:
        vt = v.get("vuln_type", "other")
        if hasattr(vt, "value"):
            vt = vt.value

        # OWASP
        for oid in VULN_TO_OWASP.get(vt, ["A05"]):
            info = OWASP_TOP_10.get(oid, {})
            key = f"{oid}: {info.get('name', '')}"
            if key not in owasp_counts:
                owasp_counts[key] = {"id": oid, "name": info.get("name", ""), "count": 0, "vulns": []}
            owasp_counts[key]["count"] += 1
            owasp_counts[key]["vulns"].append(v.get("title", vt))

        # CWE
        for cwe_item in VULN_TO_CWE.get(vt, []):
            cwe_id = cwe_item["id"]
            if cwe_id not in cwe_counts:
                cwe_counts[cwe_id] = {"id": cwe_id, "name": cwe_item["name"], "count": 0}
            cwe_counts[cwe_id]["count"] += 1

        # PCI DSS
        for req in VULN_TO_PCI_DSS.get(vt, []):
            if req not in pci_counts:
                pci_counts[req] = {
                    "requirement": req,
                    "description": PCI_DSS_DESCRIPTIONS.get(req, ""),
                    "count": 0, "status": "fail",
                }
            pci_counts[req]["count"] += 1

    return {
        "owasp_top_10": sorted(owasp_counts.values(), key=lambda x: x["count"], reverse=True),
        "cwe_top": sorted(cwe_counts.values(), key=lambda x: x["count"], reverse=True)[:15],
        "pci_dss_failures": sorted(pci_counts.values(), key=lambda x: x["count"], reverse=True),
        "pci_dss_compliant": len(pci_counts) == 0,
        "total_standards_violated": len(owasp_counts) + len(pci_counts),
    }
