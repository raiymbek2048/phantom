"""
Attack Chain Detection Module

Identifies and reports multi-step attack chains:
1. SSRF → Internal Service → RCE
2. SQLi → File Read → Source Code → RCE
3. XSS → CSRF → Account Takeover
4. IDOR → PII Leak → Account Takeover
5. Open Redirect → OAuth Token Theft
6. LFI → Log Poisoning → RCE
7. XXE → SSRF → Cloud Metadata → IAM Credentials
"""
import logging

logger = logging.getLogger(__name__)

# Chain definitions: (vuln_type_sequence, chain_name, severity_upgrade, impact)
CHAIN_PATTERNS = [
    {
        "id": "ssrf_to_rce",
        "requires": [{"vuln_type": "ssrf"}],
        "indicators": ["metadata", "169.254.169.254", "internal", "redis", "docker", "elasticsearch"],
        "chain_name": "SSRF → Internal Service Access → Potential RCE",
        "severity": "critical",
        "impact": "SSRF can reach internal services. If Redis/Docker API/Elasticsearch is accessible, "
                 "attacker can achieve Remote Code Execution via SSRF chaining.",
        "next_steps": [
            "Test Redis SLAVEOF/CONFIG SET for RCE",
            "Test Docker API /containers/create for container escape",
            "Test Elasticsearch _search for data exfiltration",
        ],
    },
    {
        "id": "ssrf_to_cloud",
        "requires": [{"vuln_type": "ssrf"}],
        "indicators": ["aws", "iam", "credentials", "access_key", "gcp", "azure", "metadata"],
        "chain_name": "SSRF → Cloud Metadata → IAM Credential Theft",
        "severity": "critical",
        "impact": "SSRF accesses cloud metadata endpoint and retrieves IAM credentials. "
                 "Attacker can use stolen credentials for full cloud account takeover.",
        "next_steps": [
            "Use stolen credentials to enumerate S3 buckets",
            "Check IAM role permissions for privilege escalation",
            "Access other cloud services (EC2, Lambda, RDS)",
        ],
    },
    {
        "id": "sqli_to_rce",
        "requires": [{"vuln_type": "sqli"}],
        "indicators": ["file_read", "load_file", "into outfile", "credentials", "password"],
        "chain_name": "SQLi → File Read → Source Code/Credentials → RCE",
        "severity": "critical",
        "impact": "SQL injection allows reading server files. Attacker can extract source code, "
                 "database credentials, and configuration files. Combined with file write "
                 "(INTO OUTFILE), this leads to webshell upload and RCE.",
        "next_steps": [
            "Read /etc/passwd for user enumeration",
            "Read application config for DB/API credentials",
            "Attempt INTO OUTFILE for webshell in web root",
        ],
    },
    {
        "id": "xss_to_takeover",
        "requires": [{"vuln_type": "xss", "alt_types": ["xss_reflected", "xss_stored", "xss_dom"]}],
        "indicators": [],  # XSS + missing CSRF = chain
        "chain_name": "XSS → Session Theft / CSRF → Account Takeover",
        "severity": "high",
        "impact": "XSS allows stealing session cookies (if HttpOnly missing) or performing "
                 "CSRF attacks on behalf of the victim (password change, email change). "
                 "Combined, this enables full account takeover.",
        "chain_with": ["csrf", "misconfig"],
        "next_steps": [
            "Craft XSS payload that changes victim's email/password",
            "Steal session token via document.cookie",
            "Exfiltrate sensitive data from authenticated pages",
        ],
    },
    {
        "id": "idor_to_leak",
        "requires": [{"vuln_type": "idor"}],
        "indicators": ["pii", "email", "password", "ssn", "credit", "phone"],
        "chain_name": "IDOR → Mass PII Exfiltration → Identity Theft",
        "severity": "critical",
        "impact": "IDOR allows accessing other users' data by iterating IDs. "
                 "Attacker can automate mass data extraction of PII, credentials, or financial data.",
        "next_steps": [
            "Enumerate all user IDs to extract complete database",
            "Use leaked credentials for credential stuffing",
            "Use PII for social engineering attacks",
        ],
    },
    {
        "id": "redirect_to_oauth",
        "requires": [{"vuln_type": "open_redirect"}],
        "indicators": ["oauth", "token", "code", "redirect_uri", "callback"],
        "chain_name": "Open Redirect → OAuth Token Theft",
        "severity": "high",
        "impact": "Open redirect in OAuth callback allows stealing authorization codes/tokens. "
                 "Attacker redirects OAuth flow to their server, capturing the victim's token.",
        "next_steps": [
            "Craft OAuth flow with redirect_uri pointing to open redirect",
            "Capture authorization code/token on attacker server",
        ],
    },
    {
        "id": "lfi_to_rce",
        "requires": [{"vuln_type": "lfi", "alt_types": ["path_traversal"]}],
        "indicators": ["log", "proc", "environ", "passwd"],
        "chain_name": "LFI → Log Poisoning → RCE",
        "severity": "critical",
        "impact": "Local File Inclusion can read server logs. By injecting PHP/code into "
                 "User-Agent or other logged headers, then including the log file, "
                 "attacker achieves Remote Code Execution.",
        "next_steps": [
            "Inject PHP code via User-Agent header",
            "Include /var/log/apache2/access.log via LFI",
            "Include /proc/self/environ for environment variable disclosure",
        ],
    },
    {
        "id": "xxe_to_ssrf",
        "requires": [{"vuln_type": "xxe"}],
        "indicators": ["file", "http", "ftp", "gopher"],
        "chain_name": "XXE → SSRF → Internal Network Access",
        "severity": "high",
        "impact": "XXE entity resolution allows making HTTP requests to internal services (SSRF). "
                 "Combined with cloud metadata access, can lead to full infrastructure compromise.",
        "next_steps": [
            "Use XXE to access http://169.254.169.254/latest/meta-data/",
            "Scan internal network via XXE-based SSRF",
            "Exfiltrate files via out-of-band XXE",
        ],
    },
    {
        "id": "deser_to_rce",
        "requires": [{"vuln_type": "rce"}],
        "indicators": ["deserializ", "pickle", "unserialize", "viewstate", "java serial", "gadget"],
        "chain_name": "Deserialization → Remote Code Execution",
        "severity": "critical",
        "impact": "Insecure deserialization allows arbitrary code execution on the server. "
                 "Attacker can establish reverse shell, read/write files, pivot to internal network.",
        "next_steps": [
            "Craft gadget chain for reverse shell",
            "Enumerate internal network from compromised server",
            "Extract credentials and secrets from environment",
        ],
    },
]


class ChainAttackModule:
    """Analyzes discovered vulnerabilities for attack chain potential."""

    def analyze(self, vulnerabilities: list[dict]) -> list[dict]:
        """
        Given a list of confirmed vulnerabilities, identify attack chains.
        Returns chain findings to add to the report.
        """
        chains = []
        vuln_types = set()
        vuln_details = {}

        for vuln in vulnerabilities:
            vtype = vuln.get("vuln_type", "")
            vuln_types.add(vtype)
            vuln_details.setdefault(vtype, []).append(vuln)

        for pattern in CHAIN_PATTERNS:
            # Check if required vuln types are present
            matched = False
            for req in pattern["requires"]:
                req_type = req["vuln_type"]
                alt_types = req.get("alt_types", [])
                all_types = [req_type] + alt_types
                if any(t in vuln_types for t in all_types):
                    matched = True
                    break

            if not matched:
                continue

            # Check indicators in vulnerability details
            all_vuln_text = " ".join(
                str(v) for vlist in vuln_details.values() for v in vlist
            ).lower()

            indicator_match = (
                not pattern["indicators"]  # No indicators needed
                or any(ind in all_vuln_text for ind in pattern["indicators"])
            )

            # Check chain_with (presence of secondary vuln type)
            chain_with = pattern.get("chain_with", [])
            chain_match = not chain_with or any(c in vuln_types for c in chain_with)

            if indicator_match or chain_match:
                # Get the triggering vulnerabilities
                trigger_vulns = []
                for req in pattern["requires"]:
                    all_types = [req["vuln_type"]] + req.get("alt_types", [])
                    for t in all_types:
                        trigger_vulns.extend(vuln_details.get(t, []))

                chain_finding = {
                    "title": f"Attack Chain: {pattern['chain_name']}",
                    "severity": pattern["severity"],
                    "vuln_type": "misconfig",
                    "chain_id": pattern["id"],
                    "impact": pattern["impact"],
                    "next_steps": pattern["next_steps"],
                    "linked_vulns": [
                        {"title": v.get("title", ""), "url": v.get("url", "")}
                        for v in trigger_vulns[:5]
                    ],
                    "url": trigger_vulns[0].get("url", "") if trigger_vulns else "",
                    "remediation": "Fix the root cause vulnerability to break the attack chain. "
                                  "Implement defense-in-depth with multiple security layers.",
                }
                chains.append(chain_finding)

        return chains
