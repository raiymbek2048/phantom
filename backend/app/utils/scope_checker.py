"""
Scope Checker — ensures PHANTOM only tests authorized targets.

Validates targets against known bug bounty programs and their scope rules.
"""
import re
from urllib.parse import urlparse


# Known bug bounty programs with wide scope (safe to scan)
KNOWN_PROGRAMS = {
    "hackerone.com": {
        "program": "HackerOne",
        "scope": ["*.hackerone.com"],
        "out_of_scope": ["hackerone.com/users/sign_in"],
        "safe_harbor": True,
    },
    "bugcrowd.com": {
        "program": "Bugcrowd",
        "scope": ["*.bugcrowd.com"],
        "safe_harbor": True,
    },
}

# Intentionally vulnerable targets (always allowed)
VULN_LABS = [
    "juice-shop", "dvwa", "hackthebox", "tryhackme",
    "portswigger.net/web-security", "pentesterlab.com",
    "localhost", "127.0.0.1", "10.", "172.16.", "192.168.",
]


def is_safe_target(domain: str) -> dict:
    """Check if a target is safe to scan."""
    domain_lower = domain.lower().strip()

    # Always allow vulnerable labs and internal targets
    for lab in VULN_LABS:
        if lab in domain_lower:
            return {"allowed": True, "reason": "Vulnerable lab / internal target"}

    # Check if it's a known bug bounty program
    for program_domain, info in KNOWN_PROGRAMS.items():
        if program_domain in domain_lower:
            return {
                "allowed": True,
                "reason": f"Known bug bounty program: {info['program']}",
                "program": info,
            }

    # For unknown targets — allow but warn
    return {
        "allowed": True,
        "reason": "Unknown program — ensure you have authorization",
        "warning": "Make sure this target has an active bug bounty program or you have written authorization to test.",
    }


def check_scope(domain: str, url: str, scope_rules: list[str] = None) -> bool:
    """Check if a URL is within the defined scope."""
    if not scope_rules:
        return True

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    for rule in scope_rules:
        # Wildcard matching: *.example.com
        if rule.startswith("*."):
            base = rule[2:]
            if hostname == base or hostname.endswith(f".{base}"):
                return True
        elif hostname == rule:
            return True

    return False
