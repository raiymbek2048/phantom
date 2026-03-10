"""
Bug Bounty Out-of-Scope Filter

Filters findings that are explicitly excluded by bug bounty programs.
Each program has different rules — this implements common exclusions.
"""
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Common bounty OOS vuln types / patterns
DEFAULT_OOS_VULN_TYPES = {
    "info_disclosure",  # Software version / banner identification
    "misconfiguration",  # Missing best practices (CSP, cookies, etc.)
}

# URL patterns that indicate login/auth endpoints
LOGIN_PATTERNS = [
    "/login", "/signin", "/auth", "/oauth", "/session/login",
    "/register", "/signup", "/password", "/forgot",
]


class BountyFilter:
    """Filters out-of-scope findings for bug bounty programs."""

    def __init__(self, rules: dict):
        """
        rules example:
        {
            "program": "superbet",
            "oos_vuln_types": ["info_disclosure", "misconfiguration"],
            "oos_patterns": [
                "clickjacking", "missing httponly", "missing secure flag",
                "missing csp", "ssl/tls", "cors without poc",
                "open redirect", "self xss", "csrf unauth",
                "version disclosure", "banner", "descriptive error",
                "email enumeration", "username enumeration",
                "tabnabbing", "csv injection",
            ],
            "oos_url_patterns": ["/login", "/signin", "/auth", "/session/login"],
            "skip_login_endpoints": True,
            "skip_third_party": True,
            "require_impact": ["open_redirect", "cors_misconfiguration"],
        }
        """
        self.rules = rules
        self.oos_vuln_types = set(rules.get("oos_vuln_types", []))
        self.oos_patterns = [p.lower() for p in rules.get("oos_patterns", [])]
        self.oos_url_patterns = rules.get("oos_url_patterns", LOGIN_PATTERNS)
        self.skip_login = rules.get("skip_login_endpoints", False)
        self.skip_third_party = rules.get("skip_third_party", False)
        self.in_scope_domains = rules.get("in_scope_domains", [])
        self.require_impact = set(rules.get("require_impact", []))

    def is_in_scope(self, vuln: dict) -> bool:
        """Check if a vulnerability finding is in-scope for the bounty program."""
        vuln_type = vuln.get("vuln_type", "")
        if hasattr(vuln_type, "value"):
            vuln_type = vuln_type.value

        title = (vuln.get("title", "") or "").lower()
        description = (vuln.get("description", "") or "").lower()
        url = vuln.get("url", "")
        combined = f"{title} {description}"

        # 1. Skip explicitly excluded vuln types
        if vuln_type in self.oos_vuln_types:
            logger.info(f"Bounty filter: OOS vuln type '{vuln_type}' for {url}")
            return False

        # 2. Skip login/auth endpoints if configured
        if self.skip_login and url:
            url_path = urlparse(url).path.lower()
            if any(pat in url_path for pat in self.oos_url_patterns):
                logger.info(f"Bounty filter: OOS login endpoint {url}")
                return False

        # 3. Skip findings matching OOS patterns in title/description
        for pattern in self.oos_patterns:
            if pattern in combined:
                logger.info(f"Bounty filter: OOS pattern '{pattern}' in {title[:50]}")
                return False

        # 4. Skip third-party findings
        if self.skip_third_party and url and self.in_scope_domains:
            url_host = urlparse(url).hostname or ""
            if not any(url_host.endswith(d.lstrip("*.")) for d in self.in_scope_domains):
                logger.info(f"Bounty filter: OOS third-party domain {url_host}")
                return False

        # 5. Require additional impact for certain types
        if vuln_type in self.require_impact:
            severity = vuln.get("severity", "")
            if hasattr(severity, "value"):
                severity = severity.value
            if severity in ("low", "info"):
                logger.info(f"Bounty filter: {vuln_type} requires impact, severity={severity}")
                return False

        return True

    def filter_findings(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Filter a list of findings. Returns (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for f in findings:
            if self.is_in_scope(f):
                in_scope.append(f)
            else:
                out_of_scope.append(f)

        if out_of_scope:
            logger.info(f"Bounty filter: removed {len(out_of_scope)} OOS findings, kept {len(in_scope)}")

        return in_scope, out_of_scope


# Pre-configured bounty rules for known programs
BOUNTY_PRESETS = {
    "superbet": {
        "program": "superbet",
        "oos_vuln_types": [],  # Don't auto-exclude types, use patterns instead
        "oos_patterns": [
            "clickjacking", "missing httponly", "missing secure flag",
            "missing csp", "content security policy", "ssl/tls configuration",
            "cors without", "open redirect", "self xss", "self-xss",
            "csrf on unauthenticated", "csrf unauth",
            "version disclosure", "banner identification", "descriptive error",
            "stack trace", "server error", "email enumeration",
            "username enumeration", "tabnabbing", "csv injection",
            "missing spf", "missing dkim", "missing dmarc",
            "s3 bucket", "rate limiting", "brute force",
            "content spoofing", "text injection",
        ],
        "oos_url_patterns": [
            "/login", "/signin", "/auth", "/oauth", "/session/login",
            "/register", "/signup", "/password", "/forgot",
            "/legacy-web", "/ssbt-api/",
        ],
        "skip_login_endpoints": True,
        "skip_third_party": True,
        "in_scope_domains": [
            "*.superbet.ro", "*.superbet.rs", "*.superbet.com", "*.superbet.pl",
            "*.spinaway.com", "*.luckydays.com", "*.luckydays.ca",
            "*.napoleoncasino.be", "*.napoleondice.be", "*.napoleongames.be",
            "*.napoleonsports.be", "*.happening.dev", "superbet.bet.br",
        ],
        "require_impact": ["open_redirect", "cors_misconfiguration"],
    }
}


def get_bounty_filter(rules: dict) -> BountyFilter:
    """Get a bounty filter, optionally loading a preset."""
    preset = rules.get("preset")
    if preset and preset in BOUNTY_PRESETS:
        merged = {**BOUNTY_PRESETS[preset], **rules}
        return BountyFilter(merged)
    return BountyFilter(rules)
