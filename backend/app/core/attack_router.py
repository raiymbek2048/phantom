"""
PHANTOM Adaptive Attack Router

Analyzes discoveries from recon/portscan/fingerprint/endpoint phases and builds
a prioritized attack plan using pure rule-based logic (no LLM needed).

Downstream phases (vuln_scan, exploit, service_attack, auth_attack, payload_gen,
waf, stress_test) read context["attack_plan"] to skip irrelevant work and
prioritize the most promising vectors.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger("phantom.attack_router")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AttackAction:
    action: str
    priority: int
    reason: str
    category: str = "general"           # service | auth | api | cms | file | network | resilience
    target: Optional[str] = None        # host:port or URL when relevant
    params: dict = field(default_factory=dict)  # extra hints for the module

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Port-to-attack mapping
# ---------------------------------------------------------------------------

_PORT_RULES: list[tuple[int, str, str, str]] = [
    # (port, action, category, reason)
    (21,    "ftp_attack",        "service",  "FTP service detected on port 21"),
    (22,    "ssh_brute",         "service",  "SSH service detected on port 22"),
    (23,    "telnet_attack",     "service",  "Telnet service detected on port 23"),
    (25,    "smtp_attack",       "service",  "SMTP service detected on port 25"),
    (110,   "pop3_attack",       "service",  "POP3 service detected on port 110"),
    (143,   "imap_attack",       "service",  "IMAP service detected on port 143"),
    (445,   "smb_attack",        "service",  "SMB service detected on port 445"),
    (1433,  "mssql_attack",      "service",  "MSSQL database detected on port 1433"),
    (3306,  "mysql_attack",      "service",  "MySQL database detected on port 3306"),
    (5432,  "postgres_attack",   "service",  "PostgreSQL database detected on port 5432"),
    (6379,  "redis_attack",      "service",  "Redis detected on port 6379 — likely unauthenticated"),
    (9200,  "elasticsearch_attack", "service", "Elasticsearch detected on port 9200"),
    (11211, "memcached_attack",  "service",  "Memcached detected on port 11211"),
    (27017, "mongodb_attack",    "service",  "MongoDB detected on port 27017 — may allow unauthenticated access"),
]

_PORT_MAP = {port: (action, category, reason) for port, action, category, reason in _PORT_RULES}

# Sensitive files that should be flagged as high priority
_HIGH_PRIORITY_FILES = {".git", ".env", ".htaccess", "wp-config.php", "config.php",
                        ".svn", ".DS_Store", "web.config", "database.yml",
                        "id_rsa", ".ssh", "shadow", "passwd"}


class AttackRouter:
    """Pure rule-based engine that converts scan discoveries into a prioritized
    attack plan stored in ``context["attack_plan"]``."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, context: dict) -> list[dict]:
        """Analyze scan context and return prioritized attack plan.

        Each entry is a dict with keys:
            action   — short identifier consumed by attack modules
            priority — 1 = highest
            reason   — human-readable explanation
            category — service | auth | api | cms | file | network | resilience
            target   — optional host:port or URL
            params   — dict of extra hints
        """
        actions: list[AttackAction] = []

        # --- 1. Port-based rules ---
        self._analyze_ports(context, actions)

        # --- 2. Technology / CMS detection ---
        self._analyze_technologies(context, actions)

        # --- 3. Endpoint analysis ---
        self._analyze_endpoints(context, actions)

        # --- 4. Sensitive files ---
        self._analyze_sensitive_files(context, actions)

        # --- 5. WAF posture ---
        self._analyze_waf(context, actions)

        # --- 6. Rate-limit / 429 detection ---
        self._analyze_rate_limits(context, actions)

        # --- 7. Risky services from portscan module ---
        self._analyze_risky_services(context, actions)

        # Deduplicate by action+target, keep highest priority
        actions = self._deduplicate(actions)

        # Sort by priority ascending (1 = first)
        actions.sort(key=lambda a: a.priority)

        # Re-number so priorities are contiguous 1..N
        for idx, act in enumerate(actions, start=1):
            act.priority = idx

        plan = [a.to_dict() for a in actions]

        # Persist into context so downstream phases can read it
        context["attack_plan"] = plan

        logger.info("AttackRouter built plan with %d actions", len(plan))
        return plan

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _analyze_ports(self, context: dict, actions: list[AttackAction]) -> None:
        """Map open ports to attack actions."""
        ports_data: dict = context.get("ports", {})
        for host, port_list in ports_data.items():
            if not isinstance(port_list, list):
                continue
            for entry in port_list:
                port_num = entry.get("port") if isinstance(entry, dict) else None
                if port_num is None:
                    continue
                if port_num in _PORT_MAP:
                    action_name, category, reason = _PORT_MAP[port_num]
                    # Database and Redis ports get highest priority
                    if port_num in (6379, 27017, 3306, 5432, 1433):
                        prio = 1
                    elif port_num in (21, 22, 23):
                        prio = 2
                    else:
                        prio = 3
                    actions.append(AttackAction(
                        action=action_name,
                        priority=prio,
                        reason=reason,
                        category=category,
                        target=f"{host}:{port_num}",
                    ))

    def _analyze_technologies(self, context: dict, actions: list[AttackAction]) -> None:
        """Derive CMS-specific and framework-specific attacks."""
        tech_data: dict = context.get("technologies", {})
        summary: dict = tech_data.get("summary", {})
        tech_lower = {k.lower(): v for k, v in summary.items()}
        tech_str = " ".join(tech_lower.keys())

        # WordPress
        if "wordpress" in tech_str:
            actions.append(AttackAction(
                action="wordpress_scan",
                priority=1,
                reason="WordPress detected — use WP-specific payloads and default creds",
                category="cms",
                params={
                    "test_default_creds": True,
                    "enumerate_plugins": True,
                    "enumerate_users": True,
                    "xmlrpc_brute": True,
                    "wp_cron_abuse": True,
                },
            ))

        # Joomla
        if "joomla" in tech_str:
            actions.append(AttackAction(
                action="joomla_scan",
                priority=1,
                reason="Joomla detected — test known Joomla attack paths",
                category="cms",
                params={"test_default_creds": True},
            ))

        # Drupal
        if "drupal" in tech_str:
            actions.append(AttackAction(
                action="drupal_scan",
                priority=1,
                reason="Drupal detected — test Drupalgeddon and admin paths",
                category="cms",
                params={"test_default_creds": True},
            ))

        # PHP
        if any(t in tech_str for t in ("php", "laravel", "codeigniter", "symfony")):
            actions.append(AttackAction(
                action="php_specific",
                priority=3,
                reason="PHP stack detected — prioritize SQLi, LFI, RCE",
                category="general",
                params={"priority_vulns": ["sqli", "lfi", "cmd_injection", "ssti"]},
            ))

        # Java / Spring
        if any(t in tech_str for t in ("java", "spring", "tomcat", "struts")):
            actions.append(AttackAction(
                action="java_specific",
                priority=3,
                reason="Java stack detected — test deserialization, SSTI, SSRF",
                category="general",
                params={"priority_vulns": ["ssti", "ssrf", "sqli", "deserialization"]},
            ))

        # Node.js / Express
        if any(t in tech_str for t in ("node", "express", "next.js", "nuxt")):
            actions.append(AttackAction(
                action="node_specific",
                priority=4,
                reason="Node.js stack detected — test prototype pollution, SSRF, XSS",
                category="general",
                params={"priority_vulns": ["xss", "ssrf", "idor", "prototype_pollution"]},
            ))

        # Python / Django / Flask
        if any(t in tech_str for t in ("python", "django", "flask")):
            actions.append(AttackAction(
                action="python_specific",
                priority=4,
                reason="Python stack detected — test SSTI, SSRF, IDOR",
                category="general",
                params={"priority_vulns": ["ssti", "ssrf", "idor"]},
            ))

        # GraphQL
        if "graphql" in tech_str:
            actions.append(AttackAction(
                action="graphql_introspection",
                priority=2,
                reason="GraphQL detected — introspection, batching, and IDOR attacks",
                category="api",
                params={"test_introspection": True, "test_batching": True},
            ))

    def _analyze_endpoints(self, context: dict, actions: list[AttackAction]) -> None:
        """Prioritize attacks based on discovered endpoints."""
        endpoints: list[dict] = context.get("endpoints", [])
        if not endpoints:
            return

        has_login = False
        has_api = False
        has_upload = False
        has_admin = False
        api_endpoints: list[str] = []
        login_urls: list[str] = []

        for ep in endpoints:
            url = (ep.get("url") or "").lower()
            ep_type = (ep.get("type") or "").lower()
            interest = (ep.get("interest") or "").lower()

            # Login / auth forms
            if any(kw in url for kw in ("/login", "/signin", "/auth", "/sso",
                                         "/wp-login", "/admin/login", "/user/login")):
                has_login = True
                login_urls.append(ep.get("url", ""))

            # Admin panels
            if any(kw in url for kw in ("/admin", "/dashboard", "/manager",
                                         "/wp-admin", "/cpanel", "/phpmyadmin")):
                has_admin = True

            # API endpoints
            if ep_type == "api" or any(kw in url for kw in ("/api/", "/graphql",
                                                             "/rest/", "/v1/", "/v2/", "/v3/")):
                has_api = True
                api_endpoints.append(ep.get("url", ""))

            # File upload
            if any(kw in url for kw in ("/upload", "/file", "/attach", "/import")):
                has_upload = True

        if has_login:
            actions.append(AttackAction(
                action="auth_brute_force",
                priority=2,
                reason="Login form found — prioritize authentication attacks",
                category="auth",
                params={"login_urls": login_urls[:10]},
            ))

        if has_admin:
            actions.append(AttackAction(
                action="admin_panel_attack",
                priority=2,
                reason="Admin panel found — test default credentials and access controls",
                category="auth",
                params={"test_default_creds": True},
            ))

        if has_api:
            actions.append(AttackAction(
                action="api_auth_testing",
                priority=2,
                reason="API endpoints found — prioritize API auth, IDOR, and rate-limit testing",
                category="api",
                params={"api_endpoints": api_endpoints[:20]},
            ))

        if has_upload:
            actions.append(AttackAction(
                action="upload_bypass",
                priority=3,
                reason="File upload found — test extension bypass, web shell upload",
                category="general",
                params={"priority_vulns": ["file_upload", "rce"]},
            ))

    def _analyze_sensitive_files(self, context: dict, actions: list[AttackAction]) -> None:
        """Flag high-priority items if .git, .env, or similar were found."""
        # Check vuln findings from sensitive_files phase
        vulns = context.get("vulnerabilities", [])
        scan_results = context.get("scan_results", [])

        all_findings = vulns + scan_results
        for finding in all_findings:
            title = (finding.get("title") or finding.get("name") or "").lower()
            url = (finding.get("url") or "").lower()
            combined = f"{title} {url}"

            for sensitive in _HIGH_PRIORITY_FILES:
                if sensitive in combined:
                    actions.append(AttackAction(
                        action="sensitive_file_exploit",
                        priority=1,
                        reason=f"Sensitive file '{sensitive}' discovered — HIGH PRIORITY",
                        category="file",
                        target=finding.get("url"),
                        params={"file_type": sensitive},
                    ))
                    break  # one action per finding

        # Also check recon data for leaked paths
        recon = context.get("recon_data", {})
        robots = recon.get("robots_txt", "") or ""
        for sensitive in (".git", ".env", ".svn", "wp-config"):
            if sensitive in robots.lower():
                actions.append(AttackAction(
                    action="sensitive_file_exploit",
                    priority=1,
                    reason=f"robots.txt references '{sensitive}' — possible leaked path",
                    category="file",
                    params={"file_type": sensitive, "source": "robots.txt"},
                ))

    def _analyze_waf(self, context: dict, actions: list[AttackAction]) -> None:
        """Set payload strategy based on WAF presence."""
        waf_info = context.get("waf_info") or {}

        if waf_info.get("detected"):
            waf_name = waf_info.get("waf_name", "unknown")
            actions.append(AttackAction(
                action="waf_evasion",
                priority=3,
                reason=f"WAF detected ({waf_name}) — use evasion techniques",
                category="network",
                params={
                    "waf_name": waf_name,
                    "strategy": "evasion",
                    "use_encoding": True,
                    "use_case_variation": True,
                    "use_chunked_transfer": True,
                    "slow_scan": True,
                },
            ))
        else:
            actions.append(AttackAction(
                action="aggressive_payloads",
                priority=5,
                reason="No WAF detected — use aggressive unencoded payloads",
                category="network",
                params={
                    "strategy": "aggressive",
                    "use_encoding": False,
                    "full_payload_set": True,
                },
            ))

    def _analyze_rate_limits(self, context: dict, actions: list[AttackAction]) -> None:
        """Adapt timing if rate limiting (429s) has been observed."""
        # Check recon data for 429 indicators
        recon = context.get("recon_data", {})
        status_codes = recon.get("status_codes", [])
        headers = recon.get("response_headers", {})

        rate_limited = False

        # Direct 429 observation
        if 429 in status_codes:
            rate_limited = True

        # Rate-limit headers present
        rl_headers = ("x-ratelimit-limit", "x-ratelimit-remaining",
                      "retry-after", "x-rate-limit-limit")
        for h in rl_headers:
            if h in {k.lower() for k in headers.keys()}:
                rate_limited = True
                break

        # Check if any endpoint responses had 429
        for ep in context.get("endpoints", []):
            if ep.get("status_code") == 429:
                rate_limited = True
                break

        if rate_limited:
            actions.append(AttackAction(
                action="adaptive_throttle",
                priority=2,
                reason="Rate limiting detected (429 responses) — slow down and adapt timing",
                category="resilience",
                params={
                    "reduce_concurrency": True,
                    "add_jitter": True,
                    "max_rps": 2,
                    "backoff_factor": 2.0,
                },
            ))

    def _analyze_risky_services(self, context: dict, actions: list[AttackAction]) -> None:
        """Process risky services flagged by the portscan module."""
        risky: list[dict] = context.get("risky_services", [])
        for svc in risky:
            service_name = (svc.get("service") or "").lower()
            port = svc.get("port")
            host = svc.get("host", context.get("domain", ""))

            # Skip if we already covered this port in _analyze_ports
            if port in _PORT_MAP:
                continue

            actions.append(AttackAction(
                action=f"{service_name}_attack",
                priority=2,
                reason=f"Risky service '{service_name}' on port {port}",
                category="service",
                target=f"{host}:{port}" if port else host,
            ))

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(actions: list[AttackAction]) -> list[AttackAction]:
        """Keep only the highest-priority entry per (action, target) pair."""
        best: dict[tuple, AttackAction] = {}
        for act in actions:
            key = (act.action, act.target)
            if key not in best or act.priority < best[key].priority:
                best[key] = act
        return list(best.values())


# ---------------------------------------------------------------------------
# Helper for downstream modules
# ---------------------------------------------------------------------------

def get_attack_plan(context: dict) -> list[dict]:
    """Return the attack plan from context, or an empty list."""
    return context.get("attack_plan", [])


def should_run_action(context: dict, action_name: str) -> bool:
    """Check if a specific action is in the attack plan."""
    plan = get_attack_plan(context)
    return any(a["action"] == action_name for a in plan)


def get_action_params(context: dict, action_name: str) -> dict:
    """Get the params dict for a specific action, or empty dict."""
    plan = get_attack_plan(context)
    for a in plan:
        if a["action"] == action_name:
            return a.get("params", {})
    return {}


def get_payload_strategy(context: dict) -> str:
    """Return 'evasion' or 'aggressive' based on WAF analysis in the plan."""
    plan = get_attack_plan(context)
    for a in plan:
        if a["action"] == "waf_evasion":
            return "evasion"
        if a["action"] == "aggressive_payloads":
            return "aggressive"
    return "standard"


def get_priority_vulns(context: dict) -> list[str]:
    """Aggregate priority_vulns from all technology-specific actions."""
    plan = get_attack_plan(context)
    vulns: list[str] = []
    seen: set[str] = set()
    for a in plan:
        for v in a.get("params", {}).get("priority_vulns", []):
            if v not in seen:
                seen.add(v)
                vulns.append(v)
    return vulns


def get_throttle_params(context: dict) -> dict | None:
    """Return adaptive throttle params if rate limiting was detected."""
    return get_action_params(context, "adaptive_throttle") or None
