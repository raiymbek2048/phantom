"""
Scope Enforcement — ensures all scanning stays within authorized boundaries.

Supports:
- Wildcard domains: *.example.com
- Exact domains: api.example.com
- Path exclusions: /admin/*, /internal/*
- IP ranges: 10.0.0.0/24
- Out-of-scope patterns: !*.staging.example.com
"""
import ipaddress
import json
import logging
import re
from fnmatch import fnmatch
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """Validates URLs against a target's authorized scope."""

    def __init__(self, scope_config: str | dict | list | None, base_domain: str = ""):
        self.base_domain = base_domain.lower().strip()
        self.include_domains: list[str] = []
        self.exclude_domains: list[str] = []
        self.include_paths: list[str] = []
        self.exclude_paths: list[str] = []
        self.include_ips: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._parse_scope(scope_config)

        # If no explicit scope, default to base domain + subdomains
        if not self.include_domains and self.base_domain:
            self.include_domains = [self.base_domain, f"*.{self.base_domain}"]

    def _parse_scope(self, scope_config):
        """Parse scope from various formats."""
        if not scope_config:
            return

        # Parse JSON string
        if isinstance(scope_config, str):
            try:
                scope_config = json.loads(scope_config)
            except (json.JSONDecodeError, ValueError):
                # Treat as newline/comma-separated list
                scope_config = [
                    s.strip() for s in re.split(r'[,\n]', scope_config)
                    if s.strip()
                ]

        if isinstance(scope_config, dict):
            # Structured format: {"include": [...], "exclude": [...]}
            for item in scope_config.get("include", []):
                self._add_rule(item, exclude=False)
            for item in scope_config.get("exclude", []):
                self._add_rule(item, exclude=True)
            for item in scope_config.get("include_paths", []):
                self.include_paths.append(item)
            for item in scope_config.get("exclude_paths", []):
                self.exclude_paths.append(item)
        elif isinstance(scope_config, list):
            for item in scope_config:
                if isinstance(item, str):
                    if item.startswith("!"):
                        self._add_rule(item[1:], exclude=True)
                    else:
                        self._add_rule(item, exclude=False)

    def _add_rule(self, rule: str, exclude: bool):
        """Add a single scope rule."""
        rule = rule.strip().lower()
        if not rule:
            return

        # Check if it's a path pattern
        if rule.startswith("/"):
            if exclude:
                self.exclude_paths.append(rule)
            else:
                self.include_paths.append(rule)
            return

        # Check if it's an IP/CIDR
        try:
            network = ipaddress.ip_network(rule, strict=False)
            if not exclude:
                self.include_ips.append(network)
            return
        except ValueError:
            pass

        # Strip protocol
        if "://" in rule:
            rule = urlparse(rule).netloc or rule

        # It's a domain pattern
        if exclude:
            self.exclude_domains.append(rule)
        else:
            self.include_domains.append(rule)

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the authorized scope."""
        if not url:
            return False

        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
        except Exception:
            return False

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        if not hostname:
            return False

        # Check excluded domains first (takes priority)
        for pattern in self.exclude_domains:
            if self._domain_matches(hostname, pattern):
                return False

        # Check excluded paths
        for pattern in self.exclude_paths:
            if fnmatch(path, pattern):
                return False

        # Check included domains
        domain_ok = False
        if self.include_domains:
            for pattern in self.include_domains:
                if self._domain_matches(hostname, pattern):
                    domain_ok = True
                    break
        else:
            # No explicit include = allow all (legacy behavior)
            domain_ok = True

        if not domain_ok:
            # Check IP ranges
            try:
                ip = ipaddress.ip_address(hostname)
                for network in self.include_ips:
                    if ip in network:
                        domain_ok = True
                        break
            except ValueError:
                pass

        # Check included paths (if specified, must match)
        if domain_ok and self.include_paths:
            path_ok = any(fnmatch(path, p) for p in self.include_paths)
            return path_ok

        return domain_ok

    def _domain_matches(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches a domain pattern (supports wildcards)."""
        if pattern == hostname:
            return True
        if pattern.startswith("*."):
            # *.example.com matches sub.example.com AND example.com
            base = pattern[2:]
            return hostname == base or hostname.endswith(f".{base}")
        return fnmatch(hostname, pattern)

    def filter_urls(self, urls: list) -> list:
        """Filter a list of URLs/endpoints to only in-scope ones."""
        filtered = []
        out_of_scope = 0
        for item in urls:
            url = item if isinstance(item, str) else item.get("url", "")
            if self.is_in_scope(url):
                filtered.append(item)
            else:
                out_of_scope += 1

        if out_of_scope > 0:
            logger.info(f"Scope filter: kept {len(filtered)}, excluded {out_of_scope} out-of-scope URLs")

        return filtered

    def get_summary(self) -> dict:
        """Return scope summary for logging."""
        return {
            "include_domains": self.include_domains,
            "exclude_domains": self.exclude_domains,
            "include_paths": self.include_paths,
            "exclude_paths": self.exclude_paths,
            "include_ips": [str(ip) for ip in self.include_ips],
        }
