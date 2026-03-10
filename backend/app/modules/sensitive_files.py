"""
Sensitive File Discovery — Find exposed configs, backups, source code.

A real hacker always checks for:
- .env, .git, .svn exposed
- Backup files (.bak, .old, .sql.gz)
- Config files (wp-config.php, settings.py, .htaccess)
- Source code leaks
- Admin panels
- API documentation
- Debug endpoints
"""
import asyncio
import logging
import re
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# Sensitive paths to check — ordered by severity
SENSITIVE_PATHS = [
    # Git/SVN exposure — CRITICAL
    (".git/HEAD", "critical", "Git repository exposed"),
    (".git/config", "critical", "Git config exposed"),
    (".svn/entries", "critical", "SVN repository exposed"),
    (".hg/store/00manifest.i", "high", "Mercurial repo exposed"),

    # Environment / config files — CRITICAL
    (".env", "critical", "Environment file exposed"),
    (".env.local", "critical", "Local env file exposed"),
    (".env.production", "critical", "Production env file exposed"),
    (".env.backup", "critical", "Env backup exposed"),
    ("env.js", "high", "JS env config exposed"),
    ("config.json", "high", "Config JSON exposed"),
    ("config.yml", "high", "Config YAML exposed"),
    ("config.yaml", "high", "Config YAML exposed"),
    ("wp-config.php", "critical", "WordPress config exposed"),
    ("wp-config.php.bak", "critical", "WordPress config backup"),
    ("configuration.php", "critical", "Joomla config exposed"),
    ("settings.py", "high", "Django settings exposed"),
    ("config/database.yml", "high", "Rails DB config exposed"),
    ("appsettings.json", "high", ".NET config exposed"),
    ("web.config", "high", "IIS web.config exposed"),
    (".htaccess", "medium", "Apache .htaccess exposed"),
    (".htpasswd", "critical", "Apache password file exposed"),
    ("nginx.conf", "high", "Nginx config exposed"),

    # Backup files — HIGH
    ("backup.sql", "critical", "SQL backup exposed"),
    ("dump.sql", "critical", "SQL dump exposed"),
    ("database.sql", "critical", "Database dump exposed"),
    ("db.sql", "critical", "Database dump exposed"),
    ("backup.tar.gz", "high", "Backup archive exposed"),
    ("backup.zip", "high", "Backup archive exposed"),
    ("site.tar.gz", "high", "Site backup exposed"),

    # Debug / development — HIGH
    ("debug", "high", "Debug endpoint"),
    ("_debug", "high", "Debug endpoint"),
    ("phpinfo.php", "high", "PHP info page"),
    ("info.php", "high", "PHP info page"),
    ("test.php", "medium", "Test page"),
    ("server-status", "high", "Apache server-status"),
    ("server-info", "high", "Apache server-info"),
    ("elmah.axd", "high", ".NET error log"),
    (".DS_Store", "low", "macOS DS_Store file"),
    ("Thumbs.db", "low", "Windows thumbnail cache"),

    # Admin panels — MEDIUM (info disclosure)
    ("admin", "medium", "Admin panel"),
    ("administrator", "medium", "Admin panel"),
    ("admin/login", "medium", "Admin login"),
    ("wp-admin", "medium", "WordPress admin"),
    ("wp-login.php", "medium", "WordPress login"),
    ("phpmyadmin", "medium", "phpMyAdmin"),
    ("adminer.php", "high", "Adminer DB tool"),
    ("_phpmyadmin", "medium", "phpMyAdmin"),
    ("cpanel", "medium", "cPanel"),
    ("webmail", "medium", "Webmail"),

    # API documentation — MEDIUM
    ("swagger.json", "medium", "Swagger API docs"),
    ("api-docs", "medium", "API documentation"),
    ("swagger-ui.html", "medium", "Swagger UI"),
    ("openapi.json", "medium", "OpenAPI spec"),
    ("graphql", "medium", "GraphQL endpoint"),
    ("graphiql", "medium", "GraphiQL IDE"),
    ("api/v1", "low", "API endpoint"),
    ("api/v2", "low", "API endpoint"),

    # Source maps — MEDIUM
    ("main.js.map", "medium", "JS source map"),
    ("app.js.map", "medium", "JS source map"),
    ("bundle.js.map", "medium", "JS source map"),

    # Container/cloud metadata
    (".dockerenv", "high", "Docker environment"),
    ("Dockerfile", "medium", "Dockerfile exposed"),
    ("docker-compose.yml", "high", "Docker compose exposed"),

    # CI/CD
    (".github/workflows", "medium", "GitHub Actions exposed"),
    (".gitlab-ci.yml", "medium", "GitLab CI config"),
    ("Jenkinsfile", "medium", "Jenkins pipeline"),

    # Package managers
    ("package.json", "low", "NPM package.json"),
    ("composer.json", "low", "PHP composer.json"),
    ("requirements.txt", "low", "Python requirements"),
    ("Gemfile", "low", "Ruby Gemfile"),
]

# Patterns that indicate a real file (not a 404 or redirect)
REAL_FILE_INDICATORS = {
    ".env": ["DB_", "DATABASE_", "SECRET", "API_KEY", "PASSWORD", "TOKEN", "REDIS", "MAIL_"],
    ".git/HEAD": ["ref: refs/"],
    ".git/config": ["[core]", "[remote"],
    "phpinfo.php": ["phpinfo()", "PHP Version", "Configuration File"],
    "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"],
    "swagger.json": ['"swagger"', '"openapi"', '"paths"'],
    "server-status": ["Apache Server Status", "Total accesses"],
    ".htpasswd": [":$", ":{SHA}"],
    "backup.sql": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "dump.sql": ["CREATE TABLE", "INSERT INTO"],
}


class SensitiveFilesModule:
    """Discover sensitive files, configs, backups, and exposed admin panels."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)

    async def run(self, context: dict) -> list[dict]:
        """Check for all sensitive file paths."""
        base_url = context.get("base_url", "")
        if not base_url:
            return []

        findings = []

        # Batch check all paths
        tasks = []
        for path, severity, description in SENSITIVE_PATHS:
            url = urljoin(base_url + "/", path)
            tasks.append(self._check_path(url, path, severity, description, base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        # Also check for source maps of discovered JS files
        endpoints = context.get("endpoints", [])
        js_files = [
            (ep.get("url") if isinstance(ep, dict) else ep)
            for ep in endpoints
            if (ep.get("url") if isinstance(ep, dict) else ep or "").endswith(".js")
        ]
        for js_url in js_files[:20]:
            map_url = js_url + ".map"
            task = self._check_path(map_url, js_url.split("/")[-1] + ".map",
                                     "medium", "JS source map exposed", base_url)
            result = await task
            if result:
                findings.append(result)

        logger.info(f"Sensitive files: found {len(findings)} exposed files/endpoints")
        return findings

    async def _check_path(self, url: str, path: str, severity: str,
                          description: str, base_url: str) -> dict | None:
        """Check if a sensitive path exists and contains real data."""
        async with self.rate_limit:
            try:
                async with httpx.AsyncClient(timeout=10.0, verify=False,
                                              follow_redirects=False) as client:
                    resp = await client.get(url)

                    # Skip redirects (usually to login page — not a real finding)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        return None

                    # Skip 404, 403, 500
                    if resp.status_code != 200:
                        # 403 on certain paths IS interesting (path exists but blocked)
                        if resp.status_code == 403 and severity in ("critical", "high"):
                            # Only report if it's a very sensitive path
                            if any(s in path for s in [".git", ".env", "backup", "dump"]):
                                return {
                                    "title": f"Sensitive path exists but blocked: /{path}",
                                    "url": url,
                                    "severity": "low",
                                    "vuln_type": "info_disclosure",
                                    "payload": f"curl {url} → 403 Forbidden",
                                    "impact": f"Path /{path} exists on the server (403). "
                                             "Verify it's properly secured.",
                                    "remediation": f"Remove /{path} from web-accessible directory.",
                                }
                        return None

                    body = resp.text
                    content_type = resp.headers.get("content-type", "")

                    # Skip if it's an HTML error page (custom 404)
                    if "text/html" in content_type and len(body) > 500:
                        # Check if it's a generic HTML page (likely custom 404)
                        body_lower = body.lower()
                        if any(ind in body_lower for ind in
                               ["not found", "page not found", "404", "error",
                                "<!doctype html", "<html"]):
                            # Verify with indicators for known file types
                            indicators = REAL_FILE_INDICATORS.get(path, [])
                            if indicators and not any(ind in body for ind in indicators):
                                return None  # HTML page, not the real file
                            elif not indicators and "<!doctype" in body_lower:
                                return None  # Generic HTML page

                    # Validate real content for known file types
                    indicators = REAL_FILE_INDICATORS.get(path, [])
                    if indicators:
                        if not any(ind in body for ind in indicators):
                            return None  # File doesn't contain expected content

                    # Empty files are not interesting
                    if len(body.strip()) < 5:
                        return None

                    # Scan for high-value secrets in the file content
                    secrets_found = self._extract_secrets(body)
                    if secrets_found:
                        severity = "critical"  # Upgrade severity if real secrets found

                    # Build finding
                    preview = body[:500]
                    # Mask secrets in preview
                    preview = re.sub(r'(password|secret|key|token)\s*[=:]\s*["\']?([^"\';\s]+)',
                                    r'\1=***REDACTED***', preview, flags=re.IGNORECASE)

                    impact = f"Sensitive file /{path} is publicly accessible. Size: {len(body)} bytes. {description}."
                    if secrets_found:
                        impact += f" CRITICAL: {len(secrets_found)} secret(s) detected: {', '.join(s['type'] for s in secrets_found)}."

                    return {
                        "title": f"{description}: /{path}",
                        "url": url,
                        "severity": severity,
                        "vuln_type": "info_disclosure",
                        "payload": f"curl {url}",
                        "impact": impact,
                        "remediation": f"Remove /{path} from web root or block access via server config. "
                                      "Add to .gitignore. Configure web server to deny access to sensitive files.",
                        "method": "GET",
                        "response_preview": preview,
                        "secrets_found": len(secrets_found) if secrets_found else 0,
                    }

            except Exception:
                return None

    def _extract_secrets(self, content: str) -> list[dict]:
        """Scan file content for high-value secrets (API keys, passwords, tokens)."""
        secrets = []
        patterns = [
            # AWS
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
            (r'(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key"),
            # Private keys
            (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
            # JWT tokens
            (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', "JWT Token"),
            # Database connection strings
            (r'(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+', "Database URL with credentials"),
            # Generic API keys
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
            # Google
            (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
            # Stripe
            (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key"),
            (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Publishable Key"),
            # GitHub
            (r'ghp_[0-9a-zA-Z]{36}', "GitHub PAT"),
            (r'github_pat_[0-9a-zA-Z_]{82}', "GitHub Fine-Grained PAT"),
            # Slack
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "Slack Token"),
            # SendGrid
            (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key"),
            # Twilio
            (r'SK[0-9a-fA-F]{32}', "Twilio API Key"),
            # Passwords in config
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{3,50})["\']', "Hardcoded Password"),
            # Mailgun
            (r'key-[0-9a-zA-Z]{32}', "Mailgun API Key"),
            # Heroku
            (r'heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "Heroku API Key"),
        ]

        for pattern, secret_type in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                secrets.append({"type": secret_type, "pattern": pattern})

        return secrets
