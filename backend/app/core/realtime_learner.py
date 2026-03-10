"""
Real-time Learning Engine — Learn DURING scans, not just after.

When a vulnerability is confirmed mid-scan, the learner:
1. Records the successful payload immediately (boosted confidence)
2. Generates quick string-transform mutations (no LLM — too slow)
3. Injects mutations into context["payloads"] for the SAME scan
4. Adapts strategy between phases based on scan progress

All mutations are simple string transforms: case variation, URL encoding,
quote swaps, comment injection, whitespace variation.
"""
import logging
import urllib.parse
import uuid
from collections import Counter

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


class RealtimeLearner:
    """Learns and adapts in real-time during a scan."""

    def __init__(self):
        self._vuln_counts: Counter = Counter()  # vuln_type -> count
        self._blocked_count: int = 0
        self._total_requests: int = 0

    # ------------------------------------------------------------------
    # Payload mutation helpers (pure string transforms, no LLM)
    # ------------------------------------------------------------------

    @staticmethod
    def _case_variations(payload: str) -> list[str]:
        """Generate case-swapped variants."""
        variants = []
        # Swap to uppercase
        upper = payload.upper()
        if upper != payload:
            variants.append(upper)
        # Swap to lowercase
        lower = payload.lower()
        if lower != payload:
            variants.append(lower)
        # Mixed case: uppercase every other alphabetic char
        mixed = []
        flip = False
        for ch in payload:
            if ch.isalpha():
                mixed.append(ch.upper() if flip else ch.lower())
                flip = not flip
            else:
                mixed.append(ch)
        mixed_str = "".join(mixed)
        if mixed_str != payload and mixed_str not in variants:
            variants.append(mixed_str)
        return variants

    @staticmethod
    def _url_encode_variations(payload: str) -> list[str]:
        """Generate URL-encoded variants."""
        variants = []
        # Full URL encode
        encoded = urllib.parse.quote(payload, safe="")
        if encoded != payload:
            variants.append(encoded)
        # Double URL encode
        double_encoded = urllib.parse.quote(encoded, safe="")
        if double_encoded != encoded:
            variants.append(double_encoded)
        return variants

    @staticmethod
    def _quote_swap(payload: str) -> list[str]:
        """Swap single quotes for double quotes and vice versa."""
        variants = []
        if "'" in payload:
            variants.append(payload.replace("'", '"'))
        if '"' in payload:
            variants.append(payload.replace('"', "'"))
        return variants

    @staticmethod
    def _comment_injection(payload: str) -> list[str]:
        """Inject SQL/HTML comments into payload."""
        variants = []
        # SQL inline comment
        if " " in payload:
            variants.append(payload.replace(" ", "/**/", 1))
        # SQL line comment suffix
        if not payload.rstrip().endswith("--"):
            variants.append(payload + " --")
        if not payload.rstrip().endswith("#"):
            variants.append(payload + " #")
        # HTML comment variant (for XSS payloads)
        if "<" in payload and ">" in payload:
            variants.append(payload.replace(">", "><!---->", 1))
        return variants

    @staticmethod
    def _whitespace_variation(payload: str) -> list[str]:
        """Vary whitespace: tabs, newlines, multiple spaces."""
        variants = []
        if " " in payload:
            # Tab substitution
            variants.append(payload.replace(" ", "\t", 1))
            # Newline substitution
            variants.append(payload.replace(" ", "\n", 1))
            # Double space
            variants.append(payload.replace(" ", "  ", 1))
        return variants

    def _generate_mutations(self, payload: str, max_mutations: int = 5) -> list[str]:
        """Generate 3-5 quick mutations using simple string transforms."""
        if not payload or len(payload) < 3:
            return []

        all_variants: list[str] = []

        # Apply each transform, collecting candidates
        all_variants.extend(self._case_variations(payload))
        all_variants.extend(self._url_encode_variations(payload))
        all_variants.extend(self._quote_swap(payload))
        all_variants.extend(self._comment_injection(payload))
        all_variants.extend(self._whitespace_variation(payload))

        # Deduplicate and exclude the original
        seen = {payload}
        unique = []
        for v in all_variants:
            if v not in seen and len(v) < 5000:
                seen.add(v)
                unique.append(v)

        return unique[:max_mutations]

    # ------------------------------------------------------------------
    # Core methods
    # ------------------------------------------------------------------

    async def on_vuln_confirmed(
        self,
        vuln_data: dict,
        context: dict,
        db: AsyncSession,
    ) -> list[str]:
        """Called immediately when a vuln is confirmed during exploit phase.

        - Records the successful payload in KnowledgePattern (boosted confidence)
        - Generates 3-5 quick mutations
        - Adds mutations to context["payloads"] for same-scan testing
        - Returns the mutations list
        """
        payload = vuln_data.get("payload_used") or vuln_data.get("payload", "")
        vuln_type = vuln_data.get("vuln_type", "unknown")
        if hasattr(vuln_type, "value"):
            vuln_type = vuln_type.value

        # Track counts for adapt_strategy
        self._vuln_counts[vuln_type] += 1

        if not payload or len(payload) < 3:
            return []

        # --- 1. Record as effective payload with boosted confidence ---
        technologies = context.get("technologies") or {}
        tech_summary = technologies.get("summary", {})
        tech = next(iter(tech_summary.keys()), "unknown").lower() if tech_summary else "unknown"

        try:
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "effective_payload",
                        KnowledgePattern.vuln_type == vuln_type,
                        KnowledgePattern.technology == tech,
                    )
                ).limit(1)
            )
            existing = result.scalar_one_or_none()

            if existing:
                data = existing.pattern_data or {}
                payloads_list = data.get("payloads", [])
                if payload not in payloads_list:
                    payloads_list.append(payload)
                    payloads_list = payloads_list[-50:]
                existing.pattern_data = {
                    "payload": payloads_list[0],
                    "payloads": payloads_list,
                    "realtime": True,
                }
                existing.sample_count += 1
                # Boost confidence for real-time confirmed payload
                existing.confidence = min(0.95, existing.confidence + 0.1)
            else:
                db.add(KnowledgePattern(
                    id=str(uuid.uuid4()),
                    pattern_type="effective_payload",
                    technology=tech,
                    vuln_type=vuln_type,
                    pattern_data={
                        "payload": payload,
                        "payloads": [payload],
                        "realtime": True,
                    },
                    confidence=0.6,  # Higher initial confidence (confirmed in real-time)
                    sample_count=1,
                ))
            await db.flush()
        except Exception as e:
            logger.warning(f"RealtimeLearner: failed to record payload: {e}")

        # --- 2. Generate quick mutations ---
        mutations = self._generate_mutations(payload, max_mutations=5)

        # --- 3. Add mutations to context["payloads"] ---
        if mutations:
            existing_payloads = {
                p.get("payload", "") if isinstance(p, dict) else str(p)
                for p in context.get("payloads", [])
            }
            added = 0
            for mut in mutations:
                if mut not in existing_payloads:
                    context.setdefault("payloads", []).append({
                        "payload": mut,
                        "vuln_type": vuln_type,
                        "type": vuln_type,
                        "source": "realtime_mutation",
                        "parent_payload": payload[:200],
                    })
                    added += 1
            if added:
                logger.info(
                    f"RealtimeLearner: {vuln_type} confirmed — added {added} mutations to context"
                )

        return mutations

    async def adapt_strategy(self, context: dict, db: AsyncSession) -> dict:
        """Called between phases to adjust strategy based on scan progress.

        Returns a dict of adjustments to apply to context.
        """
        adjustments: dict = {
            "skip_vuln_types": [],
            "increase_aggressiveness": False,
            "waf_only_mode": False,
            "prioritize_vuln_types": [],
            "notes": [],
        }

        # --- 1. Skip over-proven vuln types (>5 confirmed) ---
        for vt, count in self._vuln_counts.items():
            if count > 5:
                adjustments["skip_vuln_types"].append(vt)
                adjustments["notes"].append(
                    f"Skipping {vt}: already confirmed {count} instances"
                )

        # --- 2. Increase aggressiveness if no vulns after endpoint+vuln_scan ---
        total_vulns = len(context.get("vulnerabilities", []))
        endpoints_found = len(context.get("endpoints", []))
        if endpoints_found > 0 and total_vulns == 0:
            adjustments["increase_aggressiveness"] = True
            adjustments["notes"].append(
                f"0 vulns with {endpoints_found} endpoints — increasing payload aggressiveness"
            )
            # Add aggressive context flags
            context["aggressive_mode"] = True
            context["payload_depth"] = "deep"

        # --- 3. WAF blocking detection ---
        waf_info = context.get("waf_info") or {}
        if waf_info.get("detected"):
            blocked = waf_info.get("blocked_count", 0)
            total = waf_info.get("total_requests", 0)
            if total > 0 and (blocked / total) > 0.5:
                adjustments["waf_only_mode"] = True
                adjustments["notes"].append(
                    f"WAF blocking {blocked}/{total} ({blocked/total*100:.0f}%) requests "
                    f"— switching to WAF-specific payloads only"
                )
                # Filter payloads to WAF-bypass only
                waf_payloads = [
                    p for p in context.get("payloads", [])
                    if isinstance(p, dict) and p.get("waf_bypass")
                ]
                if waf_payloads:
                    context["payloads"] = waf_payloads
                    adjustments["notes"].append(
                        f"Filtered to {len(waf_payloads)} WAF-bypass payloads"
                    )

        # --- 4. Prioritize vuln types from knowledge base ---
        try:
            technologies = context.get("technologies") or {}
            tech_list = list(technologies.get("summary", {}).keys())
            if tech_list:
                from app.core.knowledge import KnowledgeBase
                kb = KnowledgeBase()
                insights = await kb.get_tech_vuln_insights(db, tech_list)
                recs = insights.get("recommendations", [])
                # Prioritize vuln types that have high success rate but haven't been tested yet
                tested = set(self._vuln_counts.keys())
                for rec in recs[:5]:
                    vt = rec.get("vuln_type", "")
                    if vt and vt not in tested and rec.get("success_rate", 0) > 0.3:
                        adjustments["prioritize_vuln_types"].append(vt)
                if adjustments["prioritize_vuln_types"]:
                    adjustments["notes"].append(
                        f"Prioritizing untested high-success types: "
                        f"{', '.join(adjustments['prioritize_vuln_types'])}"
                    )
        except Exception as e:
            logger.debug(f"RealtimeLearner: knowledge-based prioritization failed: {e}")

        # Apply skip list to context
        if adjustments["skip_vuln_types"]:
            context["skip_vuln_types"] = adjustments["skip_vuln_types"]

        return adjustments
