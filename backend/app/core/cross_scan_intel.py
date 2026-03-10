"""
Cross-Scan Intelligence — Learn from ALL past scans to predict vulnerabilities.

Uses historical scan data to:
1. Predict which vuln types a target is likely vulnerable to (based on tech stack)
2. Find similar targets and reuse their successful attack strategies
3. Enrich scan context before phases begin with cross-scan payloads and priorities
"""
import logging
from collections import defaultdict

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern
from app.models.vulnerability import Vulnerability, VulnType
from app.models.scan import Scan, ScanStatus
from app.models.target import Target

logger = logging.getLogger(__name__)


class CrossScanIntel:
    """Cross-scan intelligence: predictions and enrichment from historical data."""

    async def get_tech_predictions(
        self,
        technologies: list[str],
        db: AsyncSession,
    ) -> list[dict]:
        """Given a target's tech stack, predict likely vulnerability types.

        Queries past Vulnerability records, joins with Target to compare
        technology stacks, and ranks vuln_types by probability.

        Returns: [{"vuln_type": "sqli", "probability": 0.73, "sample_count": 15, "technologies": ["php", "mysql"]}, ...]
        """
        if not technologies:
            return []

        tech_set = set(t.lower() for t in technologies)

        # Query all targets that have completed scans
        result = await db.execute(
            select(Target).where(
                Target.technologies.isnot(None),
            )
        )
        all_targets = result.scalars().all()

        if not all_targets:
            return []

        # Find targets with similar tech stacks (>50% overlap)
        similar_target_ids = []
        for t in all_targets:
            t_techs = set()
            tech_data = t.technologies or {}
            summary = tech_data.get("summary", {})
            if isinstance(summary, dict):
                t_techs = set(k.lower() for k in summary.keys())
            elif isinstance(summary, list):
                t_techs = set(str(x).lower() for x in summary)

            if not t_techs:
                continue

            # Calculate overlap ratio
            overlap = tech_set & t_techs
            union = tech_set | t_techs
            if union and len(overlap) / len(union) >= 0.3:
                similar_target_ids.append(t.id)

        if not similar_target_ids:
            # Fallback: use knowledge base patterns
            return await self._predictions_from_knowledge(technologies, db)

        # Query vulnerability distribution for similar targets
        vuln_counts: dict[str, int] = defaultdict(int)
        target_with_vuln: dict[str, set] = defaultdict(set)

        # Process in batches to avoid overly large IN clauses
        batch_size = 50
        for i in range(0, len(similar_target_ids), batch_size):
            batch = similar_target_ids[i:i + batch_size]
            result = await db.execute(
                select(
                    Vulnerability.vuln_type,
                    Vulnerability.target_id,
                    func.count(Vulnerability.id),
                ).where(
                    Vulnerability.target_id.in_(batch),
                ).group_by(
                    Vulnerability.vuln_type,
                    Vulnerability.target_id,
                )
            )
            for vt, tid, count in result.all():
                vt_str = vt.value if hasattr(vt, "value") else str(vt)
                vuln_counts[vt_str] += count
                target_with_vuln[vt_str].add(tid)

        if not vuln_counts:
            return await self._predictions_from_knowledge(technologies, db)

        # Calculate probability: targets_with_this_vuln / total_similar_targets
        total_similar = len(similar_target_ids)
        predictions = []
        for vt, count in vuln_counts.items():
            targets_affected = len(target_with_vuln[vt])
            probability = targets_affected / total_similar
            predictions.append({
                "vuln_type": vt,
                "probability": round(probability, 2),
                "sample_count": count,
                "targets_affected": targets_affected,
                "total_similar_targets": total_similar,
                "technologies": list(tech_set),
            })

        predictions.sort(key=lambda x: x["probability"], reverse=True)
        return predictions[:15]

    async def _predictions_from_knowledge(
        self,
        technologies: list[str],
        db: AsyncSession,
    ) -> list[dict]:
        """Fallback: get predictions from KnowledgePattern correlations."""
        predictions = []
        for tech in technologies[:10]:
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "tech_vuln_correlation",
                        KnowledgePattern.technology == tech.lower(),
                        KnowledgePattern.confidence > 0.3,
                    )
                ).order_by(KnowledgePattern.confidence.desc()).limit(10)
            )
            patterns = result.scalars().all()
            for p in patterns:
                data = p.pattern_data or {}
                predictions.append({
                    "vuln_type": p.vuln_type,
                    "probability": round(data.get("success_rate", 0), 2),
                    "sample_count": p.sample_count,
                    "technologies": [tech.lower()],
                    "source": "knowledge_base",
                })

        # Deduplicate by vuln_type, keeping highest probability
        seen: dict[str, dict] = {}
        for p in predictions:
            vt = p["vuln_type"]
            if vt not in seen or p["probability"] > seen[vt]["probability"]:
                seen[vt] = p
        result_list = sorted(seen.values(), key=lambda x: x["probability"], reverse=True)
        return result_list[:15]

    async def get_similar_targets(
        self,
        target_id: str,
        db: AsyncSession,
    ) -> list[dict]:
        """Find targets with similar characteristics (tech stack, ports, domain patterns).

        Returns top 5 similar targets with their vuln summary.
        """
        # Load the reference target
        result = await db.execute(select(Target).where(Target.id == target_id))
        ref_target = result.scalar_one_or_none()
        if not ref_target:
            return []

        ref_techs = set()
        tech_data = ref_target.technologies or {}
        summary = tech_data.get("summary", {})
        if isinstance(summary, dict):
            ref_techs = set(k.lower() for k in summary.keys())
        elif isinstance(summary, list):
            ref_techs = set(str(x).lower() for x in summary)

        ref_ports = set()
        ports_data = ref_target.ports or {}
        if isinstance(ports_data, dict):
            ref_ports = set(str(k) for k in ports_data.keys())
        elif isinstance(ports_data, list):
            ref_ports = set(str(p) for p in ports_data)

        # Load all other targets
        result = await db.execute(
            select(Target).where(Target.id != target_id)
        )
        all_targets = result.scalars().all()

        scored: list[tuple[float, Target]] = []

        for t in all_targets:
            score = 0.0

            # Technology overlap (weight: 0.6)
            t_techs = set()
            t_tech_data = t.technologies or {}
            t_summary = t_tech_data.get("summary", {})
            if isinstance(t_summary, dict):
                t_techs = set(k.lower() for k in t_summary.keys())
            elif isinstance(t_summary, list):
                t_techs = set(str(x).lower() for x in t_summary)

            if ref_techs and t_techs:
                overlap = ref_techs & t_techs
                union = ref_techs | t_techs
                if union:
                    score += 0.6 * (len(overlap) / len(union))

            # Port overlap (weight: 0.25)
            t_ports = set()
            t_ports_data = t.ports or {}
            if isinstance(t_ports_data, dict):
                t_ports = set(str(k) for k in t_ports_data.keys())
            elif isinstance(t_ports_data, list):
                t_ports = set(str(p) for p in t_ports_data)

            if ref_ports and t_ports:
                overlap = ref_ports & t_ports
                union = ref_ports | t_ports
                if union:
                    score += 0.25 * (len(overlap) / len(union))

            # Domain pattern similarity (weight: 0.15)
            ref_domain = ref_target.domain.lower()
            t_domain = t.domain.lower()
            # Check TLD match
            ref_parts = ref_domain.split(".")
            t_parts = t_domain.split(".")
            if len(ref_parts) >= 2 and len(t_parts) >= 2:
                if ref_parts[-1] == t_parts[-1]:  # Same TLD
                    score += 0.05
                if ref_parts[-2:] == t_parts[-2:]:  # Same domain suffix
                    score += 0.10

            if score > 0.1:
                scored.append((score, t))

        # Sort by score descending, take top 5
        scored.sort(key=lambda x: x[0], reverse=True)
        top_targets = scored[:5]

        results = []
        for sim_score, t in top_targets:
            # Get vuln summary for this target
            vuln_result = await db.execute(
                select(
                    Vulnerability.vuln_type,
                    Vulnerability.severity,
                    func.count(Vulnerability.id),
                ).where(
                    Vulnerability.target_id == t.id,
                ).group_by(
                    Vulnerability.vuln_type,
                    Vulnerability.severity,
                )
            )
            vuln_summary = {}
            for vt, sev, count in vuln_result.all():
                vt_str = vt.value if hasattr(vt, "value") else str(vt)
                sev_str = sev.value if hasattr(sev, "value") else str(sev)
                vuln_summary[vt_str] = vuln_summary.get(vt_str, 0) + count

            t_techs_list = list(
                (t.technologies or {}).get("summary", {}).keys()
                if isinstance((t.technologies or {}).get("summary"), dict)
                else []
            )

            results.append({
                "target_id": t.id,
                "domain": t.domain,
                "similarity_score": round(sim_score, 2),
                "technologies": t_techs_list,
                "vuln_summary": vuln_summary,
                "total_vulns": sum(vuln_summary.values()),
            })

        return results

    async def enrich_context(self, context: dict, db: AsyncSession) -> dict:
        """Called at start of scan pipeline to enrich context with cross-scan intelligence.

        - Gets tech predictions for target's stack
        - Prioritizes predicted vuln types in attack strategy
        - Adds cross-scan payloads that worked on similar targets
        - Returns enriched context
        """
        target_id = context.get("target_id")
        technologies = context.get("technologies") or {}
        tech_list = list(technologies.get("summary", {}).keys()) if isinstance(technologies.get("summary"), dict) else []

        enrichment = {
            "predictions": [],
            "similar_targets": [],
            "cross_scan_payloads_added": 0,
            "priority_vuln_types": [],
        }

        # --- 1. Get tech-based predictions ---
        if tech_list:
            try:
                predictions = await self.get_tech_predictions(tech_list, db)
                enrichment["predictions"] = predictions

                # Log predictions
                for pred in predictions[:5]:
                    vt = pred["vuln_type"]
                    prob = pred["probability"]
                    logger.info(
                        f"Cross-scan intel: {'+'.join(tech_list[:3])} targets have "
                        f"{prob*100:.0f}% {vt} rate"
                    )

                # Set priority vuln types (probability > 40%)
                priority_types = [
                    p["vuln_type"] for p in predictions
                    if p["probability"] > 0.4
                ]
                if priority_types:
                    enrichment["priority_vuln_types"] = priority_types
                    context["priority_vuln_types"] = priority_types

            except Exception as e:
                logger.warning(f"CrossScanIntel: tech predictions failed: {e}")

        # --- 2. Find similar targets ---
        if target_id:
            try:
                similar = await self.get_similar_targets(target_id, db)
                enrichment["similar_targets"] = similar

                if similar:
                    logger.info(
                        f"Cross-scan intel: found {len(similar)} similar targets "
                        f"(top: {similar[0]['domain']} at {similar[0]['similarity_score']} similarity)"
                    )
            except Exception as e:
                logger.warning(f"CrossScanIntel: similar targets lookup failed: {e}")

        # --- 3. Add cross-scan payloads from similar targets ---
        if target_id:
            try:
                added = await self._add_cross_scan_payloads(context, db)
                enrichment["cross_scan_payloads_added"] = added
            except Exception as e:
                logger.warning(f"CrossScanIntel: payload enrichment failed: {e}")

        # Store enrichment data in context for later phases
        context["cross_scan_intel"] = enrichment

        return context

    async def _add_cross_scan_payloads(self, context: dict, db: AsyncSession) -> int:
        """Add payloads that worked on similar targets to context."""
        technologies = context.get("technologies") or {}
        tech_list = list(technologies.get("summary", {}).keys()) if isinstance(technologies.get("summary"), dict) else []

        if not tech_list:
            return 0

        # Get effective payloads from knowledge base for matching technologies
        added = 0
        existing_payloads = set()
        for p in context.get("payloads", []):
            if isinstance(p, dict):
                existing_payloads.add(p.get("payload", ""))
            else:
                existing_payloads.add(str(p))

        for tech in tech_list[:5]:
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "effective_payload",
                        KnowledgePattern.technology == tech.lower(),
                        KnowledgePattern.confidence > 0.5,
                    )
                ).order_by(KnowledgePattern.confidence.desc()).limit(10)
            )
            patterns = result.scalars().all()

            for p in patterns:
                data = p.pattern_data or {}
                payloads = data.get("payloads", [])
                if not payloads and data.get("payload"):
                    payloads = [data["payload"]]

                for payload in payloads[:3]:
                    if payload and payload not in existing_payloads and len(payload) >= 3:
                        context.setdefault("payloads", []).append({
                            "payload": payload,
                            "vuln_type": p.vuln_type or "unknown",
                            "type": p.vuln_type or "unknown",
                            "source": "cross_scan_intel",
                            "technology": tech.lower(),
                            "confidence": p.confidence,
                        })
                        existing_payloads.add(payload)
                        added += 1

        # Also add AI mutation payloads with high confidence
        result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "ai_mutation",
                    KnowledgePattern.confidence > 0.6,
                )
            ).order_by(KnowledgePattern.confidence.desc()).limit(20)
        )
        mutations = result.scalars().all()

        for m in mutations:
            data = m.pattern_data or {}
            payload = data.get("payload", "")
            if payload and payload not in existing_payloads and len(payload) >= 3:
                context.setdefault("payloads", []).append({
                    "payload": payload,
                    "vuln_type": m.vuln_type or "unknown",
                    "type": m.vuln_type or "unknown",
                    "source": "cross_scan_mutation",
                    "confidence": m.confidence,
                })
                existing_payloads.add(payload)
                added += 1

        if added:
            logger.info(f"Cross-scan intel: added {added} payloads from similar targets/mutations")

        return added
