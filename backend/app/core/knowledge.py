"""
Knowledge Base — PHANTOM's Learning Engine

Learns from every scan to improve future decisions:
1. Records which vuln types are found on which tech stacks
2. Tracks which payloads work and which don't
3. Identifies false positive patterns
4. Builds per-technology attack strategies
5. Provides context to the AI agent for smarter decisions
"""
import logging
from collections import defaultdict

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern, AgentDecision
from app.models.vulnerability import Vulnerability, VulnType, Severity
from app.models.scan import Scan, ScanStatus
from app.models.target import Target

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Interface to PHANTOM's accumulated knowledge."""

    async def get_tech_vuln_insights(self, db: AsyncSession, technologies: list[str]) -> dict:
        """Get vulnerability insights for detected technologies.
        Returns which vuln types are most likely based on past experience."""
        if not technologies:
            return {"recommendations": [], "confidence": 0.0}

        insights = {}
        for tech in technologies[:10]:
            tech_lower = tech.lower()
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "tech_vuln_correlation",
                        KnowledgePattern.technology == tech_lower,
                        KnowledgePattern.confidence > 0.3,
                    )
                ).order_by(KnowledgePattern.confidence.desc())
            )
            patterns = result.scalars().all()
            for p in patterns:
                vt = p.vuln_type
                data = p.pattern_data or {}
                if vt not in insights or data.get("success_rate", 0) > insights[vt].get("success_rate", 0):
                    insights[vt] = {
                        "vuln_type": vt,
                        "success_rate": data.get("success_rate", 0),
                        "sample_count": p.sample_count,
                        "confidence": p.confidence,
                        "technology": tech_lower,
                    }

        sorted_insights = sorted(insights.values(), key=lambda x: x["success_rate"], reverse=True)
        return {
            "recommendations": sorted_insights[:10],
            "confidence": sorted_insights[0]["confidence"] if sorted_insights else 0.0,
        }

    async def get_effective_payloads(self, db: AsyncSession, vuln_type: str, technology: str = None) -> list[dict]:
        """Get payloads that have historically been effective (from PATT, nuclei, scans)."""
        query = select(KnowledgePattern).where(
            and_(
                KnowledgePattern.pattern_type.in_(["effective_payload", "nuclei_live"]),
                KnowledgePattern.vuln_type == vuln_type,
                KnowledgePattern.confidence > 0.4,
            )
        )
        if technology:
            query = query.where(KnowledgePattern.technology == technology.lower())

        query = query.order_by(KnowledgePattern.confidence.desc()).limit(20)
        result = await db.execute(query)
        patterns = result.scalars().all()

        results = []
        for p in patterns:
            data = p.pattern_data or {}
            # For nuclei_live patterns, paths with injection markers count as payloads
            nuclei_paths = data.get("paths", []) if p.pattern_type == "nuclei_live" else []
            has_payload = data.get("payload") or data.get("payloads") or nuclei_paths

            if not has_payload:
                continue
            entry = {
                "payload": data.get("payload", nuclei_paths[0] if nuclei_paths else ""),
                "success_count": p.sample_count,
                "confidence": p.confidence,
                "technology": p.technology,
            }
            # Include full payload list if available (from PayloadsAllTheThings, nuclei etc.)
            all_payloads = data.get("payloads", [])
            if nuclei_paths and not all_payloads:
                all_payloads = nuclei_paths
            if all_payloads:
                entry["payloads"] = all_payloads
            results.append(entry)
        return results

    async def get_false_positive_patterns(self, db: AsyncSession, vuln_type: str = None) -> list[dict]:
        """Get known false positive patterns to avoid."""
        query = select(KnowledgePattern).where(
            KnowledgePattern.pattern_type == "false_positive",
        )
        if vuln_type:
            query = query.where(KnowledgePattern.vuln_type == vuln_type)

        result = await db.execute(query.limit(50))
        patterns = result.scalars().all()

        results = []
        for p in patterns:
            data = p.pattern_data or {}
            # Each pattern may store multiple indicators in the "indicators" list
            indicators = data.get("indicators", [])
            if not indicators:
                ind = data.get("indicator", "")
                indicators = [ind] if ind else []
            for indicator in indicators:
                results.append({
                    "indicator": indicator,
                    "vuln_type": p.vuln_type,
                    "false_count": p.sample_count,
                })
        return results

    async def get_best_strategy(self, db: AsyncSession, technologies: list[str]) -> dict | None:
        """Get the best scan strategy for a technology profile."""
        for tech in technologies:
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "scan_strategy",
                        KnowledgePattern.technology == tech.lower(),
                        KnowledgePattern.confidence > 0.5,
                    )
                ).order_by(KnowledgePattern.confidence.desc()).limit(1)
            )
            pattern = result.scalar_one_or_none()
            if pattern:
                return pattern.pattern_data
        return None

    async def get_past_decisions(self, db: AsyncSession, technologies: list[str], limit: int = 20) -> list[dict]:
        """Get past agent decisions for similar technology contexts."""
        # Find decisions that were productive
        result = await db.execute(
            select(AgentDecision).where(
                AgentDecision.was_productive == True,
            ).order_by(AgentDecision.created_at.desc()).limit(limit * 3)
        )
        decisions = result.scalars().all()

        # Filter to decisions with matching tech context
        relevant = []
        tech_set = set(t.lower() for t in technologies)
        for d in decisions:
            ctx = d.context_summary or {}
            decision_techs = set(str(t).lower() for t in ctx.get("technologies", []))
            overlap = tech_set & decision_techs
            if overlap:
                relevant.append({
                    "action": d.action,
                    "reasoning": d.reasoning,
                    "result": d.result_summary,
                    "tech_overlap": list(overlap),
                })

        return relevant[:limit]

    async def get_h1_insights(self, db: AsyncSession, vuln_type: str = None) -> list[dict]:
        """Get insights learned from HackerOne report outcomes."""
        query = select(KnowledgePattern).where(
            KnowledgePattern.pattern_type == "h1_insight",
            KnowledgePattern.confidence > 0.3,
        )
        if vuln_type:
            query = query.where(KnowledgePattern.vuln_type == vuln_type)
        query = query.order_by(KnowledgePattern.confidence.desc()).limit(20)
        result = await db.execute(query)
        patterns = result.scalars().all()
        return [
            {
                "vuln_type": p.vuln_type,
                "insight": p.pattern_data.get("insight", ""),
                "recommendation": p.pattern_data.get("recommendation", ""),
                "bounty_range": p.pattern_data.get("bounty_range", ""),
                "confidence": p.confidence,
                "sample_count": p.sample_count,
            }
            for p in patterns if p.pattern_data
        ]

    async def get_summary_for_agent(self, db: AsyncSession, context: dict) -> dict:
        """Build a comprehensive knowledge summary for the AI agent."""
        technologies = list((context.get("technologies") or {}).get("summary", {}).keys())

        tech_insights = await self.get_tech_vuln_insights(db, technologies)
        past_decisions = await self.get_past_decisions(db, technologies, limit=10)
        fp_patterns = await self.get_false_positive_patterns(db)
        h1_insights = await self.get_h1_insights(db)

        # Get overall stats
        total_scans = (await db.execute(
            select(func.count(Scan.id)).where(Scan.status == ScanStatus.COMPLETED)
        )).scalar() or 0

        total_vulns = (await db.execute(
            select(func.count(Vulnerability.id))
        )).scalar() or 0

        total_patterns = (await db.execute(
            select(func.count(KnowledgePattern.id))
        )).scalar() or 0

        return {
            "experience": {
                "total_scans_completed": total_scans,
                "total_vulns_found": total_vulns,
                "knowledge_patterns": total_patterns,
            },
            "tech_vuln_insights": tech_insights,
            "past_successful_decisions": past_decisions[:5],
            "false_positive_patterns": fp_patterns[:10],
            "h1_insights": h1_insights[:10],
            "technologies_detected": technologies,
        }

    # ---- Learning Methods ----

    async def learn_from_scan(self, db: AsyncSession, scan_id: str):
        """Post-scan learning: extract patterns from completed scan."""
        # Load scan and its vulnerabilities
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan or scan.status != ScanStatus.COMPLETED:
            return

        target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_result.scalar_one_or_none()
        if not target:
            return

        vulns_result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulns = vulns_result.scalars().all()

        technologies = list((target.technologies or {}).get("summary", {}).keys())
        tech_lower = [t.lower() for t in technologies]

        # 1. Learn tech → vulnerability correlations
        await self._learn_tech_vuln_correlation(db, tech_lower, vulns)

        # 2. Learn effective payloads
        await self._learn_effective_payloads(db, tech_lower, vulns)

        # 3. Learn from agent decisions (mark productivity)
        await self._evaluate_decisions(db, scan_id, vulns)

        # 4. Learn scan strategies (which approaches work for which tech)
        try:
            await self.learn_scan_strategy(db, scan_id)
        except Exception as e:
            logger.warning(f"Strategy learning error (non-fatal): {e}")

        # 5. Auto-decay old patterns to keep knowledge fresh
        try:
            await self.decay_old_patterns(db, days_threshold=30)
        except Exception as e:
            logger.warning(f"Knowledge decay error (non-fatal): {e}")

        await db.commit()
        logger.info(f"Knowledge: learned from scan {scan_id} ({len(vulns)} vulns, {len(tech_lower)} techs)")

    async def _learn_tech_vuln_correlation(self, db: AsyncSession, technologies: list[str], vulns):
        """Update tech → vuln_type success rates."""
        vuln_types = defaultdict(int)
        for v in vulns:
            vuln_types[v.vuln_type.value] += 1

        for tech in technologies:
            for vt, count in vuln_types.items():
                # Find or create pattern
                result = await db.execute(
                    select(KnowledgePattern).where(
                        and_(
                            KnowledgePattern.pattern_type == "tech_vuln_correlation",
                            KnowledgePattern.technology == tech,
                            KnowledgePattern.vuln_type == vt,
                        )
                    )
                )
                pattern = result.scalar_one_or_none()

                if pattern:
                    # Update existing
                    data = pattern.pattern_data or {}
                    old_scans = data.get("scans_tested", 1)
                    old_found = data.get("vulns_found", 0)
                    new_scans = old_scans + 1
                    new_found = old_found + count
                    pattern.pattern_data = {
                        "success_rate": new_found / new_scans,
                        "vulns_found": new_found,
                        "scans_tested": new_scans,
                    }
                    pattern.sample_count = new_scans
                    pattern.confidence = min(0.95, 0.3 + (new_scans * 0.05))
                else:
                    # Create new
                    db.add(KnowledgePattern(
                        pattern_type="tech_vuln_correlation",
                        technology=tech,
                        vuln_type=vt,
                        pattern_data={
                            "success_rate": float(count),
                            "vulns_found": count,
                            "scans_tested": 1,
                        },
                        confidence=0.35,
                        sample_count=1,
                    ))

            # Also record "no vuln found" for types NOT found
            # (to lower their priority over time)
            all_vt = {v.value for v in VulnType}
            not_found = all_vt - set(vuln_types.keys())
            for vt in not_found:
                result = await db.execute(
                    select(KnowledgePattern).where(
                        and_(
                            KnowledgePattern.pattern_type == "tech_vuln_correlation",
                            KnowledgePattern.technology == tech,
                            KnowledgePattern.vuln_type == vt,
                        )
                    )
                )
                pattern = result.scalar_one_or_none()
                if pattern:
                    data = pattern.pattern_data or {}
                    old_scans = data.get("scans_tested", 1)
                    pattern.pattern_data = {
                        **data,
                        "scans_tested": old_scans + 1,
                        "success_rate": data.get("vulns_found", 0) / (old_scans + 1),
                    }
                    pattern.sample_count = old_scans + 1

    async def _learn_effective_payloads(self, db: AsyncSession, technologies: list[str], vulns):
        """Record payloads that successfully found vulnerabilities."""
        for v in vulns:
            payload = v.payload_used
            if not payload or len(payload) < 3:
                continue

            tech = technologies[0] if technologies else "unknown"
            vt = v.vuln_type.value

            # Find or create
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "effective_payload",
                        KnowledgePattern.vuln_type == vt,
                        KnowledgePattern.technology == tech,
                    )
                ).limit(1)
            )
            existing = result.scalar_one_or_none()

            if existing:
                data = existing.pattern_data or {}
                payloads = data.get("payloads", [])
                if payload not in payloads:
                    payloads.append(payload)
                    payloads = payloads[-50:]  # Keep last 50
                existing.pattern_data = {
                    "payload": payloads[0],
                    "payloads": payloads,
                }
                existing.sample_count += 1
                existing.confidence = min(0.95, existing.confidence + 0.05)
            else:
                db.add(KnowledgePattern(
                    pattern_type="effective_payload",
                    technology=tech,
                    vuln_type=vt,
                    pattern_data={
                        "payload": payload,
                        "payloads": [payload],
                    },
                    confidence=0.4,
                    sample_count=1,
                ))

    async def _evaluate_decisions(self, db: AsyncSession, scan_id: str, vulns):
        """Mark agent decisions as productive or not."""
        result = await db.execute(
            select(AgentDecision).where(AgentDecision.scan_id == scan_id)
        )
        decisions = result.scalars().all()

        vuln_types_found = {v.vuln_type.value for v in vulns}
        vuln_urls = {v.url for v in vulns}

        for d in decisions:
            action = d.action or ""
            result_data = d.result_summary or {}

            # Decision was productive if the module it ran found something
            if action.startswith("run_module:"):
                module = action.split(":", 1)[1]
                module_found = result_data.get("vulns_found", 0) > 0
                d.was_productive = module_found
            elif action.startswith("deep_dive:"):
                d.was_productive = result_data.get("vulns_found", 0) > 0
            elif action == "stop":
                d.was_productive = True  # Stopping is always valid if we had vulns

    async def learn_scan_strategy(self, db: AsyncSession, scan_id: str):
        """Learn which scan strategies (module sequences) produce results.
        Called after learn_from_scan to record what worked."""
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            return

        target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_result.scalar_one_or_none()
        if not target:
            return

        technologies = list((target.technologies or {}).get("summary", {}).keys())
        if not technologies:
            return

        vulns_result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulns = vulns_result.scalars().all()

        # Get agent decisions for this scan
        decisions_result = await db.execute(
            select(AgentDecision).where(AgentDecision.scan_id == scan_id)
        )
        decisions = decisions_result.scalars().all()

        productive_actions = [d.action for d in decisions if d.was_productive]
        all_actions = [d.action for d in decisions]

        # Build strategy summary
        strategy_data = {
            "scan_type": scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type),
            "productive_actions": productive_actions,
            "all_actions": all_actions,
            "vulns_found": len(vulns),
            "vuln_types": list(set(v.vuln_type.value for v in vulns)),
            "success_rate": len(productive_actions) / max(len(all_actions), 1),
        }

        for tech in technologies[:3]:
            tech_lower = tech.lower()
            result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "scan_strategy",
                        KnowledgePattern.technology == tech_lower,
                    )
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                data = existing.pattern_data or {}
                # Merge productive actions
                old_productive = set(data.get("productive_actions", []))
                old_productive.update(productive_actions)
                old_scans = data.get("scans_tested", 1)
                old_vulns = data.get("total_vulns", 0)
                new_scans = old_scans + 1
                new_vulns = old_vulns + len(vulns)
                existing.pattern_data = {
                    **data,
                    "productive_actions": list(old_productive),
                    "scans_tested": new_scans,
                    "total_vulns": new_vulns,
                    "avg_vulns_per_scan": new_vulns / new_scans,
                    "success_rate": new_vulns / max(new_scans, 1),
                    "last_vuln_types": strategy_data["vuln_types"],
                }
                existing.sample_count = new_scans
                existing.confidence = min(0.95, 0.3 + (new_scans * 0.05))
            else:
                db.add(KnowledgePattern(
                    pattern_type="scan_strategy",
                    technology=tech_lower,
                    pattern_data=strategy_data,
                    confidence=0.35,
                    sample_count=1,
                ))

    async def decay_old_patterns(self, db: AsyncSession, days_threshold: int = 30):
        """Exponential decay with pattern-type-aware rates and sample-count resistance.
        Called periodically to keep knowledge base fresh."""
        from datetime import datetime, timedelta
        import math

        cutoff = datetime.utcnow() - timedelta(days=days_threshold)

        result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.updated_at < cutoff,
                KnowledgePattern.confidence > 0.15,
            )
        )
        patterns = result.scalars().all()

        # Pattern types that stay relevant longer get slower decay (higher half-life)
        HALF_LIFE_DAYS = {
            "effective_payload": 90,   # Payloads stay valid long
            "nuclei_live": 90,
            "nuclei_template": 120,
            "cve_live": 60,
            "cve_exploit": 60,
            "owasp_test": 120,
            "ctf_technique": 120,
            "discovery_pattern": 90,
            "tech_vuln_correlation": 60,
            "scan_strategy": 45,
            "scan_feedback": 45,
            "scan_insight": 45,
            "h1_report": 60,
            "h1_insight": 60,
            "disclosed_report": 90,
            "endpoint_pattern": 45,
            "false_positive": 30,      # FPs go stale fast
            "waf_bypass": 30,
            "waf_evasion": 30,
            "ai_mutation": 45,
            "payload_mutation": 45,
        }
        DEFAULT_HALF_LIFE = 45

        now = datetime.utcnow()
        decayed = 0
        deleted = 0
        for p in patterns:
            age_days = (now - p.updated_at).days
            half_life = HALF_LIFE_DAYS.get(p.pattern_type, DEFAULT_HALF_LIFE)

            # High sample count = more resistance to decay (up to 2x half-life)
            sample_boost = min(2.0, 1.0 + math.log2(max(1, p.sample_count)) * 0.15)
            effective_half_life = half_life * sample_boost

            # Exponential decay: conf * 0.5^(age/half_life)
            decay_factor = 0.5 ** (age_days / effective_half_life)
            new_conf = p.confidence * decay_factor

            if new_conf < 0.15 or (p.sample_count <= 1 and new_conf < 0.25):
                await db.delete(p)
                deleted += 1
            elif new_conf < p.confidence - 0.01:  # Only update if meaningful change
                p.confidence = round(new_conf, 4)
                decayed += 1

        if decayed or deleted:
            await db.commit()
            logger.info(f"Knowledge decay: {decayed} decayed, {deleted} deleted (exponential, type-aware)")

        return {"decayed": decayed, "deleted": deleted}

    async def record_successful_payload(self, db: AsyncSession, vuln_type: str,
                                        payload: str, url: str, technology: str = None):
        """Record a payload that successfully exploited a vulnerability.
        Boosts existing pattern or creates new effective_payload entry."""
        if not payload or len(payload) < 3:
            return

        # Try to find existing pattern with same payload
        result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "effective_payload",
                    KnowledgePattern.vuln_type == vuln_type,
                    KnowledgePattern.pattern_data["payload"].astext == payload,
                )
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.sample_count += 1
            existing.confidence = min(0.99, existing.confidence + 0.05)
            urls = (existing.pattern_data or {}).get("confirmed_urls", [])
            if url not in urls:
                urls.append(url)
                urls = urls[-10:]  # Keep last 10
            existing.pattern_data = {**(existing.pattern_data or {}), "confirmed_urls": urls}
        else:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            db.add(KnowledgePattern(
                pattern_type="effective_payload",
                vuln_type=vuln_type,
                technology=technology,
                pattern_data={
                    "payload": payload,
                    "source": "exploit_confirmed",
                    "confirmed_urls": [url],
                    "domain": domain,
                },
                confidence=0.8,
                sample_count=1,
            ))

        try:
            await db.flush()
        except Exception as e:
            logger.debug(f"Failed to record successful payload: {e}")

    async def record_false_positive(self, db: AsyncSession, vuln_type: str, indicator: str):
        """Record a false positive pattern for future avoidance."""
        result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "false_positive",
                    KnowledgePattern.vuln_type == vuln_type,
                )
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            data = existing.pattern_data or {}
            indicators = data.get("indicators", [])
            if indicator not in indicators:
                indicators.append(indicator)
            existing.pattern_data = {"indicator": indicators[0], "indicators": indicators}
            existing.sample_count += 1
            existing.confidence = min(0.95, existing.confidence + 0.05)
        else:
            db.add(KnowledgePattern(
                pattern_type="false_positive",
                vuln_type=vuln_type,
                pattern_data={"indicator": indicator, "indicators": [indicator]},
                confidence=0.4,
                sample_count=1,
            ))
        await db.commit()
