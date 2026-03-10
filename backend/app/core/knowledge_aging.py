"""
Knowledge Aging System

Manages the lifecycle of learned patterns:
- Decay confidence of stale patterns over time
- Delete weak, outdated patterns
- Deduplicate overlapping patterns
- Generate health reports on the knowledge base
"""
import logging
from datetime import datetime, timedelta

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


class KnowledgeAging:
    """Manages knowledge pattern aging, cleanup, and health reporting."""

    async def decay_confidence(self, db: AsyncSession) -> dict:
        """
        Apply time-based confidence decay to all knowledge patterns.

        Rules (applied in priority order):
        - Age > 90 days + confidence < 0.3 → DELETE (stale and weak)
        - Age > 90 days + confidence >= 0.3 → confidence *= 0.9
        - Age > 60 days + sample_count <= 1 → confidence *= 0.85
        - Age > 30 days + sample_count <= 1 → confidence *= 0.95
        - Recently updated (< 30 days) → no change
        """
        now = datetime.utcnow()
        result = await db.execute(select(KnowledgePattern))
        patterns = result.scalars().all()

        stats = {"decayed": 0, "deleted": 0, "unchanged": 0, "total": len(patterns)}
        to_delete = []

        for pattern in patterns:
            updated = pattern.updated_at or pattern.created_at or now
            age = now - updated
            age_days = age.total_seconds() / 86400

            if age_days > 90 and pattern.confidence < 0.3:
                # Stale and weak — mark for deletion
                to_delete.append(pattern.id)
                stats["deleted"] += 1
            elif age_days > 90:
                # Old but still has some confidence — gentle decay
                pattern.confidence *= 0.9
                pattern.confidence = round(pattern.confidence, 4)
                stats["decayed"] += 1
            elif age_days > 60 and (pattern.sample_count or 0) <= 1:
                # Unconfirmed and aging
                pattern.confidence *= 0.85
                pattern.confidence = round(pattern.confidence, 4)
                stats["decayed"] += 1
            elif age_days > 30 and (pattern.sample_count or 0) <= 1:
                # Slight decay for unconfirmed
                pattern.confidence *= 0.95
                pattern.confidence = round(pattern.confidence, 4)
                stats["decayed"] += 1
            else:
                stats["unchanged"] += 1

        # Delete stale patterns
        if to_delete:
            await db.execute(
                delete(KnowledgePattern).where(KnowledgePattern.id.in_(to_delete))
            )

        await db.commit()

        logger.info(
            f"Knowledge aging: decayed={stats['decayed']}, "
            f"deleted={stats['deleted']}, unchanged={stats['unchanged']}"
        )
        return stats

    async def cleanup_duplicates(self, db: AsyncSession) -> dict:
        """
        Find and merge duplicate knowledge patterns.

        Duplicates = same pattern_type + vuln_type + technology with >80% payload overlap.
        Merge strategy: keep highest confidence, sum sample_counts, delete duplicate.
        """
        stats = {"merged": 0, "deleted": 0}

        # Group patterns by (pattern_type, vuln_type, technology)
        result = await db.execute(select(KnowledgePattern))
        patterns = result.scalars().all()

        # Build groups
        groups: dict[tuple, list[KnowledgePattern]] = {}
        for p in patterns:
            key = (p.pattern_type, p.vuln_type or "", p.technology or "")
            groups.setdefault(key, []).append(p)

        to_delete = set()

        for key, group in groups.items():
            if len(group) < 2:
                continue

            # Compare each pair
            for i in range(len(group)):
                if group[i].id in to_delete:
                    continue
                for j in range(i + 1, len(group)):
                    if group[j].id in to_delete:
                        continue

                    overlap = self._calculate_overlap(
                        group[i].pattern_data, group[j].pattern_data
                    )
                    if overlap >= 0.8:
                        # Merge: keep the one with higher confidence
                        keeper, dupe = (
                            (group[i], group[j])
                            if group[i].confidence >= group[j].confidence
                            else (group[j], group[i])
                        )
                        keeper.sample_count = (keeper.sample_count or 0) + (dupe.sample_count or 0)
                        keeper.updated_at = datetime.utcnow()
                        to_delete.add(dupe.id)
                        stats["merged"] += 1

        # Delete duplicates
        if to_delete:
            await db.execute(
                delete(KnowledgePattern).where(KnowledgePattern.id.in_(list(to_delete)))
            )
            stats["deleted"] = len(to_delete)

        await db.commit()

        logger.info(
            f"Knowledge dedup: merged={stats['merged']}, deleted={stats['deleted']}"
        )
        return stats

    async def get_health_report(self, db: AsyncSession) -> dict:
        """Generate a comprehensive knowledge base health report."""
        now = datetime.utcnow()

        # Total patterns
        total = (await db.execute(
            select(func.count(KnowledgePattern.id))
        )).scalar() or 0

        # Patterns by type
        type_result = await db.execute(
            select(
                KnowledgePattern.pattern_type,
                func.count(KnowledgePattern.id),
            ).group_by(KnowledgePattern.pattern_type)
        )
        by_type = {pt: count for pt, count in type_result.all()}

        # Average confidence
        avg_conf = (await db.execute(
            select(func.avg(KnowledgePattern.confidence))
        )).scalar() or 0.0

        # Stale patterns (>90 days, never updated differently from created)
        stale_cutoff = now - timedelta(days=90)
        stale_count = (await db.execute(
            select(func.count(KnowledgePattern.id)).where(
                KnowledgePattern.updated_at <= stale_cutoff
            )
        )).scalar() or 0

        # Top 10 most confident
        top_result = await db.execute(
            select(KnowledgePattern)
            .order_by(KnowledgePattern.confidence.desc())
            .limit(10)
        )
        top_patterns = [
            {
                "id": p.id,
                "pattern_type": p.pattern_type,
                "technology": p.technology,
                "vuln_type": p.vuln_type,
                "confidence": round(p.confidence, 4),
                "sample_count": p.sample_count,
                "updated_at": p.updated_at.isoformat() + "Z" if p.updated_at else None,
            }
            for p in top_result.scalars().all()
        ]

        # Weakest 10 patterns (lowest confidence, still active)
        weak_result = await db.execute(
            select(KnowledgePattern)
            .order_by(KnowledgePattern.confidence.asc())
            .limit(10)
        )
        weak_patterns = [
            {
                "id": p.id,
                "pattern_type": p.pattern_type,
                "technology": p.technology,
                "vuln_type": p.vuln_type,
                "confidence": round(p.confidence, 4),
                "sample_count": p.sample_count,
                "updated_at": p.updated_at.isoformat() + "Z" if p.updated_at else None,
            }
            for p in weak_result.scalars().all()
        ]

        # Coverage gaps: vuln_types with <3 patterns
        vuln_type_result = await db.execute(
            select(
                KnowledgePattern.vuln_type,
                func.count(KnowledgePattern.id),
            )
            .where(KnowledgePattern.vuln_type.isnot(None))
            .group_by(KnowledgePattern.vuln_type)
        )
        coverage_gaps = [
            {"vuln_type": vt, "pattern_count": count}
            for vt, count in vuln_type_result.all()
            if count < 3
        ]

        return {
            "total_patterns": total,
            "patterns_by_type": by_type,
            "average_confidence": round(float(avg_conf), 4),
            "stale_patterns": stale_count,
            "top_patterns": top_patterns,
            "weak_patterns": weak_patterns,
            "coverage_gaps": coverage_gaps,
        }

    @staticmethod
    def _calculate_overlap(data_a: dict, data_b: dict) -> float:
        """
        Calculate overlap between two pattern_data dicts.

        Compares all string values (especially payloads) for similarity.
        Returns a float 0.0-1.0 representing overlap percentage.
        """
        if not data_a or not data_b:
            return 0.0

        # Extract all string values from both dicts for comparison
        def extract_strings(d: dict) -> set[str]:
            strings = set()
            for k, v in d.items():
                if isinstance(v, str):
                    strings.add(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            strings.add(item)
                elif isinstance(v, dict):
                    strings.update(extract_strings(v))
            return strings

        strings_a = extract_strings(data_a)
        strings_b = extract_strings(data_b)

        if not strings_a and not strings_b:
            # Compare keys as fallback
            keys_a = set(data_a.keys())
            keys_b = set(data_b.keys())
            if not keys_a and not keys_b:
                return 1.0
            union = keys_a | keys_b
            return len(keys_a & keys_b) / len(union) if union else 0.0

        if not strings_a or not strings_b:
            return 0.0

        union = strings_a | strings_b
        intersection = strings_a & strings_b
        return len(intersection) / len(union) if union else 0.0
