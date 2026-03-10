"""
Program Intelligence Engine.

Collects, scores, and recommends HackerOne bug bounty programs.
Uses GraphQL for program data and hacktivity for bounty intelligence.
"""
import logging
from datetime import datetime

import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bounty_program import BountyProgram
from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)

H1_GRAPHQL = "https://hackerone.com/graphql"

PROGRAMS_QUERY = """
query($cursor: String) {
  teams(
    first: 25,
    after: $cursor,
    where: {
      _and: [
        { offers_bounties: { _eq: true } },
        { state: { _eq: public_mode } }
      ]
    }
  ) {
    edges {
      node {
        handle
        name
        url
        offers_bounties
        launched_at
        allows_bounty_splitting
        base_bounty
        currency
        resolved_report_count
        structured_scopes(first: 20) {
          edges {
            node {
              asset_identifier
              asset_type
              eligible_for_bounty
              eligible_for_submission
              max_severity
            }
          }
        }
      }
      cursor
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


class ProgramIntel:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.client = httpx.AsyncClient(timeout=30.0)

    async def collect_programs(self, pages: int = 10) -> dict:
        """Fetch bounty programs from H1 GraphQL and store in DB."""
        stats = {"fetched": 0, "created": 0, "updated": 0, "errors": 0}
        cursor = None

        for page in range(pages):
            try:
                resp = await self.client.post(
                    H1_GRAPHQL,
                    json={"query": PROGRAMS_QUERY, "variables": {"cursor": cursor}},
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()

                teams = data.get("data", {}).get("teams", {})
                edges = teams.get("edges", [])
                if not edges:
                    break

                for edge in edges:
                    node = edge["node"]
                    stats["fetched"] += 1

                    scopes = [
                        {
                            "asset": s["node"]["asset_identifier"],
                            "type": s["node"]["asset_type"],
                            "bounty_eligible": s["node"]["eligible_for_bounty"],
                            "max_severity": s["node"]["max_severity"],
                        }
                        for s in node.get("structured_scopes", {}).get("edges", [])
                    ]

                    existing = await self.db.execute(
                        select(BountyProgram).where(
                            BountyProgram.handle == node["handle"]
                        )
                    )
                    program = existing.scalar_one_or_none()

                    resolved = node.get("resolved_report_count") or 0

                    if program:
                        program.name = node["name"]
                        program.base_bounty = node.get("base_bounty")
                        program.currency = node.get("currency", "usd")
                        program.resolved_report_count = resolved
                        program.scope = scopes
                        program.updated_at = datetime.utcnow()
                        stats["updated"] += 1
                    else:
                        program = BountyProgram(
                            handle=node["handle"],
                            name=node["name"],
                            url=node.get("url", f"https://hackerone.com/{node['handle']}"),
                            offers_bounties=node.get("offers_bounties", True),
                            base_bounty=node.get("base_bounty"),
                            currency=node.get("currency", "usd"),
                            launched_at=node.get("launched_at"),
                            resolved_report_count=resolved,
                            scope=scopes,
                        )
                        self.db.add(program)
                        stats["created"] += 1

                page_info = teams.get("pageInfo", {})
                if not page_info.get("hasNextPage"):
                    break
                cursor = page_info.get("endCursor")

            except Exception as e:
                logger.error(f"Program fetch page {page} failed: {e}")
                stats["errors"] += 1
                break

        await self.db.commit()
        logger.info(f"Program collection: {stats}")
        return stats

    async def enrich_from_hacktivity(self) -> dict:
        """Enrich programs with bounty intelligence from collected hacktivity data."""
        stats = {"programs_enriched": 0}

        # Get all h1_report patterns grouped by program
        result = await self.db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "h1_report"
            )
        )
        reports = result.scalars().all()

        # Group by program
        program_data: dict[str, list] = {}
        for r in reports:
            prog = r.pattern_data.get("program")
            if prog:
                program_data.setdefault(prog, []).append(r)

        for handle, h1_reports in program_data.items():
            program_result = await self.db.execute(
                select(BountyProgram).where(BountyProgram.handle == handle)
            )
            program = program_result.scalar_one_or_none()
            if not program:
                continue

            bounties = [
                r.pattern_data.get("bounty")
                for r in h1_reports
                if r.pattern_data.get("bounty")
            ]
            vuln_types: dict[str, int] = {}
            reporters: dict[str, int] = {}

            for r in h1_reports:
                if r.vuln_type:
                    vuln_types[r.vuln_type] = vuln_types.get(r.vuln_type, 0) + 1
                reporter = r.pattern_data.get("reporter")
                if reporter:
                    reporters[reporter] = reporters.get(reporter, 0) + 1

            if bounties:
                program.avg_bounty = sum(bounties) / len(bounties)
                program.max_bounty = max(bounties)
                program.min_bounty = min(bounties)
                program.total_paid = sum(bounties)
                program.bounty_reports_count = len(bounties)

            if vuln_types:
                program.known_vuln_types = vuln_types

            if reporters:
                top = sorted(reporters.items(), key=lambda x: x[1], reverse=True)[:10]
                program.top_reporters = [
                    {"username": u, "reports": c} for u, c in top
                ]

            program.updated_at = datetime.utcnow()
            stats["programs_enriched"] += 1

        await self.db.commit()
        logger.info(f"Program enrichment: {stats}")
        return stats

    async def compute_scores(self) -> dict:
        """Compute ROI and difficulty scores for all programs."""
        stats = {"scored": 0}

        result = await self.db.execute(
            select(BountyProgram).where(BountyProgram.is_active == True)
        )
        programs = result.scalars().all()

        for program in programs:
            # ROI score: higher avg_bounty and more resolved reports = better
            avg_b = program.avg_bounty or program.base_bounty or 0
            resolved = program.resolved_report_count or 0

            # Programs with many resolved reports are more active = more chance
            activity_factor = min(resolved / 100, 1.0) if resolved else 0.1

            # Scope size factor: more assets = more attack surface
            scope_size = len(program.scope or [])
            scope_factor = min(scope_size / 10, 1.0) if scope_size else 0.1

            # Base ROI = avg_bounty * activity * scope
            program.roi_score = round(avg_b * activity_factor * scope_factor, 2)

            # Difficulty: high resolved_report_count = well-tested = harder to find new bugs
            # But also means the program is responsive
            if resolved > 500:
                program.difficulty_score = 0.8
            elif resolved > 200:
                program.difficulty_score = 0.6
            elif resolved > 50:
                program.difficulty_score = 0.4
            else:
                program.difficulty_score = 0.2

            # Adjust difficulty based on our past performance
            if program.our_reports_count > 0:
                acceptance_rate = program.our_accepted_count / program.our_reports_count
                if acceptance_rate > 0.5:
                    program.difficulty_score = max(0.1, program.difficulty_score - 0.2)
                elif acceptance_rate < 0.2:
                    program.difficulty_score = min(1.0, program.difficulty_score + 0.2)

            stats["scored"] += 1

        await self.db.commit()
        logger.info(f"Program scoring: {stats}")
        return stats

    async def get_recommendations(self, limit: int = 10) -> list[dict]:
        """Get top recommended programs to scan."""
        result = await self.db.execute(
            select(BountyProgram)
            .where(
                BountyProgram.is_active == True,
                BountyProgram.offers_bounties == True,
                BountyProgram.roi_score.isnot(None),
            )
            .order_by(BountyProgram.roi_score.desc())
            .limit(limit)
        )
        programs = result.scalars().all()

        recommendations = []
        for p in programs:
            # Build reasoning
            reasons = []
            if (p.avg_bounty or 0) > 500:
                reasons.append(f"high avg bounty (${p.avg_bounty:.0f})")
            if (p.resolved_report_count or 0) > 100:
                reasons.append(f"active program ({p.resolved_report_count} resolved)")
            if len(p.scope or []) > 5:
                reasons.append(f"large scope ({len(p.scope)} assets)")
            if (p.difficulty_score or 0) < 0.5:
                reasons.append("lower difficulty")
            if p.known_vuln_types:
                top_vuln = max(p.known_vuln_types, key=p.known_vuln_types.get)
                reasons.append(f"common: {top_vuln}")

            web_assets = [
                s["asset"] for s in (p.scope or [])
                if s.get("type") == "URL" and s.get("bounty_eligible")
            ]

            recommendations.append({
                "handle": p.handle,
                "name": p.name,
                "url": p.url,
                "roi_score": p.roi_score,
                "difficulty": p.difficulty_score,
                "avg_bounty": p.avg_bounty,
                "base_bounty": p.base_bounty,
                "resolved_reports": p.resolved_report_count,
                "scope_size": len(p.scope or []),
                "web_assets": web_assets[:10],
                "known_vuln_types": p.known_vuln_types,
                "reasons": reasons,
                "our_stats": {
                    "reports": p.our_reports_count,
                    "accepted": p.our_accepted_count,
                    "duplicates": p.our_duplicate_count,
                    "bounty_earned": p.our_total_bounty,
                },
            })

        return recommendations

    async def get_program_detail(self, handle: str) -> dict | None:
        """Get detailed intelligence for a specific program."""
        result = await self.db.execute(
            select(BountyProgram).where(BountyProgram.handle == handle)
        )
        program = result.scalar_one_or_none()
        if not program:
            return None

        # Get related h1 reports
        reports_result = await self.db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.technology == handle,
            ).limit(50)
        )
        h1_reports = reports_result.scalars().all()

        disclosed_reports = [
            {
                "title": r.pattern_data.get("title"),
                "severity": r.pattern_data.get("severity"),
                "bounty": r.pattern_data.get("bounty"),
                "cwe": r.pattern_data.get("cwe"),
                "url": r.pattern_data.get("url"),
            }
            for r in h1_reports
            if r.pattern_data.get("disclosed")
        ]

        return {
            "handle": program.handle,
            "name": program.name,
            "url": program.url,
            "base_bounty": program.base_bounty,
            "avg_bounty": program.avg_bounty,
            "max_bounty": program.max_bounty,
            "total_paid": program.total_paid,
            "resolved_reports": program.resolved_report_count,
            "roi_score": program.roi_score,
            "difficulty": program.difficulty_score,
            "scope": program.scope,
            "known_vuln_types": program.known_vuln_types,
            "top_reporters": program.top_reporters,
            "disclosed_reports": disclosed_reports,
            "our_stats": {
                "reports": program.our_reports_count,
                "accepted": program.our_accepted_count,
                "duplicates": program.our_duplicate_count,
                "bounty_earned": program.our_total_bounty,
                "last_scanned": program.last_scanned_at.isoformat() if program.last_scanned_at else None,
            },
            "notes": program.notes,
            "priority": program.priority,
        }

    async def get_dashboard(self) -> dict:
        """Get overall program intelligence dashboard."""
        total = await self.db.execute(
            select(func.count()).select_from(BountyProgram)
        )
        active = await self.db.execute(
            select(func.count()).where(
                BountyProgram.is_active == True,
                BountyProgram.offers_bounties == True,
            )
        )
        with_bounty = await self.db.execute(
            select(func.count()).where(BountyProgram.avg_bounty.isnot(None))
        )
        scored = await self.db.execute(
            select(func.count()).where(BountyProgram.roi_score.isnot(None))
        )
        avg_roi = await self.db.execute(
            select(func.avg(BountyProgram.roi_score)).where(
                BountyProgram.roi_score.isnot(None)
            )
        )
        scanned = await self.db.execute(
            select(func.count()).where(BountyProgram.last_scanned_at.isnot(None))
        )

        recommendations = await self.get_recommendations(limit=5)

        return {
            "total_programs": total.scalar(),
            "active_programs": active.scalar(),
            "with_bounties": with_bounty.scalar(),
            "scored": scored.scalar(),
            "avg_roi_score": avg_roi.scalar() or 0,
            "scanned": scanned.scalar(),
            "top_programs": recommendations,
        }

    async def close(self):
        await self.client.aclose()
