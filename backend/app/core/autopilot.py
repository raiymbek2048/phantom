"""
Auto-Pilot Scanner.

Intelligently selects programs to scan based on ROI scoring,
past results, and knowledge base. Manages scan scheduling,
throttling, and notifications.
"""
import logging
import random
from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bounty_program import BountyProgram
from app.models.target import Target, TargetSource
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.vulnerability import Vulnerability
from app.models.h1_submission import H1Submission, H1Status
from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)

# Minimum hours between scans of the same program
MIN_RESCAN_HOURS = 24


class AutoPilot:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def select_program(self) -> BountyProgram | None:
        """Intelligently select the best program to scan next."""
        # Get all active bounty programs with scores
        result = await self.db.execute(
            select(BountyProgram).where(
                BountyProgram.is_active == True,
                BountyProgram.offers_bounties == True,
                BountyProgram.priority >= 0,  # not skipped
            ).order_by(BountyProgram.roi_score.desc().nullslast())
        )
        programs = result.scalars().all()

        if not programs:
            logger.warning("No programs available for autopilot")
            return None

        # Filter out recently scanned
        candidates = []
        now = datetime.utcnow()
        for p in programs:
            if p.last_scanned_at:
                hours_since = (now - p.last_scanned_at).total_seconds() / 3600
                if hours_since < MIN_RESCAN_HOURS:
                    continue
            candidates.append(p)

        if not candidates:
            # All recently scanned — pick the one scanned longest ago
            candidates = sorted(
                programs,
                key=lambda p: p.last_scanned_at or datetime.min,
            )[:5]

        # Load program history from knowledge base
        program_history = {}
        try:
            from sqlalchemy import and_
            hist_result = await self.db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "program_history",
                )
            )
            for kp in hist_result.scalars().all():
                data = kp.pattern_data or {}
                program_history[kp.technology] = data
        except Exception:
            pass

        # Score candidates
        scored = []
        for p in candidates:
            score = 0.0

            # ROI score (primary factor)
            score += (p.roi_score or 0) * 0.4

            # Never scanned by us — exploration bonus
            if not p.last_scanned_at:
                score += 50

            # Has scope with web assets
            web_assets = [
                s for s in (p.scope or [])
                if s.get("type") == "URL" and s.get("bounty_eligible")
            ]
            score += len(web_assets) * 5

            # High priority bonus
            if p.priority >= 2:
                score += 100
            elif p.priority >= 1:
                score += 50

            # Lower difficulty = easier = better for grinding
            if p.difficulty_score:
                score += (1 - p.difficulty_score) * 30

            # Acceptance rate bonus (if we have data)
            if p.our_reports_count > 0:
                acceptance = p.our_accepted_count / p.our_reports_count
                score += acceptance * 40
                # Penalize high duplicate rate
                dup_rate = p.our_duplicate_count / p.our_reports_count
                score -= dup_rate * 30

            # KB: boost programs that historically yield vulns
            hist = program_history.get(p.handle, {})
            if hist:
                avg_vulns = hist.get("avg_vulns", 0)
                if avg_vulns > 0:
                    score += min(avg_vulns * 15, 60)  # cap at 60 points
                elif hist.get("scans", 0) >= 3 and avg_vulns == 0:
                    score -= 40  # penalize consistently unproductive programs

            scored.append((p, score))

        scored.sort(key=lambda x: x[1], reverse=True)

        # Weighted random from top 5 — not pure greedy to allow exploration
        top = scored[:5]
        if not top:
            return None

        weights = [max(s, 1) for _, s in top]
        total = sum(weights)
        probs = [w / total for w in weights]

        chosen = random.choices([p for p, _ in top], weights=probs, k=1)[0]
        logger.info(
            f"Autopilot selected: {chosen.handle} "
            f"(ROI={chosen.roi_score}, priority={chosen.priority})"
        )
        return chosen

    async def select_target_asset(self, program: BountyProgram) -> str | None:
        """Select the best asset from program scope to scan."""
        scope = program.scope or []
        web_assets = [
            s["asset"] for s in scope
            if s.get("type") == "URL" and s.get("bounty_eligible")
        ]

        if not web_assets:
            # Fallback: use program handle as domain
            return f"www.{program.handle}.com"

        # Prefer assets we haven't scanned recently
        for asset in web_assets:
            domain = asset.replace("https://", "").replace("http://", "").rstrip("/")
            target_result = await self.db.execute(
                select(Target).where(Target.domain == domain)
            )
            target = target_result.scalar_one_or_none()
            if not target or not target.updated_at:
                return domain
            hours_since = (datetime.utcnow() - target.updated_at).total_seconds() / 3600
            if hours_since >= MIN_RESCAN_HOURS:
                return domain

        # All scanned recently — pick random
        return random.choice(web_assets).replace("https://", "").replace("http://", "").rstrip("/")

    async def run_scan(self, program: BountyProgram | None = None) -> dict:
        """Run a single autopilot scan cycle."""
        if not program:
            program = await self.select_program()
        if not program:
            return {"status": "no_programs", "message": "No programs available"}

        domain = await self.select_target_asset(program)
        if not domain:
            return {"status": "no_assets", "program": program.handle}

        logger.info(f"Autopilot scan: {domain} ({program.name})")

        # Find or create target
        target_result = await self.db.execute(
            select(Target).where(Target.domain == domain)
        )
        target = target_result.scalar_one_or_none()

        if not target:
            target = Target(
                domain=domain,
                source=TargetSource.HACKERONE,
                bounty_program_url=program.url,
                notes=f"Autopilot: {program.name} bug bounty",
            )
            self.db.add(target)
            await self.db.flush()

        # Check for running scans
        active_result = await self.db.execute(
            select(Scan).where(
                Scan.target_id == target.id,
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
            )
        )
        if active_result.scalar_one_or_none():
            return {"status": "already_running", "domain": domain, "program": program.handle}

        # Create scan
        scan = Scan(
            target_id=target.id,
            scan_type=ScanType.FULL,
            status=ScanStatus.QUEUED,
            config={
                "autopilot": True,
                "program": program.handle,
                "program_name": program.name,
            },
        )
        self.db.add(scan)
        program.last_scanned_at = datetime.utcnow()
        await self.db.commit()

        scan_id = scan.id

        # Run pipeline
        from app.core.pipeline import ScanPipeline
        pipeline = ScanPipeline(scan_id=scan_id)

        try:
            await pipeline.run()
        except Exception as e:
            logger.error(f"Autopilot scan failed for {domain}: {e}")

        # Collect results
        await self.db.refresh(scan)
        vuln_result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulns = vuln_result.scalars().all()

        vuln_summary = {}
        for v in vulns:
            vtype = v.vuln_type.value
            vuln_summary[vtype] = vuln_summary.get(vtype, 0) + 1

        result = {
            "status": "completed",
            "domain": domain,
            "program": program.handle,
            "program_name": program.name,
            "scan_id": scan_id,
            "vulns_found": len(vulns),
            "vuln_types": vuln_summary,
            "endpoints_found": scan.endpoints_found or 0,
        }

        # Auto-create draft submissions for high-confidence findings
        drafts_created = 0
        for v in vulns:
            if (v.ai_confidence or 0) >= 0.7 and v.severity.value in ("critical", "high", "medium"):
                # Check not already submitted
                existing = await self.db.execute(
                    select(H1Submission).where(
                        H1Submission.vulnerability_id == v.id
                    )
                )
                if not existing.scalar_one_or_none():
                    submission = H1Submission(
                        vulnerability_id=v.id,
                        program_handle=program.handle,
                        h1_status=H1Status.DRAFT,
                        report_title=v.title,
                        report_severity=v.severity.value,
                        status_history=[{
                            "status": "draft",
                            "at": datetime.utcnow().isoformat(),
                            "note": f"Auto-created by autopilot scan of {domain}",
                        }],
                    )
                    self.db.add(submission)
                    drafts_created += 1

        if drafts_created:
            await self.db.commit()
            result["drafts_created"] = drafts_created

        # Program-specific learning: track which programs yield results
        try:
            await self._learn_program_patterns(program, domain, vulns)
        except Exception as e:
            logger.warning(f"Autopilot learning error (non-fatal): {e}")

        logger.info(
            f"Autopilot complete: {domain} — {len(vulns)} vulns, "
            f"{drafts_created} drafts created"
        )
        return result

    async def run_cycle(self, max_scans: int = 3) -> dict:
        """Run a full autopilot cycle: multiple scans."""
        results = []
        for i in range(max_scans):
            result = await self.run_scan()
            results.append(result)
            if result["status"] == "no_programs":
                break

        total_vulns = sum(r.get("vulns_found", 0) for r in results)
        total_drafts = sum(r.get("drafts_created", 0) for r in results)

        return {
            "scans_run": len(results),
            "total_vulns": total_vulns,
            "total_drafts": total_drafts,
            "results": results,
        }

    async def _learn_program_patterns(self, program: BountyProgram, domain: str, vulns):
        """Learn program-specific patterns: which programs yield vulns, which don't."""
        from sqlalchemy import and_

        vuln_types = list(set(v.vuln_type.value for v in vulns))
        handle = program.handle

        # Find or update program pattern
        result = await self.db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "program_history",
                    KnowledgePattern.technology == handle,
                )
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            data = existing.pattern_data or {}
            scans = data.get("scans", 0) + 1
            total_vulns = data.get("total_vulns", 0) + len(vulns)
            all_vuln_types = list(set(data.get("vuln_types", []) + vuln_types))
            domains_scanned = list(set(data.get("domains_scanned", []) + [domain]))

            existing.pattern_data = {
                "scans": scans,
                "total_vulns": total_vulns,
                "avg_vulns": total_vulns / scans,
                "vuln_types": all_vuln_types,
                "domains_scanned": domains_scanned[-20:],  # keep last 20
                "last_scan": datetime.utcnow().isoformat(),
                "productive": total_vulns > 0,
            }
            existing.sample_count = scans
            existing.confidence = min(0.95, 0.3 + (scans * 0.05))
        else:
            self.db.add(KnowledgePattern(
                pattern_type="program_history",
                technology=handle,
                pattern_data={
                    "scans": 1,
                    "total_vulns": len(vulns),
                    "avg_vulns": float(len(vulns)),
                    "vuln_types": vuln_types,
                    "domains_scanned": [domain],
                    "last_scan": datetime.utcnow().isoformat(),
                    "productive": len(vulns) > 0,
                },
                confidence=0.35,
                sample_count=1,
            ))

        await self.db.commit()
        logger.info(f"Autopilot learned: {handle} → {len(vulns)} vulns, types={vuln_types}")

    async def get_status(self) -> dict:
        """Get autopilot status and next recommended action."""
        # Active scans
        active_result = await self.db.execute(
            select(func.count()).where(
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED])
            )
        )
        active_scans = active_result.scalar()

        # Programs available
        programs_result = await self.db.execute(
            select(func.count()).where(
                BountyProgram.is_active == True,
                BountyProgram.offers_bounties == True,
                BountyProgram.roi_score.isnot(None),
            )
        )
        available_programs = programs_result.scalar()

        # Pending drafts
        drafts_result = await self.db.execute(
            select(func.count()).where(H1Submission.h1_status == H1Status.DRAFT)
        )
        pending_drafts = drafts_result.scalar()

        # Recent scan stats (last 24h)
        since = datetime.utcnow() - timedelta(hours=24)
        recent_result = await self.db.execute(
            select(func.count()).where(
                Scan.created_at >= since,
                Scan.config["autopilot"].as_boolean() == True,
            )
        )
        recent_scans = recent_result.scalar()

        # Next recommendation
        next_program = await self.select_program()

        return {
            "active_scans": active_scans,
            "available_programs": available_programs,
            "pending_drafts": pending_drafts,
            "scans_last_24h": recent_scans,
            "next_recommended": {
                "program": next_program.handle if next_program else None,
                "name": next_program.name if next_program else None,
                "roi_score": next_program.roi_score if next_program else None,
            } if next_program else None,
        }
