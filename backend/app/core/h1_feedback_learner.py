"""
HackerOne Feedback → Knowledge Pipeline.

Converts H1 submission outcomes into knowledge patterns that
improve future scanning strategy, payload selection, and targeting.
"""
import logging
from datetime import datetime

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.models.h1_submission import H1Submission, H1Status
from app.models.vulnerability import Vulnerability
from app.models.knowledge import KnowledgePattern
from app.models.bounty_program import BountyProgram
from app.models.target import Target

logger = logging.getLogger(__name__)

# Positive outcomes — boost patterns
POSITIVE_STATUSES = {H1Status.ACCEPTED, H1Status.RESOLVED, H1Status.BOUNTY_PAID}
# Negative outcomes — weaken patterns
NEGATIVE_STATUSES = {H1Status.DUPLICATE, H1Status.INFORMATIVE, H1Status.NOT_APPLICABLE, H1Status.SPAM}


class H1FeedbackLearner:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.llm = LLMEngine()

    async def process_feedback(self, submission_id: str) -> dict:
        """Process a single submission's outcome and update knowledge."""
        sub_result = await self.db.execute(
            select(H1Submission).where(H1Submission.id == submission_id)
        )
        sub = sub_result.scalar_one_or_none()
        if not sub:
            return {"error": "Submission not found"}

        vuln_result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.id == sub.vulnerability_id)
        )
        vuln = vuln_result.scalar_one_or_none()
        if not vuln:
            return {"error": "Vulnerability not found"}

        target_result = await self.db.execute(
            select(Target).where(Target.id == vuln.target_id)
        )
        target = target_result.scalar_one_or_none()

        actions = []

        if sub.h1_status in POSITIVE_STATUSES:
            actions.extend(await self._on_accepted(sub, vuln, target))
        elif sub.h1_status == H1Status.DUPLICATE:
            actions.extend(await self._on_duplicate(sub, vuln, target))
        elif sub.h1_status == H1Status.INFORMATIVE:
            actions.extend(await self._on_informative(sub, vuln, target))
        elif sub.h1_status == H1Status.NOT_APPLICABLE:
            actions.extend(await self._on_not_applicable(sub, vuln, target))

        await self.db.commit()
        logger.info(f"Feedback processed for submission {submission_id}: {len(actions)} actions")
        return {"submission_id": submission_id, "status": sub.h1_status.value, "actions": actions}

    async def _on_accepted(self, sub: H1Submission, vuln: Vulnerability, target: Target | None) -> list[str]:
        """Accepted/Resolved/Bounty — boost everything related."""
        actions = []
        vuln_type = vuln.vuln_type.value
        tech = self._get_tech(target)
        program = sub.program_handle

        # 1. Boost tech→vuln correlation confidence
        patterns = await self._find_patterns("tech_vuln_correlation", tech, vuln_type)
        for p in patterns:
            p.confidence = min(0.95, p.confidence + 0.15)
            p.sample_count += 1
            data = dict(p.pattern_data)
            data["h1_confirmed"] = True
            data["bounty"] = sub.bounty_amount
            p.pattern_data = data
        actions.append(f"boosted {len(patterns)} tech_vuln_correlation patterns (+0.15)")

        # 2. Boost effective payload
        if vuln.payload_used:
            payload_patterns = await self._find_patterns("effective_payload", tech, vuln_type)
            boosted = 0
            for p in payload_patterns:
                payloads = p.pattern_data.get("payloads", [])
                if vuln.payload_used in payloads:
                    p.confidence = min(0.95, p.confidence + 0.2)
                    p.sample_count += 1
                    data = dict(p.pattern_data)
                    data["h1_confirmed"] = True
                    p.pattern_data = data
                    boosted += 1

            if boosted == 0:
                # Create new pattern for this confirmed payload
                self.db.add(KnowledgePattern(
                    pattern_type="effective_payload",
                    technology=tech,
                    vuln_type=vuln_type,
                    pattern_data={
                        "payloads": [vuln.payload_used],
                        "h1_confirmed": True,
                        "bounty": sub.bounty_amount,
                        "program": program,
                        "url_pattern": vuln.url,
                    },
                    confidence=0.8,
                    sample_count=1,
                ))
                boosted = 1
            actions.append(f"boosted {boosted} payload patterns (+0.2)")

        # 3. Record successful program insight
        self.db.add(KnowledgePattern(
            pattern_type="h1_insight",
            technology=program,
            vuln_type=vuln_type,
            pattern_data={
                "outcome": "accepted",
                "bounty": sub.bounty_amount,
                "severity": vuln.severity.value,
                "url_pattern": vuln.url,
                "parameter": vuln.parameter,
                "h1_severity": sub.h1_severity_rating,
                "lesson": "This vuln type pays on this program",
            },
            confidence=0.85,
            sample_count=1,
        ))
        actions.append("created h1_insight for successful report")

        # 4. Boost program ROI
        if program:
            prog_result = await self.db.execute(
                select(BountyProgram).where(BountyProgram.handle == program)
            )
            prog = prog_result.scalar_one_or_none()
            if prog:
                prog.priority = max(prog.priority, 1)  # Mark as high priority
                actions.append(f"boosted program {program} priority")

        return actions

    async def _on_duplicate(self, sub: H1Submission, vuln: Vulnerability, target: Target | None) -> list[str]:
        """Duplicate — this pattern is already known, deprioritize."""
        actions = []
        vuln_type = vuln.vuln_type.value
        tech = self._get_tech(target)
        program = sub.program_handle

        # 1. Record duplicate pattern — avoid similar findings in future
        self.db.add(KnowledgePattern(
            pattern_type="h1_insight",
            technology=program,
            vuln_type=vuln_type,
            pattern_data={
                "outcome": "duplicate",
                "url_pattern": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload_used,
                "lesson": "Already reported — find deeper/unique bugs on this program",
            },
            confidence=0.6,
            sample_count=1,
        ))
        actions.append("recorded duplicate pattern")

        # 2. Don't fully decrease confidence — the vuln type IS valid, just already found
        # Instead, mark patterns with "common_duplicate" flag
        patterns = await self._find_patterns("tech_vuln_correlation", tech, vuln_type)
        for p in patterns:
            data = dict(p.pattern_data)
            dup_count = data.get("duplicate_count", 0) + 1
            data["duplicate_count"] = dup_count
            # If 3+ duplicates of same type on same tech — reduce priority
            if dup_count >= 3:
                data["deprioritize"] = True
                p.confidence = max(0.2, p.confidence - 0.1)
            p.pattern_data = data
        actions.append(f"updated {len(patterns)} patterns with duplicate flag")

        return actions

    async def _on_informative(self, sub: H1Submission, vuln: Vulnerability, target: Target | None) -> list[str]:
        """Informative — not impactful enough. Analyze why."""
        actions = []
        vuln_type = vuln.vuln_type.value
        program = sub.program_handle

        # Record the insight
        self.db.add(KnowledgePattern(
            pattern_type="h1_insight",
            technology=program,
            vuln_type=vuln_type,
            pattern_data={
                "outcome": "informative",
                "severity": vuln.severity.value,
                "h1_response": sub.h1_response,
                "lesson": "Finding was real but not impactful enough for bounty",
            },
            confidence=0.4,
            sample_count=1,
        ))
        actions.append("recorded informative insight")

        # Slightly decrease confidence for this vuln type on this program
        tech = self._get_tech(target)
        patterns = await self._find_patterns("tech_vuln_correlation", tech, vuln_type)
        for p in patterns:
            p.confidence = max(0.2, p.confidence - 0.05)
            data = dict(p.pattern_data)
            data["informative_count"] = data.get("informative_count", 0) + 1
            p.pattern_data = data
        actions.append(f"reduced confidence for {len(patterns)} patterns (-0.05)")

        # Claude analysis: why was it informative?
        if sub.h1_response:
            analysis = await self._analyze_rejection(sub, vuln, "informative")
            if analysis:
                actions.append(f"Claude analysis: {analysis.get('lesson', 'N/A')}")

        return actions

    async def _on_not_applicable(self, sub: H1Submission, vuln: Vulnerability, target: Target | None) -> list[str]:
        """N/A — wrong target, out of scope, or not a vuln."""
        actions = []
        vuln_type = vuln.vuln_type.value
        tech = self._get_tech(target)
        program = sub.program_handle

        # Strong negative signal
        self.db.add(KnowledgePattern(
            pattern_type="h1_insight",
            technology=program,
            vuln_type=vuln_type,
            pattern_data={
                "outcome": "not_applicable",
                "h1_response": sub.h1_response,
                "url": vuln.url,
                "lesson": "This finding type is not applicable for this program",
            },
            confidence=0.3,
            sample_count=1,
        ))
        actions.append("recorded N/A insight")

        # Decrease confidence more aggressively
        patterns = await self._find_patterns("tech_vuln_correlation", tech, vuln_type)
        for p in patterns:
            p.confidence = max(0.1, p.confidence - 0.15)
            data = dict(p.pattern_data)
            data["na_count"] = data.get("na_count", 0) + 1
            p.pattern_data = data
        actions.append(f"reduced confidence for {len(patterns)} patterns (-0.15)")

        # Record as potential false positive pattern
        if vuln.payload_used:
            self.db.add(KnowledgePattern(
                pattern_type="false_positive",
                technology=tech,
                vuln_type=vuln_type,
                pattern_data={
                    "indicator": f"h1_na:{vuln.url}",
                    "payload": vuln.payload_used,
                    "source": "h1_feedback",
                    "program": program,
                },
                confidence=0.5,
                sample_count=1,
            ))
            actions.append("recorded false positive pattern from N/A")

        return actions

    async def _analyze_rejection(self, sub: H1Submission, vuln: Vulnerability, outcome: str) -> dict | None:
        """Use Claude to understand why a report was rejected and extract lessons."""
        prompt = f"""A bug bounty report was marked as "{outcome}" by the program. Analyze why and extract lessons.

Report: {sub.report_title}
Vuln Type: {vuln.vuln_type.value}
Severity: {vuln.severity.value}
URL: {vuln.url}
Program: {sub.program_handle}
H1 Response: {sub.h1_response or 'No response provided'}

Return JSON:
{{
    "likely_reason": "Why was it rejected? (1 sentence)",
    "lesson": "What should we do differently next time? (1 sentence)",
    "avoid_pattern": "What pattern should we avoid? (e.g., 'low-impact info_disclosure on this program')",
    "severity_adjustment": "Should we target higher/lower severity? (higher/lower/same)"
}}"""

        try:
            result = await self.llm.analyze_json(prompt)
            # Save the analysis as an insight
            self.db.add(KnowledgePattern(
                pattern_type="h1_insight",
                technology=sub.program_handle,
                vuln_type=vuln.vuln_type.value,
                pattern_data={
                    "outcome": outcome,
                    "claude_analysis": result,
                    "analyzed_at": datetime.utcnow().isoformat(),
                },
                confidence=0.5,
                sample_count=1,
            ))
            return result
        except LLMError:
            return None

    async def process_all_pending(self) -> dict:
        """Process feedback for all submissions with final statuses that haven't been learned from."""
        final_statuses = list(POSITIVE_STATUSES | NEGATIVE_STATUSES)
        result = await self.db.execute(
            select(H1Submission).where(
                H1Submission.h1_status.in_(final_statuses),
            )
        )
        submissions = result.scalars().all()

        stats = {"processed": 0, "skipped": 0, "total_actions": 0}

        for sub in submissions:
            # Check if already processed (look for existing h1_insight with this outcome)
            existing = await self.db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "h1_insight",
                    KnowledgePattern.technology == sub.program_handle,
                    KnowledgePattern.pattern_data["outcome"].as_string() == sub.h1_status.value,
                ).limit(1)
            )
            if existing.scalar_one_or_none():
                stats["skipped"] += 1
                continue

            feedback = await self.process_feedback(sub.id)
            actions = feedback.get("actions", [])
            stats["processed"] += 1
            stats["total_actions"] += len(actions)

        return stats

    async def get_rejection_analysis(self, limit: int = 20) -> dict:
        """Analyze patterns in rejections to improve strategy."""
        # Get all rejected submissions
        rejected = await self.db.execute(
            select(H1Submission).where(
                H1Submission.h1_status.in_([
                    H1Status.DUPLICATE, H1Status.INFORMATIVE, H1Status.NOT_APPLICABLE
                ])
            ).limit(100)
        )
        subs = rejected.scalars().all()

        # Group by rejection reason
        by_status: dict[str, list] = {}
        by_program: dict[str, dict] = {}
        by_vuln_type: dict[str, dict] = {}

        for sub in subs:
            status = sub.h1_status.value
            by_status.setdefault(status, []).append(sub)

            prog = sub.program_handle or "unknown"
            by_program.setdefault(prog, {"total": 0, "duplicate": 0, "informative": 0, "na": 0})
            by_program[prog]["total"] += 1
            if sub.h1_status == H1Status.DUPLICATE:
                by_program[prog]["duplicate"] += 1
            elif sub.h1_status == H1Status.INFORMATIVE:
                by_program[prog]["informative"] += 1
            elif sub.h1_status == H1Status.NOT_APPLICABLE:
                by_program[prog]["na"] += 1

            sev = sub.report_severity or "unknown"
            by_vuln_type.setdefault(sev, {"total": 0})
            by_vuln_type[sev]["total"] += 1

        # Top problematic programs
        problem_programs = sorted(
            by_program.items(), key=lambda x: x[1]["total"], reverse=True
        )[:5]

        return {
            "total_rejections": len(subs),
            "by_status": {k: len(v) for k, v in by_status.items()},
            "problem_programs": [
                {"program": prog, **data} for prog, data in problem_programs
            ],
            "recommendations": self._build_recommendations(by_status, by_program),
        }

    def _build_recommendations(self, by_status: dict, by_program: dict) -> list[str]:
        """Build actionable recommendations from rejection patterns."""
        recs = []

        dup_count = len(by_status.get("duplicate", []))
        info_count = len(by_status.get("informative", []))
        na_count = len(by_status.get("not_applicable", []))

        if dup_count > 3:
            recs.append(
                f"{dup_count} duplicates — focus on deeper/logic bugs instead of surface-level findings"
            )
        if info_count > 3:
            recs.append(
                f"{info_count} informatives — target higher severity, provide better impact proof"
            )
        if na_count > 2:
            recs.append(
                f"{na_count} N/A — review program scope more carefully before scanning"
            )

        for prog, data in by_program.items():
            if data["duplicate"] >= 3:
                recs.append(f"Program '{prog}': {data['duplicate']} duplicates — consider skipping or go deeper")

        return recs

    def _get_tech(self, target: Target | None) -> str | None:
        if not target or not target.technologies:
            return None
        techs = target.technologies
        if isinstance(techs, list) and techs:
            return techs[0]
        if isinstance(techs, dict):
            return list(techs.keys())[0] if techs else None
        return None

    async def _find_patterns(self, pattern_type: str, tech: str | None, vuln_type: str) -> list:
        query = select(KnowledgePattern).where(
            KnowledgePattern.pattern_type == pattern_type,
            KnowledgePattern.vuln_type == vuln_type,
        )
        if tech:
            query = query.where(KnowledgePattern.technology == tech)
        result = await self.db.execute(query.limit(20))
        return list(result.scalars().all())

    async def close(self):
        await self.llm.close()
