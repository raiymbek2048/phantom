"""
HackerOne Feedback Tracking Engine.

Manages the lifecycle of H1 submissions and computes analytics.
"""
import logging
from datetime import datetime

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.h1_submission import H1Submission, H1Status
from app.models.vulnerability import Vulnerability
from app.models.bounty_program import BountyProgram

logger = logging.getLogger(__name__)

# Valid status transitions
H1_TRANSITIONS = {
    H1Status.DRAFT: [H1Status.SUBMITTED],
    H1Status.SUBMITTED: [H1Status.NEW, H1Status.TRIAGED, H1Status.DUPLICATE,
                          H1Status.INFORMATIVE, H1Status.NOT_APPLICABLE, H1Status.SPAM],
    H1Status.NEW: [H1Status.TRIAGED, H1Status.DUPLICATE, H1Status.INFORMATIVE,
                    H1Status.NOT_APPLICABLE, H1Status.NEEDS_MORE_INFO],
    H1Status.TRIAGED: [H1Status.ACCEPTED, H1Status.DUPLICATE, H1Status.INFORMATIVE,
                        H1Status.NOT_APPLICABLE, H1Status.NEEDS_MORE_INFO],
    H1Status.NEEDS_MORE_INFO: [H1Status.TRIAGED, H1Status.ACCEPTED, H1Status.DUPLICATE,
                                H1Status.INFORMATIVE, H1Status.NOT_APPLICABLE],
    H1Status.ACCEPTED: [H1Status.RESOLVED, H1Status.BOUNTY_PAID],
    H1Status.RESOLVED: [H1Status.BOUNTY_PAID],
    H1Status.DUPLICATE: [],
    H1Status.INFORMATIVE: [],
    H1Status.NOT_APPLICABLE: [],
    H1Status.SPAM: [],
    H1Status.BOUNTY_PAID: [],
}


class H1FeedbackTracker:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_submission(
        self,
        vulnerability_id: str,
        program_handle: str | None = None,
        report_title: str | None = None,
        report_markdown: str | None = None,
        report_severity: str | None = None,
        report_cwe: str | None = None,
        quality_score: int | None = None,
        quality_grade: str | None = None,
        duplicate_risk: bool = False,
    ) -> H1Submission:
        """Create a draft submission for a vulnerability."""
        # Get vuln details if title not provided
        if not report_title:
            vuln_result = await self.db.execute(
                select(Vulnerability).where(Vulnerability.id == vulnerability_id)
            )
            vuln = vuln_result.scalar_one_or_none()
            if vuln:
                report_title = vuln.title
                report_severity = report_severity or vuln.severity.value

        submission = H1Submission(
            vulnerability_id=vulnerability_id,
            program_handle=program_handle,
            h1_status=H1Status.DRAFT,
            report_title=report_title or "Untitled",
            report_markdown=report_markdown,
            report_severity=report_severity,
            report_cwe=report_cwe,
            quality_score=quality_score,
            quality_grade=quality_grade,
            duplicate_risk=duplicate_risk,
            status_history=[{
                "status": "draft",
                "at": datetime.utcnow().isoformat(),
                "note": "Report created",
            }],
        )
        self.db.add(submission)
        await self.db.commit()
        await self.db.refresh(submission)
        return submission

    async def mark_submitted(
        self,
        submission_id: str,
        h1_report_id: str | None = None,
        h1_url: str | None = None,
    ) -> H1Submission:
        """Mark a submission as sent to H1."""
        sub = await self._get_submission(submission_id)
        self._validate_transition(sub, H1Status.SUBMITTED)

        sub.h1_status = H1Status.SUBMITTED
        sub.h1_report_id = h1_report_id
        sub.h1_url = h1_url
        sub.submitted_at = datetime.utcnow()
        self._add_history(sub, "submitted", "Report submitted to HackerOne")

        # Update vulnerability status
        vuln_result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.id == sub.vulnerability_id)
        )
        vuln = vuln_result.scalar_one_or_none()
        if vuln:
            from app.models.vulnerability import VulnStatus
            vuln.status = VulnStatus.REPORTED

        await self.db.commit()
        return sub

    async def update_status(
        self,
        submission_id: str,
        new_status: H1Status,
        h1_response: str | None = None,
        bounty_amount: float | None = None,
        bonus_amount: float | None = None,
        h1_severity_rating: str | None = None,
        note: str | None = None,
    ) -> H1Submission:
        """Update H1 submission status based on program response."""
        sub = await self._get_submission(submission_id)
        self._validate_transition(sub, new_status)

        old_status = sub.h1_status
        sub.h1_status = new_status

        if h1_response:
            sub.h1_response = h1_response
        if h1_severity_rating:
            sub.h1_severity_rating = h1_severity_rating
        if bounty_amount is not None:
            sub.bounty_amount = bounty_amount
        if bonus_amount is not None:
            sub.bonus_amount = bonus_amount

        # Set timestamps
        now = datetime.utcnow()
        if new_status == H1Status.TRIAGED:
            sub.triaged_at = now
        elif new_status in (H1Status.RESOLVED, H1Status.ACCEPTED):
            sub.resolved_at = now
        elif new_status == H1Status.BOUNTY_PAID:
            sub.bounty_paid_at = now

        self._add_history(sub, new_status.value, note or f"Status changed from {old_status.value}")

        # Update program stats
        if sub.program_handle:
            await self._update_program_stats(sub.program_handle)

        # Update vulnerability bounty amount
        if bounty_amount and bounty_amount > 0:
            vuln_result = await self.db.execute(
                select(Vulnerability).where(Vulnerability.id == sub.vulnerability_id)
            )
            vuln = vuln_result.scalar_one_or_none()
            if vuln:
                vuln.bounty_amount = bounty_amount
                from app.models.vulnerability import VulnStatus
                vuln.status = VulnStatus.BOUNTY_RECEIVED

        await self.db.commit()
        return sub

    async def get_submission(self, submission_id: str) -> dict | None:
        """Get submission with full details."""
        sub = await self._get_submission(submission_id)

        # Get vulnerability details
        vuln_result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.id == sub.vulnerability_id)
        )
        vuln = vuln_result.scalar_one_or_none()

        allowed_transitions = [t.value for t in H1_TRANSITIONS.get(sub.h1_status, [])]

        return {
            "id": sub.id,
            "vulnerability_id": sub.vulnerability_id,
            "vuln_title": vuln.title if vuln else None,
            "vuln_url": vuln.url if vuln else None,
            "vuln_type": vuln.vuln_type.value if vuln else None,
            "program_handle": sub.program_handle,
            "h1_report_id": sub.h1_report_id,
            "h1_url": sub.h1_url,
            "h1_status": sub.h1_status.value,
            "report_title": sub.report_title,
            "report_severity": sub.report_severity,
            "report_cwe": sub.report_cwe,
            "h1_response": sub.h1_response,
            "h1_severity_rating": sub.h1_severity_rating,
            "bounty_amount": sub.bounty_amount,
            "bonus_amount": sub.bonus_amount,
            "quality_score": sub.quality_score,
            "quality_grade": sub.quality_grade,
            "duplicate_risk": sub.duplicate_risk,
            "submitted_at": sub.submitted_at.isoformat() if sub.submitted_at else None,
            "triaged_at": sub.triaged_at.isoformat() if sub.triaged_at else None,
            "resolved_at": sub.resolved_at.isoformat() if sub.resolved_at else None,
            "bounty_paid_at": sub.bounty_paid_at.isoformat() if sub.bounty_paid_at else None,
            "status_history": sub.status_history,
            "allowed_transitions": allowed_transitions,
            "notes": sub.notes,
            "created_at": sub.created_at.isoformat(),
        }

    async def list_submissions(
        self,
        status: H1Status | None = None,
        program: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """List all submissions with optional filters."""
        query = select(H1Submission).order_by(H1Submission.created_at.desc())
        if status:
            query = query.where(H1Submission.h1_status == status)
        if program:
            query = query.where(H1Submission.program_handle == program)
        query = query.limit(limit)

        result = await self.db.execute(query)
        submissions = result.scalars().all()

        items = []
        for sub in submissions:
            items.append({
                "id": sub.id,
                "vulnerability_id": sub.vulnerability_id,
                "program_handle": sub.program_handle,
                "report_title": sub.report_title,
                "h1_status": sub.h1_status.value,
                "h1_report_id": sub.h1_report_id,
                "report_severity": sub.report_severity,
                "bounty_amount": sub.bounty_amount,
                "quality_grade": sub.quality_grade,
                "duplicate_risk": sub.duplicate_risk,
                "submitted_at": sub.submitted_at.isoformat() if sub.submitted_at else None,
                "created_at": sub.created_at.isoformat(),
            })
        return items

    async def get_dashboard(self) -> dict:
        """Get submission analytics dashboard."""
        total = await self._count()
        submitted = await self._count(H1Status.SUBMITTED)
        triaged = await self._count(H1Status.TRIAGED)
        accepted = await self._count(H1Status.ACCEPTED)
        duplicate = await self._count(H1Status.DUPLICATE)
        informative = await self._count(H1Status.INFORMATIVE)
        na = await self._count(H1Status.NOT_APPLICABLE)
        resolved = await self._count(H1Status.RESOLVED)
        bounty_paid = await self._count(H1Status.BOUNTY_PAID)
        draft = await self._count(H1Status.DRAFT)

        # Bounty stats
        bounty_result = await self.db.execute(
            select(
                func.sum(H1Submission.bounty_amount),
                func.avg(H1Submission.bounty_amount),
                func.max(H1Submission.bounty_amount),
            ).where(H1Submission.bounty_amount.isnot(None))
        )
        bounty_row = bounty_result.one()

        # Acceptance rate
        total_resolved = accepted + resolved + bounty_paid + duplicate + informative + na
        acceptance_rate = (
            (accepted + resolved + bounty_paid) / total_resolved
            if total_resolved > 0 else 0
        )
        duplicate_rate = duplicate / total_resolved if total_resolved > 0 else 0

        # Response time (submitted → triaged)
        triage_times = await self.db.execute(
            select(H1Submission).where(
                H1Submission.submitted_at.isnot(None),
                H1Submission.triaged_at.isnot(None),
            )
        )
        triage_subs = triage_times.scalars().all()
        avg_triage_days = None
        if triage_subs:
            total_days = sum(
                (s.triaged_at - s.submitted_at).total_seconds() / 86400
                for s in triage_subs
            )
            avg_triage_days = round(total_days / len(triage_subs), 1)

        # Per-program breakdown
        program_result = await self.db.execute(
            select(
                H1Submission.program_handle,
                func.count().label("count"),
                func.sum(H1Submission.bounty_amount).label("total_bounty"),
            )
            .where(H1Submission.program_handle.isnot(None))
            .group_by(H1Submission.program_handle)
            .order_by(func.count().desc())
            .limit(10)
        )
        program_breakdown = [
            {"program": row[0], "submissions": row[1], "total_bounty": row[2] or 0}
            for row in program_result.all()
        ]

        return {
            "total_submissions": total,
            "by_status": {
                "draft": draft,
                "submitted": submitted,
                "triaged": triaged,
                "accepted": accepted,
                "duplicate": duplicate,
                "informative": informative,
                "not_applicable": na,
                "resolved": resolved,
                "bounty_paid": bounty_paid,
            },
            "rates": {
                "acceptance_rate": round(acceptance_rate * 100, 1),
                "duplicate_rate": round(duplicate_rate * 100, 1),
            },
            "bounties": {
                "total": bounty_row[0] or 0,
                "average": round(bounty_row[1] or 0, 2),
                "max": bounty_row[2] or 0,
            },
            "avg_triage_days": avg_triage_days,
            "program_breakdown": program_breakdown,
        }

    async def _get_submission(self, submission_id: str) -> H1Submission:
        result = await self.db.execute(
            select(H1Submission).where(H1Submission.id == submission_id)
        )
        sub = result.scalar_one_or_none()
        if not sub:
            raise ValueError(f"Submission {submission_id} not found")
        return sub

    async def _count(self, status: H1Status | None = None) -> int:
        query = select(func.count()).select_from(H1Submission)
        if status:
            query = query.where(H1Submission.h1_status == status)
        result = await self.db.execute(query)
        return result.scalar()

    async def _update_program_stats(self, handle: str):
        """Update BountyProgram stats from our submissions."""
        result = await self.db.execute(
            select(BountyProgram).where(BountyProgram.handle == handle)
        )
        program = result.scalar_one_or_none()
        if not program:
            return

        subs_result = await self.db.execute(
            select(H1Submission).where(H1Submission.program_handle == handle)
        )
        subs = subs_result.scalars().all()

        program.our_reports_count = len(subs)
        program.our_accepted_count = sum(
            1 for s in subs
            if s.h1_status in (H1Status.ACCEPTED, H1Status.RESOLVED, H1Status.BOUNTY_PAID)
        )
        program.our_duplicate_count = sum(
            1 for s in subs if s.h1_status == H1Status.DUPLICATE
        )
        program.our_total_bounty = sum(
            (s.bounty_amount or 0) + (s.bonus_amount or 0) for s in subs
        )

    def _validate_transition(self, sub: H1Submission, new_status: H1Status):
        allowed = H1_TRANSITIONS.get(sub.h1_status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition from {sub.h1_status.value} to {new_status.value}. "
                f"Allowed: {[a.value for a in allowed]}"
            )

    def _add_history(self, sub: H1Submission, status: str, note: str):
        history = list(sub.status_history or [])
        history.append({
            "status": status,
            "at": datetime.utcnow().isoformat(),
            "note": note,
        })
        sub.status_history = history
