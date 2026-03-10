"""
H1 Submission Tracking API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.h1_submission import H1Status
from app.core.h1_feedback import H1FeedbackTracker

router = APIRouter()


class CreateSubmissionRequest(BaseModel):
    vulnerability_id: str
    program_handle: str | None = None
    report_title: str | None = None
    report_markdown: str | None = None
    report_severity: str | None = None
    report_cwe: str | None = None


class MarkSubmittedRequest(BaseModel):
    h1_report_id: str | None = None
    h1_url: str | None = None


class UpdateStatusRequest(BaseModel):
    status: H1Status
    h1_response: str | None = None
    bounty_amount: float | None = None
    bonus_amount: float | None = None
    h1_severity_rating: str | None = None
    note: str | None = None
    skip_learning: bool = False


@router.get("/dashboard")
async def submissions_dashboard(db: AsyncSession = Depends(get_db)):
    """Get submission analytics dashboard."""
    tracker = H1FeedbackTracker(db)
    return await tracker.get_dashboard()


# Static routes MUST come before /{submission_id}

@router.post("/learn-all")
async def learn_from_all_feedback(db: AsyncSession = Depends(get_db)):
    """Process feedback for all submissions with final statuses."""
    from app.core.h1_feedback_learner import H1FeedbackLearner
    learner = H1FeedbackLearner(db)
    try:
        return await learner.process_all_pending()
    finally:
        await learner.close()


@router.get("/rejection-analysis")
async def rejection_analysis(db: AsyncSession = Depends(get_db)):
    """Analyze patterns in rejected submissions and get recommendations."""
    from app.core.h1_feedback_learner import H1FeedbackLearner
    learner = H1FeedbackLearner(db)
    try:
        return await learner.get_rejection_analysis()
    finally:
        await learner.close()


@router.get("")
async def list_submissions(
    status: H1Status | None = None,
    program: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List all H1 submissions."""
    tracker = H1FeedbackTracker(db)
    return await tracker.list_submissions(status=status, program=program, limit=limit)


@router.post("")
async def create_submission(
    body: CreateSubmissionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a draft submission from a vulnerability."""
    tracker = H1FeedbackTracker(db)

    # Optionally auto-generate report
    quality_score = None
    quality_grade = None
    duplicate_risk = False
    markdown = body.report_markdown

    if not markdown:
        try:
            from app.core.h1_report_generator import H1ReportGenerator
            generator = H1ReportGenerator(db)
            try:
                result = await generator.generate_report(body.vulnerability_id)
                if "error" not in result:
                    report = result.get("report", {})
                    markdown = report.get("markdown")
                    quality = result.get("quality", {})
                    quality_score = quality.get("score")
                    quality_grade = quality.get("grade")
                    dup = result.get("duplicate_check", {})
                    duplicate_risk = dup.get("is_likely_duplicate", False)
                    if not body.report_title:
                        body.report_title = report.get("title")
                    if not body.report_severity:
                        body.report_severity = report.get("severity")
                    if not body.report_cwe:
                        body.report_cwe = report.get("cwe")
            finally:
                await generator.close()
        except Exception:
            pass

    sub = await tracker.create_submission(
        vulnerability_id=body.vulnerability_id,
        program_handle=body.program_handle,
        report_title=body.report_title,
        report_markdown=markdown,
        report_severity=body.report_severity,
        report_cwe=body.report_cwe,
        quality_score=quality_score,
        quality_grade=quality_grade,
        duplicate_risk=duplicate_risk,
    )
    return {"id": sub.id, "status": sub.h1_status.value}


@router.get("/{submission_id}")
async def get_submission(
    submission_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get full submission details."""
    tracker = H1FeedbackTracker(db)
    try:
        return await tracker.get_submission(submission_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{submission_id}/submit")
async def mark_submitted(
    submission_id: str,
    body: MarkSubmittedRequest,
    db: AsyncSession = Depends(get_db),
):
    """Mark a draft as submitted to HackerOne."""
    tracker = H1FeedbackTracker(db)
    try:
        sub = await tracker.mark_submitted(
            submission_id=submission_id,
            h1_report_id=body.h1_report_id,
            h1_url=body.h1_url,
        )
        return {"id": sub.id, "status": sub.h1_status.value, "submitted_at": sub.submitted_at.isoformat()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{submission_id}/status")
async def update_status(
    submission_id: str,
    body: UpdateStatusRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update submission status based on H1 response."""
    tracker = H1FeedbackTracker(db)
    try:
        sub = await tracker.update_status(
            submission_id=submission_id,
            new_status=body.status,
            h1_response=body.h1_response,
            bounty_amount=body.bounty_amount,
            bonus_amount=body.bonus_amount,
            h1_severity_rating=body.h1_severity_rating,
            note=body.note,
        )
        # Auto-learn from feedback
        learning_result = None
        final_statuses = {"accepted", "resolved", "bounty_paid", "duplicate", "informative", "not_applicable", "spam"}
        if not body.skip_learning and sub.h1_status.value in final_statuses:
            try:
                from app.core.h1_feedback_learner import H1FeedbackLearner
                learner = H1FeedbackLearner(db)
                try:
                    learning_result = await learner.process_feedback(sub.id)
                finally:
                    await learner.close()
            except Exception as e:
                learning_result = {"error": str(e)}

        return {
            "id": sub.id,
            "status": sub.h1_status.value,
            "bounty": sub.bounty_amount,
            "learning": learning_result,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
