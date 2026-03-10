"""
HackerOne Submission Tracking Model.

Tracks the lifecycle of vulnerability reports submitted to HackerOne.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import String, DateTime, Text, JSON, Float, Integer, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class H1Status(str, PyEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    NEW = "new"
    TRIAGED = "triaged"
    NEEDS_MORE_INFO = "needs_more_info"
    ACCEPTED = "accepted"  # bounty eligible
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NOT_APPLICABLE = "not_applicable"
    SPAM = "spam"
    RESOLVED = "resolved"
    BOUNTY_PAID = "bounty_paid"


class H1Submission(Base):
    """Tracks a vulnerability report submitted to HackerOne."""
    __tablename__ = "h1_submissions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Link to our vulnerability
    vulnerability_id: Mapped[str] = mapped_column(String, ForeignKey("vulnerabilities.id"), index=True)

    # Link to program
    program_handle: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)

    # H1 report data
    h1_report_id: Mapped[str | None] = mapped_column(String(50), nullable=True, unique=True)
    h1_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    h1_status: Mapped[H1Status] = mapped_column(Enum(H1Status), default=H1Status.DRAFT)

    # Report content (snapshot at submission time)
    report_title: Mapped[str] = mapped_column(String(500))
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    report_cwe: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # H1 response
    h1_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    h1_severity_rating: Mapped[str | None] = mapped_column(String(20), nullable=True)
    h1_weakness: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Bounty
    bounty_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    bonus_amount: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Quality metrics (from our scoring)
    quality_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quality_grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    duplicate_risk: Mapped[bool] = mapped_column(default=False)

    # Timeline
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    bounty_paid_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Status history
    status_history: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # [{"status": "submitted", "at": "...", "note": "..."}, ...]

    # Notes
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerability = relationship("Vulnerability", backref="h1_submissions")
