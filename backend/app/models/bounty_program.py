"""
Bounty Program Model — tracks HackerOne programs with scoring and intelligence.
"""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, JSON, Float, Integer, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class BountyProgram(Base):
    """A bug bounty program from HackerOne with intelligence data."""
    __tablename__ = "bounty_programs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Program identity
    handle: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(500))
    platform: Mapped[str] = mapped_column(String(50), default="hackerone")

    # Program details
    offers_bounties: Mapped[bool] = mapped_column(Boolean, default=True)
    base_bounty: Mapped[float | None] = mapped_column(Float, nullable=True)
    currency: Mapped[str] = mapped_column(String(10), default="usd")
    launched_at: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resolved_report_count: Mapped[int] = mapped_column(Integer, default=0)

    # Scope — list of in-scope assets
    scope: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # [{"asset": "example.com", "type": "URL", "bounty_eligible": true, "max_severity": "critical"}, ...]

    # Bounty intelligence (computed from hacktivity data)
    avg_bounty: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_bounty: Mapped[float | None] = mapped_column(Float, nullable=True)
    min_bounty: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_paid: Mapped[float | None] = mapped_column(Float, nullable=True)
    bounty_reports_count: Mapped[int] = mapped_column(Integer, default=0)

    # Response metrics
    avg_response_days: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Vulnerability intelligence
    known_vuln_types: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # {"xss": 15, "sqli": 3, "ssrf": 7, ...}

    top_reporters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # [{"username": "...", "reports": 5}, ...]

    # Technologies detected from scope/reports
    technologies: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # ["php", "wordpress", "nginx", ...]

    # Scoring
    roi_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Computed: avg_bounty * acceptance_rate / estimated_effort
    difficulty_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # 0-1, higher = harder

    # Our interaction
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    our_reports_count: Mapped[int] = mapped_column(Integer, default=0)
    our_accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    our_duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    our_total_bounty: Mapped[float] = mapped_column(Float, default=0.0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    # 0=normal, 1=high, 2=urgent, -1=skip

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
