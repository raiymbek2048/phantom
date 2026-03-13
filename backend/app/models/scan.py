import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import String, DateTime, Text, JSON, Enum, Integer, ForeignKey, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class ScanType(str, PyEnum):
    FULL = "full"           # Full pipeline (all 12 phases)
    QUICK = "quick"         # Fast: recon + endpoint + vuln_scan + exploit
    STEALTH = "stealth"     # Slow: reduced concurrency, no fuzzing
    RECON = "recon"         # Recon only
    SCAN = "scan"           # Vulnerability scan only
    EXPLOIT = "exploit"     # Exploit only
    AI = "AI"               # AI Agent mode: autonomous decision-making
    BOUNTY = "bounty"      # Bug bounty mode: custom headers, rate limiting, OOS filtering


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED, index=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.FULL)

    # Progress
    current_phase: Mapped[str | None] = mapped_column(String(50), nullable=True)
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0)

    # Config
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # scan settings
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # scan results data (graph, tech, recon)
    priority: Mapped[int] = mapped_column(Integer, default=5)  # 1=highest, 10=lowest

    # Results summary
    subdomains_found: Mapped[int] = mapped_column(Integer, default=0)
    endpoints_found: Mapped[int] = mapped_column(Integer, default=0)
    vulns_found: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="scans")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"))
    phase: Mapped[str] = mapped_column(String(50))
    level: Mapped[str] = mapped_column(String(10), default="info")  # info, warning, error, success
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="logs")
