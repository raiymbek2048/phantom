import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import String, DateTime, Text, JSON, Enum, ForeignKey, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class TargetStatus(str, PyEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class TargetSource(str, PyEnum):
    MANUAL = "manual"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON of in-scope URLs/patterns
    status: Mapped[TargetStatus] = mapped_column(Enum(TargetStatus), default=TargetStatus.ACTIVE)
    source: Mapped[TargetSource] = mapped_column(Enum(TargetSource), default=TargetSource.MANUAL)
    bounty_program_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)  # requests/sec override

    # Recon data (populated during scanning)
    recon_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    subdomains: Mapped[list | None] = mapped_column(JSON, nullable=True)
    technologies: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ports: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Tags / grouping
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)  # ["web", "api", "prod"]

    # Continuous monitoring
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    monitoring_interval: Mapped[str] = mapped_column(String(20), default="daily", server_default="daily")  # hourly, daily, weekly

    # Ownership
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
    owner = relationship("User", foreign_keys=[user_id])
