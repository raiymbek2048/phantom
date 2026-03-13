import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Boolean, Integer, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base
from app.models.scan import ScanType


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"))
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.FULL)

    # Cron expression (e.g. "0 2 * * 1" = every Monday at 2am)
    cron_expression: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Legacy interval support: "daily", "weekly", "monthly", or cron expression
    interval: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Interval in seconds (computed from interval string, used as fallback when no cron_expression)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=86400)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Keep is_active as alias column for backward compatibility with existing data
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    target = relationship("Target")
