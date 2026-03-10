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
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.FULL)

    # Cron-like interval: "daily", "weekly", "monthly", or cron expression
    interval: Mapped[str] = mapped_column(String(50))
    # Interval in seconds (computed from interval string)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=86400)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    target = relationship("Target")
