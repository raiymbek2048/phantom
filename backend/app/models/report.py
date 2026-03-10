import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import String, DateTime, Text, JSON, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class ReportFormat(str, PyEnum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    GENERIC = "generic"
    PDF = "pdf"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"))
    scan_id: Mapped[str | None] = mapped_column(String, ForeignKey("scans.id"), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String, ForeignKey("vulnerabilities.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(500))
    format: Mapped[ReportFormat] = mapped_column(Enum(ReportFormat), default=ReportFormat.GENERIC)
    content: Mapped[str] = mapped_column(Text)  # Markdown content
    extra_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)  # PDF path

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
