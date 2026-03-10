import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, JSON, Float, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class Payload(Base):
    __tablename__ = "payloads"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    vuln_type: Mapped[str] = mapped_column(String(50), index=True)  # xss, sqli, etc.
    payload: Mapped[str] = mapped_column(Text)
    encoding: Mapped[str | None] = mapped_column(String(50), nullable=True)  # url, base64, unicode
    context: Mapped[str | None] = mapped_column(String(100), nullable=True)  # html_attr, js, sql_where
    waf_bypass: Mapped[bool] = mapped_column(Boolean, default=False)
    waf_type: Mapped[str | None] = mapped_column(String(100), nullable=True)  # cloudflare, akamai, etc.

    # Effectiveness tracking
    times_used: Mapped[int] = mapped_column(Integer, default=0)
    times_succeeded: Mapped[int] = mapped_column(Integer, default=0)
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)

    # Metadata
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)  # ai_generated, exploit_db, manual
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
