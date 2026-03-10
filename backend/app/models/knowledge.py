"""
Knowledge Base Models

Stores learned patterns from past scans so the AI improves over time:
- Which attack types work on which technologies
- Which payloads succeed vs fail
- Common false positive patterns
- Technology → vulnerability correlations
- Effective scan strategies per target profile
"""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, JSON, Float, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class KnowledgePattern(Base):
    """A learned pattern from past scanning experience."""
    __tablename__ = "knowledge_patterns"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Pattern classification
    pattern_type: Mapped[str] = mapped_column(String(50))
    # Types: tech_vuln_correlation, effective_payload, false_positive,
    #        scan_strategy, waf_bypass, endpoint_pattern

    # What technology/context this applies to
    technology: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # e.g., "php", "node", "spring", "wordpress"

    vuln_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # e.g., "sqli", "xss", "ssrf"

    # The learned pattern data
    pattern_data: Mapped[dict] = mapped_column(JSON)
    # For tech_vuln_correlation: {"success_rate": 0.8, "vulns_found": 15, "scans_tested": 20}
    # For effective_payload: {"payload": "...", "success_count": 5, "contexts": [...]}
    # For false_positive: {"indicator": "...", "vuln_type": "...", "false_count": 10}
    # For scan_strategy: {"phase_order": [...], "avg_vulns": 12, "avg_time": 180}
    # For waf_bypass: {"waf": "cloudflare", "technique": "...", "success_rate": 0.6}

    # Confidence / reliability
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    sample_count: Mapped[int] = mapped_column(Integer, default=1)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AgentDecision(Base):
    """Log of AI agent decisions for learning and analysis."""
    __tablename__ = "agent_decisions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(50))

    # What the agent decided
    step: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(100))
    # e.g., "run_module:ssrf", "skip_module:xxe", "deep_dive:sqli", "stop"

    reasoning: Mapped[str] = mapped_column(Text)
    # AI's explanation of why it chose this action

    # Context at time of decision
    context_summary: Mapped[dict] = mapped_column(JSON)
    # {technologies, endpoints_count, vulns_found_so_far, modules_run, ...}

    # Outcome
    result_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # {vulns_found: 3, new_info: "discovered redis on port 6379", ...}

    was_productive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Did this action find anything useful?

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
