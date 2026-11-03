import uuid
from datetime import datetime
from typing import Optional, Any, List, Dict
from sqlalchemy import String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, TimestampMixin


class AIAnalysis(Base, TimestampMixin):
    """Model representing automated AI incident triage and response analysis."""
    __tablename__ = "ai_analysis"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"ai_{uuid.uuid4().hex[:12]}"
    )
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    analysis_type: Mapped[str] = mapped_column(
        String(32), default="triage", nullable=False
    )  # 'triage' | 'response_suggestion'
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_techniques: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )  # [{id, name, evidence}]
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0.0-1.0
    analyst_rating: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True
    )  # 'helpful' | 'wrong' | null
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Phase 4 — Response AI Assist (Layer 2)
    suggested_action: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # kill_process | kill_process_tree | isolate | suspend_process | block_ip | no_action
    suggestion_params: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )  # {pid: 656, ip: "185.220.101.5", ...}
    suggestion_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    blast_radius: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )  # {processes_affected: 5, sessions_affected: 0, reversible: false}
    applied_by_analyst: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed_by_analyst: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dismissed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dismiss_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
