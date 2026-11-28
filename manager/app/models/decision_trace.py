"""Database models for AI Risk Analyst Decision Trace runs and persisted stage events."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

J = JSON().with_variant(JSONB, "postgresql")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AIAnalysisRun(Base):
    """One end-to-end execution of an AI workflow (Reasoning Orchestrator run).

    task_type: ``incident_analysis`` (AI Risk Analyst triage), ``risk_question`` (an analyst's question about an
    incident) or ``rule_generation`` (AI Rule Generator turn; ``subject_id`` is the rule conversation).
    """
    __tablename__ = "ai_analysis_runs"
    __table_args__ = (
        Index("ix_ai_analysis_runs_incident_created", "incident_id", "created_at"),
        Index("ix_ai_analysis_runs_task_subject", "task_type", "subject_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"run_{uuid.uuid4().hex[:16]}")
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    task_type: Mapped[str] = mapped_column(String(32), nullable=False, default="incident_analysis")
    subject_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    question: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result: Mapped[Optional[Dict[str, Any]]] = mapped_column(J, nullable=True)
    current_stage: Mapped[Optional[str]] = mapped_column(String(48), nullable=True)
    stage_status: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    mode: Mapped[str] = mapped_column(String(24), nullable=False, default="reuse")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="CREATED")
    evidence_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    analysis_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class AIDecisionTraceEvent(Base):
    """Persisted monotonic trace event emitted by real backend operations during an AIAnalysisRun."""
    __tablename__ = "ai_decision_trace_events"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "sequence", name="uq_ai_trace_run_seq"),
        Index("ix_ai_trace_events_run_seq", "analysis_run_id", "sequence"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"tr_{uuid.uuid4().hex[:16]}")
    analysis_run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ai_analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    stage: Mapped[str] = mapped_column(String(48), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="DETERMINISTIC")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_refs: Mapped[List[str]] = mapped_column(J, nullable=False, default=list)
    rule_refs: Mapped[List[str]] = mapped_column(J, nullable=False, default=list)
    safe_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(J, nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

