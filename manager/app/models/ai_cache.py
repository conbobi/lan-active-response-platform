"""Persistent tiers of the AI analysis cache (see app/services/ai/analysis_cache.py).

Rows hold validated model output and analyst-reviewed pattern guidance only. They never hold
approval, authorization or execution state, and they are always scoped by tenant.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AIAnalysisCache(Base):
    """L1: exact cache of a validated model output for one identical model input."""

    __tablename__ = "ai_analysis_cache"
    __table_args__ = (
        Index("ix_ai_analysis_cache_tenant_subject", "tenant", "subject", "detection_type"),
        Index("ix_ai_analysis_cache_tenant_evidence", "tenant", "evidence_hash", "detection_type"),
        Index("ix_ai_analysis_cache_expires_at", "expires_at"),
        Index("ix_ai_analysis_cache_created_at", "created_at"),
    )

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    # Optional owner of the cached input (e.g. an incident id); used only to report superseded rows as stale.
    subject: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    knowledge_version: Mapped[str] = mapped_column(String(64), nullable=False)
    output: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentPatternCase(Base):
    """L2: de-identified behaviour fingerprint of one incident plus its reviewed guidance references."""

    __tablename__ = "incident_pattern_cases"
    __table_args__ = (
        UniqueConstraint("tenant", "incident_id", name="uq_incident_pattern_cases_tenant_incident"),
        Index("ix_incident_pattern_cases_lookup", "tenant", "classification", "updated_at"),
        Index("ix_incident_pattern_cases_hash", "tenant", "fingerprint_hash"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"ipc_{uuid.uuid4().hex}")
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    guidance: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    analyst_label: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)


class ThreatMemory(Base):
    """Validated, de-identified analysis template for one technical attack pattern (fingerprint).

    It holds what generalises across incidents (classification, MITRE techniques and the evidence
    *roles* that support them) and never an incident's evidence IDs, agent, IPs, PIDs, timestamps,
    approvals or execution results. Exact reuse re-binds roles to the current incident's evidence and
    re-validates; similar entries are only context for a fresh model analysis.
    """

    __tablename__ = "threat_memory"
    __table_args__ = (
        UniqueConstraint("tenant", "fingerprint", "fingerprint_version", "prompt_version", "model_name",
                         name="uq_threat_memory_fingerprint"),
        Index("ix_threat_memory_lookup", "tenant", "platform", "fingerprint_version", "validation_status"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: f"tm_{uuid.uuid4().hex[:24]}")
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_version: Mapped[str] = mapped_column(String(16), nullable=False)
    attack_pattern: Mapped[str] = mapped_column(String(160), nullable=False)
    platform: Mapped[str] = mapped_column(String(16), nullable=False)
    detection_rule_ids: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    behavioral_features: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    analysis_template: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    response_playbook_reference: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    evidence_requirements: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    telemetry_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(24), nullable=False, default="auto_validated")
    status_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reviewer: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_incident_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # provenance only
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    quality_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.6)


class ThreatMemoryEvent(Base):
    """One analysis decision (observability): which tier answered, why, and how long it took."""

    __tablename__ = "threat_memory_events"
    __table_args__ = (Index("ix_threat_memory_events_created", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: f"tme_{uuid.uuid4().hex[:24]}")
    request_id: Mapped[str] = mapped_column(String(40), nullable=False)
    incident_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    memory_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    stale_rejected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lookup_error: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lookup_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    llm_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    total_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
