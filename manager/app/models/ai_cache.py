"""Persistent tiers of the AI analysis cache (see app/services/ai/analysis_cache.py).

Rows hold validated model output and analyst-reviewed pattern guidance only. They never hold
approval, authorization or execution state, and they are always scoped by tenant.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
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
