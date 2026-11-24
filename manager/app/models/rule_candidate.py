import uuid
from datetime import datetime, timezone
from typing import Optional, Any, List, Dict
from sqlalchemy import String, Text, Float, DateTime, JSON, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base


class RuleCandidate(Base):
    """SQLAlchemy model for rule_candidates table (Agent A & B)."""
    __tablename__ = "rule_candidates"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source: Mapped[str] = mapped_column(
        String(32), default="ai_harvest", nullable=False, index=True
    )  # 'ai_harvest' | 'human'
    status: Mapped[str] = mapped_column(
        String(32), default="pending", nullable=False, index=True
    )  # 'pending', 'validating', 'validated', 'rejected', 'active', 'disabled'

    validation_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    fpr: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    mitre_techniques: Mapped[Optional[List[str]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), default=list, nullable=True
    )  # list of technique IDs, e.g. ["T1059.001"]
    severity: Mapped[str] = mapped_column(
        String(16), default="medium", nullable=False, index=True
    )  # 'low' | 'medium' | 'high' | 'critical'

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    validated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    activated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    model_generated: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # Ollama model alias
    harvest_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    false_positive_samples: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), default=list, nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    versions = relationship(
        "RuleVersion",
        back_populates="rule_candidate",
        cascade="all, delete-orphan",
        order_by="RuleVersion.version_number"
    )

