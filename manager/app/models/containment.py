"""Host containment actions on an incident (file inspection/quarantine/restore, process termination,
evidence preservation). Action state and verified effect are kept apart; history is append-only."""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

JSONT = JSON().with_variant(JSONB, "postgresql")


def _now():
    return datetime.now(timezone.utc)


class ContainmentAction(Base):
    __tablename__ = "containment_actions"
    __table_args__ = (Index("ix_containment_actions_incident", "incident_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # also the Agent idempotency key
    incident_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    target: Mapped[Dict[str, Any]] = mapped_column(JSONT, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING_APPROVAL")
    effect: Mapped[str] = mapped_column(String(32), nullable=False, default="NOT_APPLIED")
    parent_action_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    command_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    receipt: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    verification: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dispatched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ContainmentEvent(Base):
    __tablename__ = "containment_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(32), ForeignKey("containment_actions.id", ondelete="CASCADE"),
                                           nullable=False, index=True)
    event: Mapped[str] = mapped_column(String(48), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
