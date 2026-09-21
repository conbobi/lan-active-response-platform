import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import String, JSON, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class ResponseAction(Base, TimestampMixin):
    """
    Model lưu trữ các Response Action (isolate, kill, block_ip, quarantine)
    kèm Snapshot trạng thái trước khi thực thi để phục vụ Undo và Auto-Rollback.
    """
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    agent_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    action_params: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default="pending", nullable=False, index=True
    )  # pending | applied | reverting | reverted | failed
    snapshot: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    undone_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    undo_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    undone_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # user_id or "system"
    auto_rollback_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    cooldown_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    audit_logs = relationship(
        "ActionAuditLog",
        back_populates="action",
        cascade="all, delete-orphan",
        order_by="ActionAuditLog.created_at.asc()"
    )

    __table_args__ = (
        Index(
            "ix_response_actions_auto_rollback",
            "status",
            "auto_rollback_at"
        ),
    )
