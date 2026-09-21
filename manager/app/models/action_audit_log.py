import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import String, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base


class ActionAuditLog(Base):
    """
    Model ghi nhận audit log các sự kiện thay đổi trạng thái của ResponseAction
    (created, applied, undo_requested, undone, auto_undone, failed).
    """
    __tablename__ = "action_audit_logs"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    action_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("response_actions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)  # "system" or user_id
    reason: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    # Relationships
    action = relationship("ResponseAction", back_populates="audit_logs")
