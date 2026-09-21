import uuid
from typing import Any, Dict, Optional
from sqlalchemy import String, Float, Integer, Boolean, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class ResponsePolicy(Base, TimestampMixin):
    """
    Model định nghĩa Response Policy: ánh xạ dải risk_score -> action -> scope (agent / group).
    Ví dụ:
      - 30-49: alert -> agent
      - 50-69: block_ip -> agent
      - 70-84: isolate -> agent
      - 85+: isolate -> group
    """
    __tablename__ = "response_policies"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"pol_{uuid.uuid4().hex[:12]}"
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    min_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    max_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False, index=True)

    action_type: Mapped[str] = mapped_column(String(32), nullable=False)  # alert, block_ip, isolate, kill...
    scope: Mapped[str] = mapped_column(String(32), default="agent", nullable=False)  # agent | group

    target_group_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("agent_groups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action_params: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    auto_rollback_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Relationship
    target_group = relationship("AgentGroup", lazy="selectin")
