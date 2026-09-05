import uuid
from sqlalchemy import String, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin
from app.models.process_group import ProcessGroup


class ProcessChainRule(Base, TimestampMixin):
    """Model representing a parent-child process relationship detection rule."""
    __tablename__ = "process_chain_rules"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    parent_group_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("process_groups.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    child_group_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("process_groups.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(
        String(32), default="alert", nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Relationships
    parent_group: Mapped["ProcessGroup"] = relationship(
        "ProcessGroup", foreign_keys=[parent_group_id], lazy="joined"
    )
    child_group: Mapped["ProcessGroup"] = relationship(
        "ProcessGroup", foreign_keys=[child_group_id], lazy="joined"
    )
