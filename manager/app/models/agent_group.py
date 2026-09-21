import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin


class AgentGroup(Base, TimestampMixin):
    """
    Model quản lý nhóm Agent (ví dụ: HR, IT, Finance, Server...).
    Cho phép gom nhóm theo phòng ban hoặc vùng mạng để áp dụng phản ứng theo quy mô.
    """
    __tablename__ = "agent_groups"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"grp_{uuid.uuid4().hex[:12]}"
    )
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Relationships
    members = relationship(
        "AgentGroupMember",
        back_populates="group",
        cascade="all, delete-orphan",
        lazy="selectin"
    )


class AgentGroupMember(Base):
    """
    Bảng liên kết nhiều-nhiều (Many-to-Many) giữa Agent và AgentGroup.
    Một agent có thể thuộc nhiều nhóm khác nhau.
    """
    __tablename__ = "agent_group_members"

    group_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("agent_groups.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False
    )
    agent_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("agents.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
        index=True
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    group = relationship("AgentGroup", back_populates="members")
    agent = relationship("Agent", lazy="selectin")
