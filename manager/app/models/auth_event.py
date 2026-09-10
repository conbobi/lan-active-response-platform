import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class AuthEvent(Base):
    """
    Model representing authentication attempts (SSH, RDP, Web, System login).
    Used for brute-force attack detection and audit trails.
    """
    __tablename__ = "auth_events"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    service: Mapped[str] = mapped_column(String(32), default="ssh", nullable=False)  # ssh, rdp, local, web
    source_ip: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="failed", nullable=False)  # failed, success
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
