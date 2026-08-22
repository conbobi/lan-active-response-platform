import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class WhitelistEntry(Base):
    """Model representing an entry in the system whitelist."""
    __tablename__ = "whitelist_entries"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    agent_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("agents.id"), nullable=True
    )
    process_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
