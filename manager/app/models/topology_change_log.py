from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class TopologyChangeLog(Base):
    __tablename__ = "topology_change_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    link_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)  # UPDATED, FAILED, CREATED, DELETED
    reason: Mapped[str] = mapped_column(String(512), default="")
    old_cost: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    new_cost: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
