from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, Boolean, Enum, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base
from app.schemas.enums import IncidentSeverity


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity), default=IncidentSeverity.LOW, nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), default="AGENT")
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    processed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def process(self) -> None:
        """Mark event as processed by detection engine."""
        self.processed = True
