from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Float, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, TimestampMixin
from app.schemas.enums import IncidentSeverity, IncidentStatus


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), default="")
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False
    )
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("agents.id"), nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    def assign_to(self, user_id: str) -> None:
        """Assign incident to a user/operator."""
        self.assigned_to = user_id
        self.status = IncidentStatus.IN_PROGRESS

    def resolve(self) -> None:
        """Resolve incident."""
        self.status = IncidentStatus.RESOLVED

    def mark_false_positive(self) -> None:
        """Mark incident as false positive and close it."""
        self.status = IncidentStatus.CLOSED
        self.severity = IncidentSeverity.LOW
