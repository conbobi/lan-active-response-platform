import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy import String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class RiskScoreRecord(Base):
    """Model representing historical risk score assessments for an agent."""
    __tablename__ = "risk_score_records"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    agent_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("agents.id"), nullable=False
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    factors: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
