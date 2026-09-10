import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, DateTime, LargeBinary, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class AgentBaseline(Base):
    """
    Model representing a trained Machine Learning behavioral baseline for an Agent.
    Stores serialized Isolation Forest model and normalization statistics.
    """
    __tablename__ = "agent_baselines"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    model_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    features_list: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ready", nullable=False)  # ready, training, insufficient_data
    samples_count: Mapped[int] = mapped_column(default=0, nullable=False)
    mean_vector: Mapped[Dict[str, float]] = mapped_column(JSON, default=dict, nullable=False)
    std_vector: Mapped[Dict[str, float]] = mapped_column(JSON, default=dict, nullable=False)
    last_trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
