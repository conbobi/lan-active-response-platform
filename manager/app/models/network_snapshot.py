from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class NetworkSnapshot(Base):
    __tablename__ = "network_snapshots"

    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
