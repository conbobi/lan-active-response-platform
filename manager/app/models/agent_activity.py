from sqlalchemy import ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AgentActivity(Base):
    __tablename__ = "agent_activity"

    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    samples: Mapped[dict] = mapped_column(JSON, nullable=False)
