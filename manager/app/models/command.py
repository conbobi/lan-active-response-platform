from datetime import datetime, timezone
from typing import Optional, Any, Dict
from sqlalchemy import String, Integer, DateTime, Enum, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base
from app.schemas.enums import CommandStatus


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[CommandStatus] = mapped_column(
        Enum(CommandStatus), default=CommandStatus.PENDING, nullable=False
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def send_to_agent(self) -> None:
        """Mark command as sent to agent."""
        self.status = CommandStatus.SENT

    def acknowledge(self, status: CommandStatus, error_message: Optional[str] = None) -> None:
        """Acknowledge command result from agent."""
        self.status = status
        self.executed_at = datetime.now(timezone.utc)
        self.error_message = error_message

    def retry(self) -> bool:
        """Increment retry counter and reset status to PENDING if allowed."""
        if self.retry_count < self.max_retries:
            self.retry_count += 1
            self.status = CommandStatus.PENDING
            self.error_message = None
            return True
        self.status = CommandStatus.FAILED
        return False
