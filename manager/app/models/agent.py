from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Float, Boolean, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin
from app.schemas.enums import AgentStatus


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(128), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus), default=AgentStatus.ACTIVE, nullable=False
    )
    cpu: Mapped[float] = mapped_column(Float, default=0.0)
    ram: Mapped[float] = mapped_column(Float, default=0.0)
    disk: Mapped[float] = mapped_column(Float, default=0.0)
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def update_heartbeat(
        self, cpu: float, ram: float, disk: float, timestamp: Optional[datetime] = None,ip_address: str = None, mac_address: str = None
    ) -> None:
        """Update system metrics and last seen timestamp."""
        self.cpu = cpu
        self.ram = ram
        self.disk = disk
        self.last_seen = timestamp or datetime.now(timezone.utc)
        if ip_address is not None:
            self.ip_address = ip_address
        if mac_address is not None:
            self.mac_address = mac_address
        if self.status == AgentStatus.DEAD or self.status == AgentStatus.INACTIVE:
            if not self.is_isolated:
                self.status = AgentStatus.ACTIVE

    def isolate(self) -> None:
        """Isolate agent from network operations."""
        self.is_isolated = True
        self.status = AgentStatus.ISOLATED

    def unisolate(self) -> None:
        """Restore agent to active network operations."""
        self.is_isolated = False
        self.status = AgentStatus.ACTIVE