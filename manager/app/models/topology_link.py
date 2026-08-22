from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy import String, Float, Boolean, ForeignKey, Column
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, TimestampMixin
from app.core.exceptions import BandwidthExceededError


class TopologyLink(Base, TimestampMixin):
    __tablename__ = "topology_links"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    target_agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    capacity: Mapped[float] = mapped_column(Float, default=1000.0, nullable=False)  # Mbps
    reserved_bandwidth: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # Mbps
    latency: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)  # ms
    load: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # %
    packet_loss: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # %
    max_safe_utilization = Column(Float, default=0.8, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def calculate_dynamic_cost(self) -> float:
        """Calculate dynamic routing cost based on metrics."""
        if not self.is_active:
            return float("inf")
        # Base cost from latency, heavily penalized by load ratio and packet loss
        load_ratio = self.load / 100.0
        packet_loss_ratio = self.packet_loss / 100.0
        cost = self.latency * (1.0 + 2.0 * load_ratio) + (packet_loss_ratio * 100.0)
        return round(cost, 4)

    def get_available_capacity(self) -> float:
        """Return available unreserved bandwidth."""
        return max(0.0, self.capacity * self.max_safe_utilization - self.reserved_bandwidth)

    def reserve_bandwidth(self, bw: float) -> None:
        """Reserve requested bandwidth."""
        available = self.get_available_capacity()
        if bw > available:
            raise BandwidthExceededError(
                f"Cannot reserve {bw} Mbps on link '{self.id}'. Available: {available} Mbps."
            )
        self.reserved_bandwidth += bw

    def release_bandwidth(self, bw: float) -> None:
        """Release allocated bandwidth."""
        self.reserved_bandwidth = max(0.0, self.reserved_bandwidth - bw)

    def deactivate(self) -> None:
        """Deactivate link."""
        self.is_active = False

    def activate(self) -> None:
        """Activate link."""
        self.is_active = True

    def update_from_dto(self, dto: Any) -> None:
        """Update metrics from DTO."""
        if hasattr(dto, "new_latency") and dto.new_latency is not None:
            self.latency = dto.new_latency
        if hasattr(dto, "new_load") and dto.new_load is not None:
            self.load = dto.new_load
        if hasattr(dto, "new_packet_loss") and dto.new_packet_loss is not None:
            self.packet_loss = dto.new_packet_loss
        if hasattr(dto, "is_active") and dto.is_active is not None:
            self.is_active = dto.is_active
