import statistics
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="TCP", nullable=False)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("agents.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def calculate_duration(self) -> float:
        """Calculate flow duration in seconds."""
        end = self.end_time or datetime.now(timezone.utc)
        start = self.start_time
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return max(0.0, (end - start).total_seconds())

    @staticmethod
    def check_beaconing(flow_list: List["Flow"], max_stddev_seconds: float = 2.0) -> bool:
        """Check if sequence of flows displays periodic beaconing behavior."""
        if len(flow_list) < 3:
            return False
        sorted_flows = sorted(flow_list, key=lambda f: f.start_time)
        intervals = []
        for i in range(1, len(sorted_flows)):
            t1 = sorted_flows[i - 1].start_time
            t2 = sorted_flows[i].start_time
            if t1.tzinfo is None:
                t1 = t1.replace(tzinfo=timezone.utc)
            if t2.tzinfo is None:
                t2 = t2.replace(tzinfo=timezone.utc)
            intervals.append((t2 - t1).total_seconds())

        if not intervals or len(intervals) < 2:
            return False
        
        stddev = statistics.stdev(intervals)
        return stddev <= max_stddev_seconds
