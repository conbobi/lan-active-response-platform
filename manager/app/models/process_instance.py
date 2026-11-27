from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ProcessInstance(Base):
    """One observed process instance (PID + start time + executable), kept across snapshots.

    ``process_info`` holds only the latest snapshot; this table is the history used to trace a chain
    after its short-lived members have exited. ``id`` equals the evidence ID the Detection Engine
    uses for the same instance (stable_id("proc_", pid, start, exe)).
    """
    __tablename__ = "process_instances"
    __table_args__ = (
        Index("ix_process_instances_agent_pid", "agent_id", "pid"),
        Index("ix_process_instances_agent_last_seen", "agent_id", "last_seen"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_start_time: Mapped[Optional[float]] = mapped_column(Float(53), nullable=True)
    start_time_source: Mapped[str] = mapped_column(String(16), default="procfs", nullable=False)
    name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    exe: Mapped[str] = mapped_column(String(1024), default="", nullable=False)
    cmdline: Mapped[str] = mapped_column(Text, default="", nullable=False)
    uid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    euid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    partial: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sources: Mapped[List[str]] = mapped_column(JSON().with_variant(JSONB, "postgresql"), default=list, nullable=False)
    parent_snapshot: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    exited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    exit_signal: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
