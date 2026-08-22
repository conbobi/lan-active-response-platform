from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class ProcessInfo(Base):
    __tablename__ = "process_info"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    exe: Mapped[str] = mapped_column(String(512), default="")
    exe_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    cmdline: Mapped[str] = mapped_column(String(1024), default="")
    session_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    memory_percent: Mapped[float] = mapped_column(Float, default=0.0)
    hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def is_suspicious_process(self) -> bool:
        """Determine if process is suspicious based on name, path, or flag."""
        suspicious_names = ["nc", "netcat", "nmap", "mimikatz", "chisel", "metasploit", "meterpreter", "powershell_hidden"]
        if self.is_suspicious:
            return True
        if any(s in self.name.lower() for s in suspicious_names):
            return True
        if self.exe and ("/tmp/" in self.exe or "/dev/shm" in self.exe):
            return True
        if self.exe_path and ("/tmp/" in self.exe_path or "/dev/shm" in self.exe_path):
            return True
        return False
