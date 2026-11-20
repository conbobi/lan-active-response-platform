import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class WebAccessLog(Base):
    """
    Model representing HTTP web access requests captured by NDR / Agent log monitor
    (e.g. from Cloudflare Tunnel cloudflared or Web Server access logs).
    Used for web brute-force detection (T1110), scanning tool identification,
    and web application vulnerability exploitation attempts (T1190).
    """
    __tablename__ = "web_access_logs"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"wlog_{uuid.uuid4().hex[:12]}"
    )
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(128), default="", nullable=True)
    method: Mapped[str] = mapped_column(String(16), default="GET", nullable=False)
    path: Mapped[str] = mapped_column(String(1024), default="/", nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), default="", nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, default=200, nullable=False)
    raw_message: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

