import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base


class ThreatIndicator(Base):
    """
    Model representing Threat Intelligence indicators (file hashes, malicious IPs, C2 domains).
    """
    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # 'hash', 'ip', 'domain'
    value: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(String(64), default="malware", nullable=False)  # malware, botnet, phishing, c2
    confidence: Mapped[float] = mapped_column(Float, default=80.0, nullable=False)  # 0 - 100
    source: Mapped[str] = mapped_column(String(64), default="external", nullable=False)  # virustotal, abuseipdb, alienvault
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
