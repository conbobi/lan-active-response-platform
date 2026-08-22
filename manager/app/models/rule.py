from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, Boolean, Enum, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base
from app.schemas.enums import IncidentSeverity


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), default="")
    rule_type: Mapped[str] = mapped_column(String(32), default="FLOW")  # FLOW or EVENT
    pattern: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., ISOLATE, ALERT, LOG
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def match(self, target: Any) -> bool:
        """Check if target object (Flow or Event DTO/Model) matches rule pattern."""
        if not self.is_enabled:
            return False
        for key, value in self.pattern.items():
            target_val = getattr(target, key, None)
            if target_val is None and isinstance(target, dict):
                target_val = target.get(key)
            if target_val != value:
                return False
        return True
