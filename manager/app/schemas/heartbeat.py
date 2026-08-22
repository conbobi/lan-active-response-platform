from datetime import datetime, timezone
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class HeartbeatDTO(ORMBaseModel):
    agent_id: str = Field(..., description="ID of the agent sending the heartbeat")
    cpu: float = Field(..., ge=0.0, le=100.0, description="CPU usage percentage")
    ram: float = Field(..., ge=0.0, le=100.0, description="RAM usage percentage")
    disk: float = Field(..., ge=0.0, le=100.0, description="Disk usage percentage")
    ip_address: str = Field(..., description="IP address of the agent")
    mac_address: str = Field(..., description="MAC address of the agent")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of heartbeat")
