from datetime import datetime, timezone
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class HeartbeatDTO(ORMBaseModel):
    agent_id: str = Field(..., description="ID of the agent sending the heartbeat")
    cpu: float = Field(0.0, ge=0.0, le=100.0, description="CPU usage percentage")
    ram: float = Field(0.0, ge=0.0, le=100.0, description="RAM usage percentage")
    disk: float = Field(0.0, ge=0.0, le=100.0, description="Disk usage percentage")
    ip_address: str = Field("127.0.0.1", description="IP address of the agent")
    mac_address: str = Field("00:00:00:00:00:00", description="MAC address of the agent")
    hostname: Optional[str] = Field(None, description="Hostname of the agent")
    platform: Optional[str] = Field(None, description="Platform / OS of the agent")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of heartbeat")

    model_config = {"extra": "allow"}
