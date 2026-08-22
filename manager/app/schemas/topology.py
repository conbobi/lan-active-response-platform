from datetime import datetime, timezone
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class TopologyUpdateDTO(ORMBaseModel):
    link_id: str = Field(..., description="Unique link identifier")
    source_agent_id: str = Field(..., description="Source agent ID")
    target_agent_id: str = Field(..., description="Target agent ID")
    new_latency: float = Field(..., ge=0.0, description="Latency in ms")
    new_load: float = Field(..., ge=0.0, le=200.0, description="Load ratio percentage")
    new_packet_loss: float = Field(..., ge=0.0, le=100.0, description="Packet loss percentage")
    is_active: bool = Field(True, description="Link active status")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Update timestamp")
    reason: Optional[str] = Field(None, description="Reason for update or change")


class TopologyLinkCreate(ORMBaseModel):
    id: str = Field(..., description="Unique link ID")
    source_agent_id: str
    target_agent_id: str
    capacity: float = Field(1000.0, gt=0.0, description="Total link capacity in Mbps")
    reserved_bandwidth: float = 0.0
    latency: float = Field(1.0, ge=0.0, description="Latency in ms")
    load: float = Field(0.0, ge=0.0, le=100.0, description="Load percentage")
    packet_loss: float = Field(0.0, ge=0.0, le=100.0, description="Packet loss percentage")
    is_active: bool = True


class TopologyLinkUpdate(ORMBaseModel):
    capacity: Optional[float] = None
    reserved_bandwidth: Optional[float] = None
    latency: Optional[float] = None
    load: Optional[float] = None
    packet_loss: Optional[float] = None
    is_active: Optional[bool] = None


class TopologyLinkOut(ORMBaseModel):
    id: str
    source_agent_id: str
    target_agent_id: str
    capacity: float
    reserved_bandwidth: float
    latency: float
    load: float
    packet_loss: float
    is_active: bool
    created_at: datetime
    updated_at: datetime