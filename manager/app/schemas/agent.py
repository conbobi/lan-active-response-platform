from datetime import datetime
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import AgentStatus


class AgentCreate(ORMBaseModel):
    id: str = Field(..., description="Unique agent identifier")
    hostname: str = Field(..., description="Agent hostname")
    ip_address: str = Field(..., description="Agent IP address")
    mac_address: str = Field(..., description="Agent MAC address")
    status: AgentStatus = AgentStatus.ACTIVE


class AgentUpdate(ORMBaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    status: Optional[AgentStatus] = None
    management_ip: Optional[str] = None
    cpu: Optional[float] = None
    ram: Optional[float] = None
    disk: Optional[float] = None
    is_isolated: Optional[bool] = None


class AgentOut(ORMBaseModel):
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    status: AgentStatus
    cpu: float
    ram: float
    disk: float
    is_isolated: bool
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    
class AgentHistoryOut(ORMBaseModel):
    id: str
    agent_id: str
    cpu: float
    ram: float
    disk: float
    timestamp: datetime
