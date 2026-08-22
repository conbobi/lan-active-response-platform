from datetime import datetime
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class FlowCreate(ORMBaseModel):
    id: str = Field(..., description="Unique flow ID")
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    packets_sent: int = 0
    start_time: datetime
    end_time: Optional[datetime] = None
    agent_id: Optional[str] = None


class FlowOut(ORMBaseModel):
    id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    packets_sent: int
    start_time: datetime
    end_time: Optional[datetime]
    agent_id: Optional[str]
    created_at: datetime
