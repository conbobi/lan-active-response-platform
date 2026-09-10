from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AuthEventItem(BaseModel):
    service: str = "ssh"
    source_ip: str = "unknown"
    username: str = "unknown"
    status: str = "failed"  # failed, success
    count: int = 1
    timestamp: Optional[datetime] = None


class AuthEventDTO(AuthEventItem):
    agent_id: str


class AuthEventOut(AuthEventDTO):
    id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
