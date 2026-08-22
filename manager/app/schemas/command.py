from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import CommandStatus


class CommandCreate(ORMBaseModel):
    id: str = Field(..., description="Unique command ID")
    agent_id: str = Field(..., description="Target agent ID")
    action: str = Field(..., description="Command action name (e.g. isolate, unisolate, block_ip)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Action payload parameters")
    max_retries: int = Field(3, ge=0)


class CommandOut(ORMBaseModel):
    id: str
    agent_id: str
    action: str
    payload: Dict[str, Any]
    status: CommandStatus
    retry_count: int
    max_retries: int
    error_message: Optional[str]
    issued_at: datetime
    executed_at: Optional[datetime]
    created_at: datetime
