from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.schemas.base import ORMBaseModel


class WhitelistEntryCreate(BaseModel):
    agent_id: Optional[str] = None
    process_name: Optional[str] = None
    path: Optional[str] = None
    reason: str


class WhitelistEntryOut(ORMBaseModel):
    id: str
    agent_id: Optional[str] = None
    process_name: Optional[str] = None
    path: Optional[str] = None
    reason: str
    created_at: datetime
