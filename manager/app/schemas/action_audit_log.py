from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class ActionAuditLogResponse(ORMBaseModel):
    id: str
    action_id: str
    event: str
    actor: str
    reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict, alias="metadata_")
    created_at: datetime

    class Config:
        populate_by_name = True
