from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import ResponseActionType, ResponseActionStatus


class ResponseActionCreate(ORMBaseModel):
    agent_id: str
    incident_id: Optional[str] = None
    action_type: ResponseActionType
    action_params: Dict[str, Any] = Field(default_factory=dict)
    auto_rollback_seconds: Optional[int] = None  # None = use system default setting


class ResponseActionResponse(ORMBaseModel):
    id: str
    incident_id: Optional[str] = None
    agent_id: str
    action_type: str
    action_params: Dict[str, Any]
    status: str
    snapshot: Optional[Dict[str, Any]] = None
    applied_at: Optional[datetime] = None
    undone_at: Optional[datetime] = None
    undo_reason: Optional[str] = None
    undone_by: Optional[str] = None
    auto_rollback_at: Optional[datetime] = None
    cooldown_until: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class UndoActionRequest(ORMBaseModel):
    reason: Optional[str] = Field(default="Manual undo via UI/API", max_length=255)


class UndoBatchRequest(ORMBaseModel):
    reason: Optional[str] = Field(default="Batch undo via UI/API", max_length=255)


class UndoBatchResponse(ORMBaseModel):
    reverted: int
    failed: int
    action_ids: List[str]
    details: List[Dict[str, Any]] = Field(default_factory=list)
