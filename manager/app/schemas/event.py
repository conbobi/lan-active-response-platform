from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import IncidentSeverity


class EventCreate(ORMBaseModel):
    id: Optional[str] = None
    agent_id: str = Field(..., description="Agent ID reporting event")
    event_type: str = Field(..., description="Event classification type")
    severity: IncidentSeverity = IncidentSeverity.LOW
    source: str = Field("AGENT", description="Source component")
    details: Dict[str, Any] = Field(default_factory=dict, description="Event metadata/payload")


class EventOut(ORMBaseModel):
    id: str
    agent_id: str
    event_type: str
    severity: IncidentSeverity
    source: str
    details: Dict[str, Any]
    processed: bool
    created_at: datetime
