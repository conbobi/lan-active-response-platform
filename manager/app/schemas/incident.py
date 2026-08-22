from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import IncidentSeverity, IncidentStatus


class IncidentNoteCreate(BaseModel):
    user: str = "system"
    content: str


class IncidentNoteOut(ORMBaseModel):
    id: str
    incident_id: str
    user: str
    content: str
    created_at: datetime


class IncidentAssignDTO(BaseModel):
    user_id: str


class IncidentNoteAddDTO(BaseModel):
    content: str
    user: str = "system"


class IncidentCreate(ORMBaseModel):
    id: str = Field(..., description="Unique incident ID")
    title: str = Field(..., description="Incident summary title")
    description: str = Field(..., description="Detailed description")
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    agent_id: Optional[str] = None
    assigned_to: Optional[str] = None
    risk_score: float = 0.0
    notes: Optional[str] = None


class IncidentUpdate(ORMBaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    risk_score: Optional[float] = None
    notes: Optional[str] = None


class IncidentOut(ORMBaseModel):
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    agent_id: Optional[str]
    assigned_to: Optional[str]
    risk_score: float
    notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
