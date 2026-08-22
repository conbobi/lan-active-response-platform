from datetime import datetime
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import IncidentSeverity, IncidentStatus


class IncidentCreate(ORMBaseModel):
    id: str = Field(..., description="Unique incident ID")
    title: str = Field(..., description="Incident summary title")
    description: str = Field(..., description="Detailed description")
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    agent_id: Optional[str] = None
    assigned_to: Optional[str] = None
    risk_score: float = 0.0


class IncidentUpdate(ORMBaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    risk_score: Optional[float] = None


class IncidentOut(ORMBaseModel):
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    agent_id: Optional[str]
    assigned_to: Optional[str]
    risk_score: float
    created_at: datetime
    updated_at: datetime
