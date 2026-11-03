from datetime import datetime
from typing import Optional, List, Dict, Any
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
    label: Optional[str] = None
    label_reason: Optional[str] = None
    labeled_by: Optional[str] = None
    labeled_at: Optional[datetime] = None


class IncidentLabelUpdate(BaseModel):
    status: Optional[str] = None
    label: Optional[str] = None
    label_reason: Optional[str] = None
    labeled_by: Optional[str] = "current_user"


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
    label: Optional[str] = None
    label_reason: Optional[str] = None
    labeled_by: Optional[str] = None
    labeled_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    culprit_process: Optional[dict] = None
    parent_process: Optional[dict] = None
    network_indicators: Optional[list] = None
    factors_breakdown: Optional[list] = None


class AIAnalysisOut(ORMBaseModel):
    id: str
    incident_id: str
    analysis_type: str = "triage"
    summary: str
    mitre_techniques: Optional[List[Dict[str, Any]]] = None
    root_cause: Optional[str] = None
    model_name: Optional[str] = None
    confidence: float = 0.0
    analyst_rating: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    suggested_action: Optional[str] = None
    suggestion_params: Optional[Dict[str, Any]] = None
    suggestion_reasoning: Optional[str] = None
    blast_radius: Optional[Dict[str, Any]] = None
    applied_by_analyst: Optional[str] = None
    applied_at: Optional[datetime] = None
    dismissed_by_analyst: Optional[str] = None
    dismissed_at: Optional[datetime] = None
    dismiss_reason: Optional[str] = None


class AIAnalysisRateDTO(BaseModel):
    rating: str  # "helpful" | "wrong"


# Alias for backward compatibility
IncidentResponse = IncidentOut

