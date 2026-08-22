from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import IncidentSeverity


class RuleCreate(ORMBaseModel):
    id: str = Field(..., description="Unique rule ID")
    name: str = Field(..., description="Rule name")
    description: str = Field("", description="Rule description")
    rule_type: str = Field("FLOW", description="Rule type: FLOW or EVENT")
    pattern: Dict[str, Any] = Field(..., description="Matching logic conditions")
    action: str = Field(..., description="Action to trigger upon match")
    is_enabled: bool = True
    severity: IncidentSeverity = IncidentSeverity.MEDIUM


class RuleOut(ORMBaseModel):
    id: str
    name: str
    description: str
    rule_type: str
    pattern: Dict[str, Any]
    action: str
    is_enabled: bool
    severity: IncidentSeverity
    created_at: datetime
