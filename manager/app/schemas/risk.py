from datetime import datetime
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel


class RiskAssessmentDTO(BaseModel):
    agent_id: str
    cpu_usage: float = 0.0
    process_list: List[Dict[str, Any]] = Field(default_factory=list)
    network_connections: List[Dict[str, Any]] = Field(default_factory=list)
    file_changes_count: int = 0


class RiskScoreOut(ORMBaseModel):
    id: str
    agent_id: str
    score: float
    factors: Dict[str, Any]
    timestamp: datetime
