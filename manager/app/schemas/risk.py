from datetime import datetime
from typing import List, Dict, Any, Union
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel



class RiskAssessmentDTO(BaseModel):
    agent_id: str
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    disk_usage: float = 0.0
    process_list: List[Dict[str, Any]] = Field(default_factory=list)
    network_connections: List[Dict[str, Any]] = Field(default_factory=list)
    file_changes_count: int = 0
    suspicious_commands: List[str] = Field(default_factory=list)
    shadow_copy_deletion: bool = False
    registry_changes: List[Dict[str, Any]] = Field(default_factory=list)
    credential_access_events: List[Dict[str, Any]] = Field(default_factory=list)
    lateral_movement_events: List[Dict[str, Any]] = Field(default_factory=list)
    mass_file_modification: bool = False
    dns_queries: List[Union[str, Dict[str, Any]]] = Field(default_factory=list)
    process_tree: List[Dict[str, Any]] = Field(default_factory=list)
    auth_events: List[Dict[str, Any]] = Field(default_factory=list)
    connection_history: List[Dict[str, Any]] = Field(default_factory=list)
    yara_matches: List[str] = Field(default_factory=list)


class RiskScoreOut(ORMBaseModel):
    id: str
    agent_id: str
    score: float
    factors: Dict[str, Any]
    timestamp: datetime
