from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class YaraRuleBase(BaseModel):
    name: str
    rule_content: str
    category: str = "malware"
    severity: str = "critical"
    enabled: bool = True


class YaraRuleCreate(YaraRuleBase):
    pass


class YaraRuleUpdate(BaseModel):
    name: Optional[str] = None
    rule_content: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None


class YaraRuleOut(YaraRuleBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class YaraScanRequest(BaseModel):
    agent_id: str
    target_path: str = "/tmp"
    recursive: bool = True


class YaraScanResultDTO(BaseModel):
    agent_id: str
    target_path: str
    matched_rules: List[str]
    matches_count: int
    details: List[Dict[str, Any]]
