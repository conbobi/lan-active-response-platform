from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel


class DetectionRuleBase(BaseModel):
    rule_id: str
    name: str
    description: str = ""
    enabled: bool = True
    weight: float = 1.0
    base_score: float = 1.0
    category: str = "os"
    config: Dict[str, Any] = Field(default_factory=dict)


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    weight: Optional[float] = None
    base_score: Optional[float] = None
    category: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class DetectionRuleOut(ORMBaseModel):
    id: str
    rule_id: str
    name: str
    description: str
    enabled: bool
    weight: float
    base_score: float
    category: str
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
