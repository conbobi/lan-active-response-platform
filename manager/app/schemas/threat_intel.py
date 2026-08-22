from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.schemas.base import ORMBaseModel


class ThreatCheckDTO(BaseModel):
    indicator_type: str  # 'hash', 'ip', 'domain'
    value: str


class ThreatIndicatorOut(ORMBaseModel):
    id: str
    indicator_type: str
    value: str
    threat_type: str
    confidence: float
    source: str
    created_at: datetime
