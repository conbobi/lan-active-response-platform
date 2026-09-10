from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class ThreatFeedBase(BaseModel):
    name: str
    url: str
    feed_type: str = "ip"  # 'ip', 'hash', 'domain', 'url'
    enabled: bool = True
    interval_hours: int = 6


class ThreatFeedCreate(ThreatFeedBase):
    pass


class ThreatFeedUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    feed_type: Optional[str] = None
    enabled: Optional[bool] = None
    interval_hours: Optional[int] = None


class ThreatFeedOut(ThreatFeedBase):
    id: str
    last_sync_at: Optional[datetime] = None
    status: str
    indicator_count: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatFeedSyncResult(BaseModel):
    feed_id: str
    name: str
    status: str
    indicators_added: int
    indicators_updated: int
    message: str
