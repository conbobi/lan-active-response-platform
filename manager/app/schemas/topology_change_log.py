from datetime import datetime
from typing import Optional
from app.schemas.base import ORMBaseModel


class TopologyChangeLogOut(ORMBaseModel):
    id: str
    link_id: str
    event_type: str
    reason: str
    old_cost: Optional[float]
    new_cost: Optional[float]
    timestamp: datetime
