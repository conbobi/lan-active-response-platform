from datetime import datetime, timezone
from typing import List, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class PathReleaseDTO(ORMBaseModel):
    session_id: str = Field(..., description="Unique path session identifier to release")
    link_ids: List[str] = Field(..., description="List of link IDs to release reserved bandwidth from")
    allocated_bandwidth: float = Field(..., ge=0.0, description="Amount of bandwidth to release in Mbps")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Release timestamp")
