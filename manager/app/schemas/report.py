from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.schemas.base import ORMBaseModel


class ReportGenerateRequest(BaseModel):
    month: Optional[int] = None
    year: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    title: Optional[str] = None


class ReportOut(ORMBaseModel):
    id: str
    title: str
    period_start: datetime
    period_end: datetime
    file_path: str
    format: str
    created_at: datetime
