from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel


class ProcessGroupBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Unique name of the process group")
    patterns: List[str] = Field(default_factory=list, description="List of process executable patterns")
    description: Optional[str] = Field(default="", max_length=512, description="Optional description of the group")


class ProcessGroupCreate(ProcessGroupBase):
    pass


class ProcessGroupUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    patterns: Optional[List[str]] = None
    description: Optional[str] = Field(default=None, max_length=512)


class ProcessGroupOut(ORMBaseModel):
    id: str
    name: str
    patterns: List[str]
    description: Optional[str] = ""
    created_at: datetime
    updated_at: datetime
