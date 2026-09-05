from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel
from app.schemas.process_group import ProcessGroupOut


class ProcessChainAction(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    ISOLATE = "isolate"


class ProcessChainRuleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Name of the process chain rule")
    parent_group_id: str = Field(..., description="ID of parent ProcessGroup")
    child_group_id: str = Field(..., description="ID of child ProcessGroup")
    action: str = Field(default="alert", description="Action to trigger: alert, block, or isolate")
    is_active: bool = Field(default=True, description="Whether rule is currently active")


class ProcessChainRuleCreate(ProcessChainRuleBase):
    pass


class ProcessChainRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    parent_group_id: Optional[str] = None
    child_group_id: Optional[str] = None
    action: Optional[str] = None
    is_active: Optional[bool] = None


class ProcessChainRuleOut(ORMBaseModel):
    id: str
    name: str
    parent_group_id: str
    child_group_id: str
    action: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    parent_group: Optional[ProcessGroupOut] = None
    child_group: Optional[ProcessGroupOut] = None
