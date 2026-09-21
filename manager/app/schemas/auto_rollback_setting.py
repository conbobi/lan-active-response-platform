from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class AutoRollbackSettingRequest(ORMBaseModel):
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=86400, description="Auto-rollback timeout in seconds")
    enabled: Optional[bool] = Field(default=None, description="Enable or disable auto-rollback")
    cooldown_seconds: Optional[int] = Field(default=None, ge=0, le=86400, description="Anti-flapping cooldown in seconds")


class AutoRollbackSettingResponse(ORMBaseModel):
    timeout_seconds: int = 300
    enabled: bool = True
    cooldown_seconds: int = 600
