from datetime import datetime, timezone
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel
from app.schemas.enums import CommandStatus


class CommandAckDTO(ORMBaseModel):
    command_id: str = Field(..., description="ID of the acknowledged command")
    status: CommandStatus = Field(..., description="Execution result status")
    error_message: Optional[str] = Field(None, description="Error message if execution failed")
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Execution timestamp")
