from datetime import datetime
from typing import Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class ProcessInfoCreate(ORMBaseModel):
    id: str = Field(..., description="Unique process record ID")
    agent_id: str = Field(..., description="Agent ID")
    pid: int = Field(..., description="Process ID")
    name: str = Field(..., description="Process executable name")
    exe: str = Field("", description="Process full binary path")
    cmdline: str = Field("", description="Command line string")
    cpu_percent: float = Field(0.0, ge=0.0)
    memory_percent: float = Field(0.0, ge=0.0)
    hash: Optional[str] = Field(None, description="SHA256 executable hash")
    is_suspicious: bool = False


class ProcessInfoOut(ORMBaseModel):
    id: str
    agent_id: str
    pid: int
    name: str
    exe: str
    cmdline: str
    cpu_percent: float
    memory_percent: float
    hash: Optional[str]
    is_suspicious: bool
    created_at: datetime
