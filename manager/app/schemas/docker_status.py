from typing import List, Optional
from pydantic import BaseModel, Field


class ContainerStatusOut(BaseModel):
    """Schema representing metrics and status for a single Docker container."""
    container_id: str = Field(..., description="Short container ID (12 characters)")
    name: str = Field(..., description="Container name without leading slash")
    status: str = Field(..., description="Current status: running, exited, restarting, paused, etc.")
    uptime: str = Field("N/A", description="Human-readable uptime or stop time")
    cpu_percent: float = Field(0.0, description="CPU usage percentage")
    memory_usage: float = Field(0.0, description="Memory used in megabytes (MB)")
    memory_limit: float = Field(0.0, description="Memory limit in megabytes (MB)")
    network_rx: float = Field(0.0, description="Total network bytes received")
    network_tx: float = Field(0.0, description="Total network bytes transmitted")


class DockerStatusResponse(BaseModel):
    """Summary response for Docker daemon status and list of monitored containers."""
    available: bool = Field(True, description="Whether Docker daemon is reachable")
    error: Optional[str] = Field(None, description="Error message if Docker daemon is unreachable")
    total_containers: int = Field(0, description="Total number of monitored containers")
    containers: List[ContainerStatusOut] = Field(default_factory=list, description="List of containers")
