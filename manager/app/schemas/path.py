from typing import List, Optional
from pydantic import Field
from app.schemas.base import ORMBaseModel


class PathRequestDTO(ORMBaseModel):
    source_agent_id: str = Field(..., description="Starting agent node ID")
    destination_agent_id: str = Field(..., description="Target agent node ID")
    required_bandwidth: float = Field(0.0, ge=0.0, description="Required bandwidth in Mbps")
    priority: int = Field(1, ge=1, le=10, description="Traffic priority level (1-10)")
    exclude_link_ids: List[str] = Field(default_factory=list, description="Links to exclude from pathfinding")
    max_hops: int = Field(10, ge=1, description="Maximum hops permitted")


class PathResult(ORMBaseModel):
    session_id: str = Field(..., description="Unique path reservation session ID")
    path: List[str] = Field(..., description="Sequence of agent IDs forming the path")
    link_ids: List[str] = Field(..., description="Sequence of topology link IDs used")
    total_cost: float = Field(..., description="Cumulative Dijkstra path cost")
    total_latency: float = Field(..., description="Cumulative latency in ms")
    allocated_bandwidth: float = Field(..., description="Allocated bandwidth in Mbps")
    load_ratio: float = Field(..., description="Average load ratio along path")
    found: bool = Field(True, description="Whether a valid path was discovered")
