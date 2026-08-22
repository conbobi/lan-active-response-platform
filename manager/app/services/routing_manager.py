import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class PathInfo:
    session_id: str
    source_id: str
    target_id: str
    path_nodes: List[str]
    link_ids: List[str]
    allocated_bandwidth: float
    total_cost: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RoutingEntry:
    destination_id: str
    next_hop: str
    link_id: str
    cost: float


class RoutingManager:
    """
    Manages active routing tables and path reservations.
    """
    def __init__(self):
        # session_id -> PathInfo
        self.active_paths: Dict[str, PathInfo] = {}
        # source_id -> (destination_id -> RoutingEntry)
        self.routing_tables: Dict[str, Dict[str, RoutingEntry]] = {}

    def create_path_reservation(
        self,
        source_id: str,
        target_id: str,
        path_nodes: List[str],
        link_ids: List[str],
        allocated_bandwidth: float,
        total_cost: float
    ) -> PathInfo:
        session_id = f"path_sess_{uuid.uuid4().hex[:12]}"
        path_info = PathInfo(
            session_id=session_id,
            source_id=source_id,
            target_id=target_id,
            path_nodes=path_nodes,
            link_ids=link_ids,
            allocated_bandwidth=allocated_bandwidth,
            total_cost=total_cost
        )
        self.active_paths[session_id] = path_info
        return path_info

    def release_path_reservation(self, session_id: str) -> Optional[PathInfo]:
        return self.active_paths.pop(session_id, None)

    def get_path_reservation(self, session_id: str) -> Optional[PathInfo]:
        return self.active_paths.get(session_id)

    def update_routing_table(self, source_id: str, destination_id: str, next_hop: str, link_id: str, cost: float) -> None:
        if source_id not in self.routing_tables:
            self.routing_tables[source_id] = {}
        self.routing_tables[source_id][destination_id] = RoutingEntry(
            destination_id=destination_id,
            next_hop=next_hop,
            link_id=link_id,
            cost=cost
        )
