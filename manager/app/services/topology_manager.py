from ast import Tuple
from sqlalchemy.ext.asyncio import session
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any, ClassVar
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.topology_link import TopologyLink
from app.models.topology_change_log import TopologyChangeLog
from app.schemas.enums import AgentStatus
from app.schemas.topology import TopologyUpdateDTO
from app.schemas.path import PathRequestDTO, PathResult
from app.schemas.path_release import PathReleaseDTO
from app.schemas.heartbeat import HeartbeatDTO
from app.repositories.topology_link_repository import TopologyLinkRepository
from app.repositories.agent_repository import AgentRepository
from app.repositories.topology_change_log_repository import TopologyChangeLogRepository
from app.services.lock_manager import LockManager
from app.services.path_finder import PathFinder
from app.services.routing_manager import RoutingManager
from app.services.agent_service import AgentService
from app.core.exceptions import NotFoundError, BandwidthExceededError, PathNotFoundError


logger = logging.getLogger(__name__)


class TopologyManager:
    """
    Singleton TopologyManager responsible for network topology graph maintenance,
    dynamic cost recalculation, path reservation, link failure handling, and agent health sweeps.
    """
    _instance: ClassVar[Optional["TopologyManager"]] = None

    def __new__(cls) -> "TopologyManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.lock_manager = LockManager.get_instance()
            cls._instance.routing_manager = RoutingManager()
            cls._instance.graph: Dict[str, List[Dict[str, Any]]] = {}
            cls._instance.links_cache: Dict[str, TopologyLink] = {}
        return cls._instance

    @classmethod
    def get_instance(cls) -> "TopologyManager":
        return cls()

    async def load_graph(self, session: AsyncSession) -> None:
        """Load active topology links from database to construct in-memory graph."""
        link_repo = TopologyLinkRepository(session)
        active_links = await link_repo.get_active_links()

        new_graph: Dict[str, List[Dict[str, Any]]] = {}
        new_links_cache: Dict[str, TopologyLink] = {}

        for link in active_links:
            new_links_cache[link.id] = link
            cost = link.calculate_dynamic_cost()

            # Bidirectional edge assumption in LAN unless directional
            for src, dst in [(link.source_agent_id, link.target_agent_id), (link.target_agent_id, link.source_agent_id)]:
                new_graph.setdefault(src, []).append({
                    "node": dst,
                    "link_id": link.id,
                    "cost": cost,
                    "capacity": link.capacity,
                    "available_capacity": link.get_available_capacity(),
                    "latency": link.latency,
                    "load": link.load,
                    "packet_loss": link.packet_loss,
                    "is_active": link.is_active
                })

        self.graph = new_graph
        self.links_cache = new_links_cache
        logger.info(f"Loaded topology graph with {len(active_links)} active links.")

    async def recalculate_all_costs(self, session: AsyncSession) -> None:
        """Recalculate dynamic routing costs for all cached links and refresh graph."""
        await self.load_graph(session)

    def find_path_with_capacity(
        self,
        source_id: str,
        target_id: str,
        required_bandwidth: float = 0.0,
        exclude_links: Optional[Set[str]] = None
    ) -> tuple[List[str], List[str], float]:
        """Find path satisfying capacity requirement."""
        path_finder = PathFinder(self.graph)
        return path_finder.find_shortest_path(
            source_id=source_id,
            target_id=target_id,
            required_bandwidth=required_bandwidth,
            exclude_links=exclude_links
        )

    async def distribute_traffic_load(self, session: AsyncSession) -> None:
        """Adjust edge costs to prevent bottleneck congestion."""
        await self.recalculate_all_costs(session)

    async def handle_link_failure(self, link_id: str, session: AsyncSession, reason: str = "Link failure detected") -> None:
        """Deactivate broken topology link and update graph."""
        await self.lock_manager.acquire_lock(link_id)
        try:
            link_repo = TopologyLinkRepository(session)
            link = await link_repo.get(link_id)
            if link and link.is_active:
                old_cost = link.calculate_dynamic_cost()
                link.deactivate()
                await self.log_topology_change(
                    link_id=link_id,
                    event_type="FAILED",
                    reason=reason,
                    old_cost=old_cost,
                    new_cost=float("inf"),
                    session=session
                )
                await session.flush()
                await self.recalculate_all_costs(session)
                logger.warning(f"Topology link '{link_id}' marked FAILED.")
        finally:
            self.lock_manager.release_lock(link_id)

    async def process_topology_update(self, dto: TopologyUpdateDTO, session: AsyncSession) -> None:
        """Process link parameter updates reported from agents."""
        await self.lock_manager.acquire_lock(dto.link_id)
        try:
            link_repo = TopologyLinkRepository(session)
            link = await link_repo.get(dto.link_id)
            if not link:
                # Auto-create link if it does not exist
                link = TopologyLink(
                    id=dto.link_id,
                    source_agent_id=dto.source_agent_id,
                    target_agent_id=dto.target_agent_id,
                    latency=dto.new_latency,
                    load=dto.new_load,
                    packet_loss=dto.new_packet_loss,
                    is_active=dto.is_active
                )
                await link_repo.add(link)
                old_cost = None
                event_type = "CREATED"
            else:
                old_cost = link.calculate_dynamic_cost()
                link.update_from_dto(dto)
                event_type = "UPDATED"

            new_cost = link.calculate_dynamic_cost()
            await self.log_topology_change(
                link_id=dto.link_id,
                event_type=event_type,
                reason=dto.reason or "Periodic topology update",
                old_cost=old_cost,
                new_cost=new_cost,
                session=session
            )
            await session.flush()
            await self.recalculate_all_costs(session)
        finally:
            self.lock_manager.release_lock(dto.link_id)

    async def process_heartbeat(self, dto: HeartbeatDTO, session: AsyncSession) -> None:
        """Process agent heartbeat."""
        agent_service = AgentService(session)
        await agent_service.update_heartbeat(dto)
        from app.websocket.dashboard_connection_manager import dashboard_manager
        await dashboard_manager.broadcast({
            "type": "heartbeat",
            "data": dto.model_dump(mode="json")
        })

    async def reserve_path(self, dto: PathRequestDTO, session: AsyncSession) -> PathResult:
        """Reserve path and allocate bandwidth for a flow request."""
        exclude_links = set(dto.exclude_link_ids)
        nodes, link_ids, total_cost = self.find_path_with_capacity(
            source_id=dto.source_agent_id,
            target_id=dto.destination_agent_id,
            required_bandwidth=dto.required_bandwidth,
            exclude_links=exclude_links
        )

        # Acquire locks on all links along path to avoid concurrency race
        acquired_locks = []
        try:
            for link_id in link_ids:
                await self.lock_manager.acquire_lock(link_id)
                acquired_locks.append(link_id)

            link_repo = TopologyLinkRepository(session)
            total_latency = 0.0
            total_load = 0.0

            for link_id in link_ids:
                link = await link_repo.get(link_id)
                if not link:
                    raise NotFoundError(f"Link '{link_id}' not found during reservation.")
                link.reserve_bandwidth(dto.required_bandwidth)
                total_latency += link.latency
                total_load += link.load

            await session.flush()
            await self.recalculate_all_costs(session)

            avg_load = total_load / len(link_ids) if link_ids else 0.0
            reservation = self.routing_manager.create_path_reservation(
                source_id=dto.source_agent_id,
                target_id=dto.destination_agent_id,
                path_nodes=nodes,
                link_ids=link_ids,
                allocated_bandwidth=dto.required_bandwidth,
                total_cost=total_cost
            )

            return PathResult(
                session_id=reservation.session_id,
                path=nodes,
                link_ids=link_ids,
                total_cost=total_cost,
                total_latency=total_latency,
                allocated_bandwidth=dto.required_bandwidth,
                load_ratio=avg_load,
                found=True
            )
        finally:
            for link_id in acquired_locks:
                self.lock_manager.release_lock(link_id)

    async def release_path(self, session_id: str, session: AsyncSession) -> bool:
        """Release reserved path bandwidth by session ID."""
        path_info = self.routing_manager.release_path_reservation(session_id)
        if not path_info:
            return False

        link_repo = TopologyLinkRepository(session)
        for link_id in path_info.link_ids:
            await self.lock_manager.acquire_lock(link_id)
            try:
                link = await link_repo.get(link_id)
                if link:
                    link.release_bandwidth(path_info.allocated_bandwidth)
            finally:
                self.lock_manager.release_lock(link_id)

        await session.flush()
        await self.recalculate_all_costs(session)
        logger.info(f"Released path session '{session_id}'.")
        return True

    async def process_path_release(self, dto: PathReleaseDTO, session: AsyncSession) -> bool:
        """Process explicit PathReleaseDTO."""
        if dto.session_id and dto.session_id in self.routing_manager.active_paths:
            return await self.release_path(dto.session_id, session)

        # Fallback release directly on specified link_ids
        link_repo = TopologyLinkRepository(session)
        for link_id in dto.link_ids:
            await self.lock_manager.acquire_lock(link_id)
            try:
                link = await link_repo.get(link_id)
                if link:
                    link.release_bandwidth(dto.allocated_bandwidth)
            finally:
                self.lock_manager.release_lock(link_id)

        await session.flush()
        await self.recalculate_all_costs(session)
        return True

    async def sweep_dead_agents(self, session: AsyncSession, threshold_seconds: int = 30) -> List[str]:
        """Detect and deactivate unresponsive agents and their links."""
        agent_repo = AgentRepository(session)
        dead_agents = await agent_repo.get_dead_agents(threshold_seconds=threshold_seconds)
        dead_ids = []

        if dead_agents:
            link_repo = TopologyLinkRepository(session)
            for agent in dead_agents:
                agent.status = AgentStatus.DEAD
                dead_ids.append(agent.id)

                # Deactivate links associated with this agent
                agent_links = await link_repo.find_by_agent(agent.id)
                for link in agent_links:
                    if link.is_active:
                        link.deactivate()
                        await self.log_topology_change(
                            link_id=link.id,
                            event_type="FAILED",
                            reason=f"Agent '{agent.id}' heartbeat timeout (DEAD)",
                            old_cost=link.calculate_dynamic_cost(),
                            new_cost=float("inf"),
                            session=session
                        )

            await session.flush()
            await self.recalculate_all_costs(session)
            logger.warning(f"Dead agent sweep detected {len(dead_ids)} unresponsive agents: {dead_ids}")
            from app.websocket.dashboard_connection_manager import dashboard_manager
            await dashboard_manager.broadcast({
                "type": "dead_agent",
                "data": {"agent_id": dead_ids, "status": "DEAD"}
            })
        return dead_ids

    async def log_topology_change(
        self,
        link_id: str,
        event_type: str,
        reason: str,
        old_cost: Optional[float],
        new_cost: Optional[float],
        session: AsyncSession
    ) -> TopologyChangeLog:
        """Create a topology change audit log."""
        log_repo = TopologyChangeLogRepository(session)
        log_entry = TopologyChangeLog(
            id=f"log_{uuid.uuid4().hex[:12]}",
            link_id=link_id,
            event_type=event_type,
            reason=reason,
            old_cost=old_cost,
            new_cost=new_cost,
            timestamp=datetime.now(timezone.utc)
        )
        return await log_repo.add(log_entry)


topology_manager = TopologyManager()