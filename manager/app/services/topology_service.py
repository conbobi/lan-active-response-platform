import logging
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.topology import TopologyUpdateDTO
from app.schemas.path import PathRequestDTO, PathResult
from app.schemas.path_release import PathReleaseDTO
from app.schemas.heartbeat import HeartbeatDTO
from app.services.topology_manager import topology_manager, TopologyManager
from app.services.scheduler import Scheduler
from app.core.config import settings
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class TopologyFacade:
    """
    Facade pattern providing simplified entry points for Routers and WebSockets to interact
    with topology operations, path management, and scheduled tasks.
    """
    def __init__(self, manager: TopologyManager = topology_manager):
        self.manager = manager
        self.scheduler = Scheduler()

    async def handle_topology_update(self, dto: TopologyUpdateDTO, session: AsyncSession) -> None:
        """Handle topology link metrics update."""
        await self.manager.process_topology_update(dto, session)

    async def request_path(self, dto: PathRequestDTO, session: AsyncSession) -> PathResult:
        """Request shortest path allocation with capacity constraints."""
        return await self.manager.reserve_path(dto, session)

    async def release_path(self, dto: PathReleaseDTO, session: AsyncSession) -> bool:
        """Release allocated path resources."""
        return await self.manager.process_path_release(dto, session)

    async def process_heartbeat(self, dto: HeartbeatDTO, session: AsyncSession) -> None:
        """Process incoming agent heartbeat."""
        await self.manager.process_heartbeat(dto, session)

    def schedule_background_tasks(self) -> Scheduler:
        """Schedule dead agent sweep and topology recalculation background jobs."""
        async def sweep_job():
            async with AsyncSessionLocal() as session:
                try:
                    await self.manager.sweep_dead_agents(
                        session=session,
                        threshold_seconds=settings.DEAD_AGENT_TIMEOUT_SECONDS
                    )
                    await session.commit()
                except Exception as e:
                    await session.rollback()
                    logger.error(f"Error in dead agent sweep job: {e}", exc_info=True)

        self.scheduler.schedule_task(
            interval_seconds=settings.SWEEP_INTERVAL_SECONDS,
            func=sweep_job
        )
        return self.scheduler


topology_facade = TopologyFacade()