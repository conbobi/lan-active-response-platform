from typing import Optional, List
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.topology_link import TopologyLink
from app.repositories.base import SqlAlchemyRepository


class TopologyLinkRepository(SqlAlchemyRepository[TopologyLink]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, TopologyLink)

    async def find_by_agent_pair(self, source_id: str, target_id: str) -> Optional[TopologyLink]:
        stmt = select(TopologyLink).where(
            TopologyLink.source_agent_id == source_id,
            TopologyLink.target_agent_id == target_id
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_links(self) -> List[TopologyLink]:
        stmt = select(TopologyLink).where(TopologyLink.is_active == True)  # noqa: E712
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_agent(self, agent_id: str) -> List[TopologyLink]:
        stmt = select(TopologyLink).where(
            or_(
                TopologyLink.source_agent_id == agent_id,
                TopologyLink.target_agent_id == agent_id
            )
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
