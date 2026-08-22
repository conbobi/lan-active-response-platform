from datetime import datetime, timezone, timedelta
from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.flow import Flow
from app.repositories.base import SqlAlchemyRepository


class FlowRepository(SqlAlchemyRepository[Flow]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Flow)

    async def find_by_agent(self, agent_id: str) -> List[Flow]:
        stmt = select(Flow).where(Flow.agent_id == agent_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_recent_flows(self, minutes: int = 15) -> List[Flow]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        stmt = select(Flow).where(Flow.start_time >= cutoff)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
