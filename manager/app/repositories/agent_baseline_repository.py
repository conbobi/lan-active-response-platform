from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent_baseline import AgentBaseline
from app.repositories.base import SqlAlchemyRepository


class AgentBaselineRepository(SqlAlchemyRepository[AgentBaseline]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, AgentBaseline)

    async def get_by_agent(self, agent_id: str) -> Optional[AgentBaseline]:
        stmt = select(AgentBaseline).where(AgentBaseline.agent_id == agent_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_all_baselines(self) -> List[AgentBaseline]:
        stmt = select(AgentBaseline).order_by(AgentBaseline.last_trained_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
