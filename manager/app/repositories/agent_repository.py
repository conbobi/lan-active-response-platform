from datetime import datetime, timezone, timedelta
from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent import Agent
from app.schemas.enums import AgentStatus
from app.repositories.base import SqlAlchemyRepository


class AgentRepository(SqlAlchemyRepository[Agent]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Agent)

    async def find_by_hostname(self, hostname: str) -> Optional[Agent]:
        stmt = select(Agent).where(Agent.hostname == hostname)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_ip(self, ip_address: str) -> Optional[Agent]:
        stmt = select(Agent).where(Agent.ip_address == ip_address)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_agents(self) -> List[Agent]:
        stmt = select(Agent).where(Agent.status == AgentStatus.ACTIVE)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_dead_agents(self, threshold_seconds: int = 30) -> List[Agent]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=threshold_seconds)
        stmt = select(Agent).where(
            Agent.last_seen < cutoff,
            Agent.status.in_([AgentStatus.ACTIVE, AgentStatus.ISOLATED])
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())