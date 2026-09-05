from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.flow import Flow
from app.repositories.base import SqlAlchemyRepository


class FlowRepository(SqlAlchemyRepository[Flow]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Flow)

    async def find_by_agent(self, agent_id: str) -> List[Flow]:
        stmt = select(Flow).where(Flow.agent_id == agent_id).order_by(Flow.start_time.asc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_recent_flows(self, minutes: int = 15, agent_id: Optional[str] = None) -> List[Flow]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        stmt = select(Flow).where(Flow.start_time >= cutoff)
        if agent_id and agent_id.lower() not in ("all", "none", "null"):
            if agent_id == "manager":
                stmt = stmt.where(Flow.agent_id.is_(None))
            else:
                stmt = stmt.where(Flow.agent_id == agent_id)
        stmt = stmt.order_by(Flow.start_time.asc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_flows_paginated(
        self,
        skip: int = 0,
        limit: int = 100,
        agent_id: Optional[str] = None
    ) -> List[Flow]:
        stmt = select(Flow)
        if agent_id and agent_id.lower() not in ("all", "none", "null"):
            if agent_id == "manager":
                stmt = stmt.where(Flow.agent_id.is_(None))
            else:
                stmt = stmt.where(Flow.agent_id == agent_id)
        stmt = stmt.order_by(Flow.start_time.asc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
