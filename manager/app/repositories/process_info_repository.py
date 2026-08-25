from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.process_info import ProcessInfo
from app.repositories.base import SqlAlchemyRepository


class ProcessInfoRepository(SqlAlchemyRepository[ProcessInfo]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ProcessInfo)

    async def find_by_agent(self, agent_id: str) -> List[ProcessInfo]:
        stmt = select(ProcessInfo).where(ProcessInfo.agent_id == agent_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_suspicious(self) -> List[ProcessInfo]:
        stmt = select(ProcessInfo).where(ProcessInfo.is_suspicious == True)  # noqa: E712
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
        
    async def get_by_agent(self, agent_id: str, limit: int = 500) -> List[ProcessInfo]:
        stmt = select(ProcessInfo).where(ProcessInfo.agent_id == agent_id).order_by(ProcessInfo.created_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_by_agent(self, agent_id: str) -> None:
        from sqlalchemy import delete
        stmt = delete(ProcessInfo).where(ProcessInfo.agent_id == agent_id)
        await self.session.execute(stmt)