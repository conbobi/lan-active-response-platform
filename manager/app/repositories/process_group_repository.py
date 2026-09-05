from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.process_group import ProcessGroup
from app.repositories.base import SqlAlchemyRepository


class ProcessGroupRepository(SqlAlchemyRepository[ProcessGroup]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ProcessGroup)

    async def get_by_name(self, name: str) -> Optional[ProcessGroup]:
        stmt = select(ProcessGroup).where(ProcessGroup.name == name)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_all(self, skip: int = 0, limit: int = 100) -> List[ProcessGroup]:
        stmt = select(ProcessGroup).order_by(ProcessGroup.name.asc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
