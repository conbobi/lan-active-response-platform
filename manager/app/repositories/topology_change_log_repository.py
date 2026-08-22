from typing import List
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.topology_change_log import TopologyChangeLog
from app.repositories.base import SqlAlchemyRepository


class TopologyChangeLogRepository(SqlAlchemyRepository[TopologyChangeLog]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, TopologyChangeLog)

    async def get_recent_logs(self, limit: int = 50) -> List[TopologyChangeLog]:
        stmt = select(TopologyChangeLog).order_by(desc(TopologyChangeLog.timestamp)).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
