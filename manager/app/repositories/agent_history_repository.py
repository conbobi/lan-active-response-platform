from app.repositories.base import SqlAlchemyRepository
from app.models.agent_history import AgentHistory
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
class AgentHistoryRepository(SqlAlchemyRepository[AgentHistory]):
    def __init__(self, db: AsyncSession):
        super().__init__(db, AgentHistory)   # Quan trọng: gán self.db

    async def get_history(self, agent_id: str, limit: int = 50):
        # Dùng SQLAlchemy 2.0 style (async)
        stmt = (
            select(AgentHistory)
            .where(AgentHistory.agent_id == agent_id)
            .order_by(AgentHistory.timestamp.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()