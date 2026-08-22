from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.risk_score import RiskScoreRecord
from app.repositories.base import SqlAlchemyRepository


class RiskScoreRepository(SqlAlchemyRepository[RiskScoreRecord]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, RiskScoreRecord)

    async def get_latest_by_agent(self, agent_id: str, limit: int = 10) -> List[RiskScoreRecord]:
        """Fetch latest risk score records for a specific agent."""
        stmt = (
            select(RiskScoreRecord)
            .where(RiskScoreRecord.agent_id == agent_id)
            .order_by(RiskScoreRecord.timestamp.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
