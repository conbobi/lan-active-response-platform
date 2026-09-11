import uuid
from typing import List, Optional, Dict, Any
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

    async def get_latest_one_by_agent(self, agent_id: str) -> Optional[RiskScoreRecord]:
        """Fetch single latest risk score record for a specific agent."""
        stmt = (
            select(RiskScoreRecord)
            .where(RiskScoreRecord.agent_id == agent_id)
            .order_by(RiskScoreRecord.timestamp.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(
        self,
        agent_id: str,
        score: float,
        smoothed_score: Optional[float] = None,
        factors: Optional[Dict[str, Any]] = None
    ) -> RiskScoreRecord:
        """Create and store a risk score record."""
        record = RiskScoreRecord(
            id=f"risk_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            score=score,
            smoothed_score=smoothed_score,
            factors=factors or {}
        )
        return await self.add(record)

