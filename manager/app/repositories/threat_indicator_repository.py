from typing import Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.threat_indicator import ThreatIndicator
from app.repositories.base import SqlAlchemyRepository


class ThreatIndicatorRepository(SqlAlchemyRepository[ThreatIndicator]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ThreatIndicator)

    async def lookup(self, value: str, indicator_type: Optional[str] = None) -> Optional[ThreatIndicator]:
        """Lookup threat indicator by value and optional type."""
        stmt = select(ThreatIndicator).where(ThreatIndicator.value == value)
        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
        result = await self.session.execute(stmt)
        return result.scalars().first()
