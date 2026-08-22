from datetime import datetime
from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.report import Report
from app.repositories.base import SqlAlchemyRepository


class ReportRepository(SqlAlchemyRepository[Report]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Report)

    async def get_by_period(self, start: datetime, end: datetime) -> List[Report]:
        """Fetch reports generated within a given date period."""
        stmt = (
            select(Report)
            .where(Report.period_start >= start, Report.period_end <= end)
            .order_by(Report.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
