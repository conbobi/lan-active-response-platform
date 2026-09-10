from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.threat_feed import ThreatFeed
from app.repositories.base import SqlAlchemyRepository


class ThreatFeedRepository(SqlAlchemyRepository[ThreatFeed]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ThreatFeed)

    async def get_enabled_feeds(self) -> List[ThreatFeed]:
        stmt = select(ThreatFeed).where(ThreatFeed.enabled == True)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_name(self, name: str) -> Optional[ThreatFeed]:
        stmt = select(ThreatFeed).where(ThreatFeed.name == name)
        result = await self.session.execute(stmt)
        return result.scalars().first()
