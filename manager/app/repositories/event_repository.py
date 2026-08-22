from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.event import Event
from app.repositories.base import SqlAlchemyRepository


class EventRepository(SqlAlchemyRepository[Event]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Event)

    async def get_unprocessed_events(self) -> List[Event]:
        stmt = select(Event).where(Event.processed == False)  # noqa: E712
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def mark_processed(self, event_id: str) -> Optional[Event]:
        ev = await self.get(event_id)
        if ev:
            ev.process()
            await self.session.flush()
            await self.session.refresh(ev)
        return ev
