from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.incident import Incident
from app.schemas.enums import IncidentStatus
from app.repositories.base import SqlAlchemyRepository


class IncidentRepository(SqlAlchemyRepository[Incident]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Incident)

    async def find_open_incidents(self) -> List[Incident]:
        stmt = select(Incident).where(
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS])
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_agent(self, agent_id: str) -> List[Incident]:
        stmt = select(Incident).where(Incident.agent_id == agent_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
