from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.incident import Incident
from app.repositories.incident_repository import IncidentRepository
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.core.exceptions import NotFoundError
from app.services.base import AbstractService


class IncidentService(AbstractService[IncidentRepository]):
    def __init__(self, session: AsyncSession):
        repo = IncidentRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def create_incident(self, dto: IncidentCreate) -> Incident:
        inc = Incident(
            id=dto.id,
            title=dto.title,
            description=dto.description,
            severity=dto.severity,
            agent_id=dto.agent_id,
            assigned_to=dto.assigned_to,
            risk_score=dto.risk_score
        )
        return await self.repository.add(inc)

    async def update_incident(self, incident_id: str, dto: IncidentUpdate) -> Incident:
        inc = await self.repository.update(incident_id, dto)
        if not inc:
            raise NotFoundError(f"Incident '{incident_id}' not found.")
        return inc

    async def get_incident(self, incident_id: str) -> Incident:
        inc = await self.repository.get(incident_id)
        if not inc:
            raise NotFoundError(f"Incident '{incident_id}' not found.")
        return inc

    async def list_incidents(self, skip: int = 0, limit: int = 100) -> List[Incident]:
        return await self.repository.list(skip=skip, limit=limit)

    async def assign_incident(self, incident_id: str, user_id: str) -> Incident:
        inc = await self.get_incident(incident_id)
        inc.assign_to(user_id)
        await self.session.flush()
        return inc

    async def resolve_incident(self, incident_id: str) -> Incident:
        inc = await self.get_incident(incident_id)
        inc.resolve()
        await self.session.flush()
        return inc
