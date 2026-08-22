import uuid
import logging
from typing import List, Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.repositories.incident_repository import IncidentRepository
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.schemas.enums import IncidentSeverity, IncidentStatus
from app.core.exceptions import NotFoundError
from app.services.base import AbstractService

logger = logging.getLogger(__name__)


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
            risk_score=dto.risk_score,
            notes=dto.notes
        )
        return await self.repository.add(inc)

    async def create_from_risk(
        self,
        agent_id: str,
        risk_score: float,
        factors: Dict[str, Any]
    ) -> Incident:
        """Automated incident creation triggered by high risk score (> 80)."""
        inc_id = f"inc_{uuid.uuid4().hex[:12]}"
        severity = IncidentSeverity.CRITICAL if risk_score >= 90.0 else IncidentSeverity.HIGH
        title = f"High Risk Alert for Agent '{agent_id}' (Score: {risk_score})"
        desc = f"Automated incident generated due to risk score {risk_score}. Factors: {factors}"

        inc = Incident(
            id=inc_id,
            title=title,
            description=desc,
            severity=severity,
            status=IncidentStatus.OPEN,
            agent_id=agent_id,
            risk_score=risk_score,
            notes=f"Auto-generated incident on risk score spike."
        )
        created = await self.repository.add(inc)
        await self.session.flush()
        logger.warning(f"Automated incident '{inc_id}' created for agent '{agent_id}'.")
        return created

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

    async def mark_false_positive(self, incident_id: str) -> Incident:
        inc = await self.get_incident(incident_id)
        inc.mark_false_positive()
        await self.session.flush()
        return inc

    async def add_note(self, incident_id: str, content: str, user: str = "system") -> IncidentNote:
        inc = await self.get_incident(incident_id)
        note = IncidentNote(
            incident_id=inc.id,
            user=user,
            content=content
        )
        self.session.add(note)

        # Also append note preview to incident notes field
        current_notes = inc.notes or ""
        inc.notes = f"{current_notes}\n[{user}]: {content}".strip()

        await self.session.flush()
        await self.session.refresh(note)
        return note

    async def list_notes(self, incident_id: str) -> List[IncidentNote]:
        stmt = select(IncidentNote).where(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at.asc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
