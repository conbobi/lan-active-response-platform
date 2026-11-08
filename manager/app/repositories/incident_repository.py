from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.incident import Incident
from app.schemas.enums import IncidentStatus
from app.repositories.base import SqlAlchemyRepository


class IncidentRepository(SqlAlchemyRepository[Incident]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Incident)

    async def find_open_incidents(self) -> List[Incident]:
        stmt = select(Incident).where(
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED])
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def find_by_agent(self, agent_id: str) -> List[Incident]:
        stmt = select(Incident).where(Incident.agent_id == agent_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_active_incidents_for_dashboard(
        self, limit: int = 10, hours: int = 24
    ) -> List[Incident]:
        """Only return OPEN/INVESTIGATING/CONTAINED incidents within time window, ordered by risk_score and created_at."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        stmt = (
            select(Incident)
            .where(
                Incident.status.in_([
                    IncidentStatus.OPEN,
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.CONTAINED,
                ])
            )
            .where(Incident.created_at >= cutoff)
            .order_by(desc(Incident.risk_score), desc(Incident.created_at))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def resolve_active_incidents_for_agent(
        self, agent_id: str, resolved_reason: str = "Auto-resolved after agent unisolated"
    ) -> List[Incident]:
        """Auto-resolve active incidents for a given agent and record resolution note."""
        now = datetime.now(timezone.utc)
        stmt = (
            select(Incident)
            .where(
                Incident.agent_id == agent_id,
                Incident.status.in_([
                    IncidentStatus.OPEN,
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.CONTAINED,
                ])
            )
        )
        result = await self.session.execute(stmt)
        incidents = list(result.scalars().all())
        for inc in incidents:
            inc.status = IncidentStatus.RESOLVED
            inc.resolved_at = now
            note_content = f"Incident auto-resolved: {resolved_reason}."
            if inc.notes:
                inc.notes += f"\n{note_content}"
            else:
                inc.notes = note_content
        await self.session.flush()
        return incidents

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = False,
        hours: Optional[int] = None
    ) -> List[Incident]:
        stmt = select(Incident)
        if active_only:
            stmt = stmt.where(
                Incident.status.in_([
                    IncidentStatus.OPEN,
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.CONTAINED,
                ])
            )
        if hours is not None and hours > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            stmt = stmt.where(Incident.created_at >= cutoff)

        stmt = stmt.order_by(desc(Incident.created_at)).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
