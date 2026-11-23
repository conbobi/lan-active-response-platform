import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy import String, cast, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.incident import Incident
from app.schemas.enums import IncidentStatus
from app.repositories.base import SqlAlchemyRepository

logger = logging.getLogger("larp.repositories.incident")

ACTIVE_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED)


def open_incident_filter():
    return Incident.status.in_(ACTIVE_STATUSES) & or_(Incident.label.is_(None), Incident.label != "false_positive")


def network_finding_filter():
    evidence = cast(Incident.detection_evidence, String)
    return or_(
        evidence.contains('"network"'), evidence.contains('"network_connection"'),
        evidence.contains('"c2_communication"'), evidence.contains('"http_beaconing"'),
        Incident.description.ilike("%direct connection to c2 port%"),
        Incident.description.ilike("%'network_connection'%"),
        Incident.description.ilike("%'c2_communication'%"),
    )


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
            .where(open_incident_filter())
            .where(Incident.created_at >= cutoff)
            .order_by(desc(Incident.risk_score), desc(Incident.created_at))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        items = list(result.scalars().all())
        logger.info(f"Found {len(items)} incidents for dashboard (limit={limit}, hours={hours})")
        return items

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = False,
        hours: Optional[int] = None,
        finding: Optional[str] = None,
    ) -> List[Incident]:
        stmt = select(Incident)
        if active_only:
            stmt = stmt.where(open_incident_filter())
        if finding == "network":
            stmt = stmt.where(network_finding_filter())
        if hours is not None and hours > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            stmt = stmt.where(Incident.created_at >= cutoff)

        stmt = stmt.order_by(desc(Incident.created_at)).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        items = list(result.scalars().all())
        logger.info(f"IncidentRepository.list returned {len(items)} incidents (skip={skip}, limit={limit}, active_only={active_only})")
        return items
