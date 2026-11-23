from datetime import datetime, timezone

from sqlalchemy import case, func, select, tuple_

from app.models.agent import Agent
from app.models.agent_activity import AgentActivity
from app.models.event import Event
from app.models.incident import Incident
from app.repositories.incident_repository import IncidentRepository, open_incident_filter
from app.schemas.agent import AgentOut
from app.schemas.incident import IncidentOut
from app.services.agent.activity import attach_incident_activity, observation_expiry
from app.core.agent_health import OFFLINE_AFTER, STALE_AFTER
from app.services.incident.incident_service import IncidentService


class DashboardService:
    def __init__(self, session):
        self.session = session

    async def get_summary(self, hours=24, limit=50, offset=0):
        now = datetime.now(timezone.utc)
        health_column = case(
            (Agent.decommissioned_at.is_not(None), "decommissioned"),
            (Agent.last_seen <= now - OFFLINE_AFTER, "offline"),
            (Agent.last_seen <= now - STALE_AFTER, "stale"),
            else_="online",
        ).label("health")
        health_counts = dict((await self.session.execute(
            select(health_column, func.count()).group_by(health_column)
        )).all())
        agents = (await self.session.execute(select(Agent).order_by(
            Agent.last_seen.desc(), Agent.id,
        ).offset(offset).limit(limit))).scalars().all()
        queue_count = await self.session.scalar(select(func.count()).select_from(Incident).where(open_incident_filter()))
        repo = IncidentRepository(self.session)
        history = await repo.list(limit=limit, hours=hours)
        network_findings = await repo.list(limit=limit, active_only=True, finding="network")

        # Active behavior can span multiple days. Resolve current fingerprints before applying the history window.
        live = (await self.session.execute(select(Agent.id, AgentActivity.samples).join(AgentActivity).where(
            Agent.decommissioned_at.is_(None), Agent.last_seen > now - STALE_AFTER,
        ))).all()
        keys = []
        for agent_id, samples in live:
            sample = samples.get("socket", {})
            expiry = observation_expiry(sample)
            if expiry and expiry > now:
                keys.extend((agent_id, entity) for entity in sample.get("detections", ()))
        candidates = []
        for start in range(0, len(keys), 200):
            candidates.extend((await self.session.execute(select(Incident).where(
                open_incident_filter(),
                tuple_(Incident.agent_id, Incident.fingerprint).in_(keys[start:start + 200]),
            ).order_by(Incident.updated_at.desc()))).scalars().all())
        current = {}
        for incident in candidates:
            current.setdefault((incident.agent_id, incident.fingerprint), incident)

        records = list({incident.id: incident for incident in [*history, *network_findings, *current.values()]}.values())
        service = IncidentService(self.session)
        for incident in records:
            await service._enrich_incident(incident, stored_only=True)
        await attach_incident_activity(self.session, records, now)
        active = sorted((incident for incident in current.values() if incident.detection_activity == "active"),
                        key=lambda incident: incident.risk_score, reverse=True)

        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        events = (await self.session.execute(select(Event).order_by(Event.created_at.desc()).limit(25))).scalars().all()
        event_counts = dict((await self.session.execute(select(Event.event_type, func.count()).where(
            Event.created_at >= today,
        ).group_by(Event.event_type))).all())
        level = "critical" if any(inc.risk_score >= 85 for inc in active) else (
            "warning" if active or health_counts.get("offline", 0) or health_counts.get("stale", 0) else "unverified"
        )

        return {
            "as_of": now.isoformat(),
            "health_counts": health_counts,
            "alive_agents": health_counts.get("online", 0),
            "offline_agents": health_counts.get("offline", 0),
            "total_agents": sum(health_counts.values()),
            "health_level": level,
            "health_score": 40 if level == "critical" else 70 if level == "warning" else 100,
            "incident_queue": queue_count,
            "active_incidents": len(active),
            "active_behavior": IncidentOut.model_validate(active[0]).model_dump(mode="json") if active else None,
            "incidents": [IncidentOut.model_validate(incident).model_dump(mode="json") for incident in history],
            "network_findings": [IncidentOut.model_validate(incident).model_dump(mode="json") for incident in network_findings],
            "agents": [AgentOut.model_validate(agent).model_dump(mode="json") for agent in agents],
            "events": [{"id": event.id, "type": event.event_type, "timestamp": event.created_at,
                        "agent_id": event.agent_id, "severity": event.severity, "details": event.details}
                       for event in events],
            "alerts_today": sum(event_counts.values()),
            "block_events_today": event_counts.get("block_ip", 0),
        }
