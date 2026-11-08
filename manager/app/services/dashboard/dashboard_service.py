from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.incident_repository import IncidentRepository
from app.repositories.agent_repository import AgentRepository
from app.schemas.enums import IncidentStatus


class DashboardService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.incident_repo = IncidentRepository(session)
        self.agent_repo = AgentRepository(session)

    async def get_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Aggregate dashboard summary: health score, active incident counts, agent statuses.
        Follows the exact posture scoring formula:
        - Priority 1: Unresolved critical incident on alive agent (score >= 85) -> max(0, 40 - count * 15), level 'critical'
        - Priority 2: Unresolved medium incidents (30 <= score < 85) -> count >= 3 -> score 55, level 'warning'
        - Priority 3: Offline agents -> offline >= 2 -> score 70, level 'warning'
        - Safe: 100
        """
        active_incidents = await self.incident_repo.get_active_incidents_for_dashboard(limit=100, hours=hours)
        all_agents = await self.agent_repo.list(skip=0, limit=1000)

        # Deduplicate agents by hostname or id
        unique_agents = {}
        for a in all_agents:
            key = a.hostname or a.id
            if key not in unique_agents:
                unique_agents[key] = a

        agents_list = list(unique_agents.values())
        now = datetime.now(timezone.utc)

        # Helper to check if agent is alive
        def is_alive(a) -> bool:
            status = str(a.status or "").lower()
            if status in ("dead", "offline", "inactive"):
                return False
            if status in ("active", "online", "isolated", "quarantine"):
                return True
            if a.last_seen:
                # 5 minutes
                age = (now - a.last_seen).total_seconds()
                return age < 300
            return False

        alive_map = {a.id: is_alive(a) for a in agents_list}
        alive_agents_count = sum(1 for a in agents_list if is_alive(a))
        offline_agents_count = len(agents_list) - alive_agents_count

        unresolved_critical = []
        unresolved_medium = []

        for inc in active_incidents:
            score = inc.risk_score or 0.0
            agent_alive = alive_map.get(inc.agent_id, False)
            if not agent_alive:
                continue

            if score >= 85:
                unresolved_critical.append(inc)
            elif score >= 30:
                unresolved_medium.append(inc)

        health_score = 100
        level = "safe"

        if len(unresolved_critical) > 0:
            health_score = max(0, 40 - len(unresolved_critical) * 15)
            level = "critical"
        elif len(unresolved_medium) >= 3:
            health_score = min(health_score, 55)
            level = "warning"
        elif offline_agents_count >= 2:
            health_score = min(health_score, 70)
            level = "warning"

        return {
            "health_score": health_score,
            "health_level": level,
            "active_incidents": len(active_incidents),
            "critical_incidents": len(unresolved_critical),
            "medium_incidents": len(unresolved_medium),
            "total_agents": len(agents_list),
            "alive_agents": alive_agents_count,
            "offline_agents": offline_agents_count,
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "agent_id": inc.agent_id,
                    "status": inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                    "risk_score": inc.risk_score,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None,
                }
                for inc in active_incidents
            ]
        }

