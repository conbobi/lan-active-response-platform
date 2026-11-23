import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent import Agent
from app.models.agent_activity import AgentActivity
from app.models.agent_history import AgentHistory
from app.repositories.agent_repository import AgentRepository
from app.repositories.agent_history_repository import AgentHistoryRepository
from app.schemas.agent import AgentCreate
from app.schemas.heartbeat import HeartbeatDTO
from app.schemas.enums import AgentStatus
from app.core.exceptions import AgentNotFoundError, ConflictError
from app.services.core.base import AbstractService
from app.core.agent_health import OFFLINE_AFTER, as_utc

logger = logging.getLogger(__name__)

class AgentService(AbstractService[AgentRepository]):
    def __init__(self, session: AsyncSession):
        repo = AgentRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def register_agent(self, dto: AgentCreate) -> Agent:
        existing = await self.repository.get(dto.id)
        if existing:
            raise ConflictError(f"Agent with ID '{dto.id}' already exists.")
        agent = Agent(
            id=dto.id,
            hostname=dto.hostname,
            ip_address=dto.ip_address,
            mac_address=dto.mac_address,
            status=dto.status or AgentStatus.ACTIVE
        )
        return await self.repository.add(agent)

    async def update_heartbeat(self, dto: HeartbeatDTO) -> Agent:
        now = datetime.now(timezone.utc)
        captured = as_utc(dto.timestamp)
        if captured is None or not now - OFFLINE_AFTER <= captured <= now + timedelta(seconds=30):
            raise ValueError("Heartbeat timestamp outside the accepted window")
        context = getattr(self.session, "info", {})
        sequenced = context.get("defer_incident_events") is True
        agent = (await self.session.get(Agent, dto.agent_id, with_for_update=True)
                 if sequenced else await self.repository.get(dto.agent_id))
        previous_health = agent.health if agent else None
        if not agent:
            # Auto register if unknown agent sends heartbeat
            agent = Agent(
                id=dto.agent_id,
                hostname=dto.hostname or f"agent-{dto.agent_id[:8]}",
                ip_address=dto.ip_address or "127.0.0.1",
                mac_address=dto.mac_address or "00:00:00:00:00:00",
                status=AgentStatus.ACTIVE
            )
            await self.repository.add(agent)
            logger.info(f"[HEARTBEAT] Auto-registered new agent '{dto.agent_id}' (hostname: {agent.hostname})")

        if agent.decommissioned_at is not None:
            return agent
        if sequenced:
            activity = await self.session.get(AgentActivity, agent.id)
            samples = dict(activity.samples) if activity else {}
            previous = as_utc(samples.get("heartbeat_at"))
            if previous and captured <= previous:
                return agent
            samples["heartbeat_at"] = captured.isoformat()
            if activity:
                activity.samples = samples
            else:
                self.session.add(AgentActivity(agent_id=agent.id, samples=samples))
            if previous_health != "online":
                context.setdefault("dashboard_events", []).append({"type": "ACTIVITY_UPDATED", "agent_id": agent.id})

        if dto.hostname:
            agent.hostname = dto.hostname
        agent.update_heartbeat(
            cpu=dto.cpu,
            ram=dto.ram,
            disk=dto.disk,
            timestamp=now,
            ip_address=dto.ip_address,
            mac_address=dto.mac_address,
        )

        history_repo = AgentHistoryRepository(self.session)
        history_entry = AgentHistory(
            id=f"hist_{uuid.uuid4().hex[:12]}",
            agent_id=dto.agent_id,
            cpu=dto.cpu,
            ram=dto.ram,
            disk=dto.disk,
            timestamp=dto.timestamp
        )
        await history_repo.add(history_entry)

        await self.session.flush()
        return agent

    async def process_heartbeat(self, dto: HeartbeatDTO) -> Agent:
        """Process agent heartbeat and broadcast update to dashboard."""
        agent = await self.update_heartbeat(dto)
        if getattr(self.session, "info", {}).get("defer_incident_events") is True:
            return agent
        try:
            from app.websocket.dashboard_connection_manager import dashboard_manager
            await dashboard_manager.broadcast({
                "type": "heartbeat",
                "data": dto.model_dump(mode="json")
            })
        except Exception as e:
            logger.warning(f"Failed to broadcast heartbeat to dashboard: {e}")
        return agent

    async def sweep_dead_agents(self, threshold_seconds: int = 30) -> List[str]:
        """Detect and deactivate unresponsive agents."""
        dead_agents = await self.repository.get_dead_agents(threshold_seconds=threshold_seconds)
        dead_ids = []
        if dead_agents:
            for agent in dead_agents:
                agent.status = AgentStatus.DEAD
                dead_ids.append(agent.id)
            await self.session.flush()
            logger.warning(f"Dead agent sweep detected {len(dead_ids)} unresponsive agents: {dead_ids}")
            try:
                from app.websocket.dashboard_connection_manager import dashboard_manager
                await dashboard_manager.broadcast({
                    "type": "dead_agent",
                    "data": {"agent_id": dead_ids, "status": "DEAD"}
                })
            except Exception as e:
                logger.warning(f"Failed to broadcast dead_agent event: {e}")
        return dead_ids

    async def isolate_agent(self, agent_id: str) -> Agent:
        agent = await self.repository.get(agent_id)
        if not agent:
            raise AgentNotFoundError(agent_id)
        agent.isolate()
        await self.session.flush()
        return agent

    async def unisolate_agent(self, agent_id: str) -> Agent:
        agent = await self.repository.get(agent_id)
        if not agent:
            raise AgentNotFoundError(agent_id)
        agent.unisolate()
        await self.session.flush()
        return agent

    async def get_agent(self, agent_id: str) -> Agent:
        agent = await self.repository.get(agent_id)
        if not agent:
            raise AgentNotFoundError(agent_id)
        return agent

    async def list_agents(self, skip: int = 0, limit: int = 100, deduplicate: bool = True) -> List[Agent]:
        stmt = select(Agent).order_by(Agent.last_seen.desc(), Agent.id).offset(skip).limit(limit)
        return list((await self.session.execute(stmt)).scalars().all())

    async def delete_agent(self, agent_id: str) -> bool:
        agent = await self.repository.get(agent_id)
        if not agent:
            raise AgentNotFoundError(f"Agent '{agent_id}' not found.")
        if agent.decommissioned_at is None:
            agent.decommissioned_at = datetime.now(timezone.utc)
            await self.session.flush()
        return True

    async def delete_offline_agents(self) -> int:
        now = datetime.now(timezone.utc)
        statement = update(Agent).where(Agent.last_seen <= now - OFFLINE_AFTER,
                                        Agent.decommissioned_at.is_(None)).values(decommissioned_at=now)
        result = await self.session.execute(statement)
        return result.rowcount
