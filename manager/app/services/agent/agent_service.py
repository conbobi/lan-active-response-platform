import uuid
import logging
from datetime import datetime, timezone
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent import Agent
from app.repositories.agent_repository import AgentRepository
from app.schemas.agent import AgentCreate
from app.schemas.heartbeat import HeartbeatDTO
from app.schemas.enums import AgentStatus
from app.core.exceptions import AgentNotFoundError, ConflictError
from app.services.core.base import AbstractService
from app.models.agent_history import AgentHistory
from app.repositories.agent_history_repository import AgentHistoryRepository

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
        agent = await self.repository.get(dto.agent_id)
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
        else:
            if dto.hostname and agent.hostname != dto.hostname:
                agent.hostname = dto.hostname

        # Cập nhật tất cả thông tin từ heartbeat

        agent.update_heartbeat(
            cpu=dto.cpu,
            ram=dto.ram,
            disk=dto.disk,
            timestamp=dto.timestamp,
            ip_address=dto.ip_address,       # Nếu model hỗ trợ
            mac_address=dto.mac_address       # Nếu model hỗ trợ
        )
        # Hoặc gán trực tiếp nếu update_heartbeat không có tham số ip/mac
        agent.ip_address = dto.ip_address
        agent.mac_address = dto.mac_address

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
        if not deduplicate:
            return await self.repository.list(skip=skip, limit=limit)

        agents = await self.repository.list(skip=0, limit=10000)
        latest_by_hostname = {}
        for a in agents:
            key = a.hostname or a.id
            if key not in latest_by_hostname:
                latest_by_hostname[key] = a
                continue

            existing = latest_by_hostname[key]
            a_status = getattr(a.status, "value", str(a.status)).lower()
            e_status = getattr(existing.status, "value", str(existing.status)).lower()
            a_active = a_status in ("active", "online")
            e_active = e_status in ("active", "online")

            if a_active and not e_active:
                latest_by_hostname[key] = a
            elif not a_active and e_active:
                pass
            else:
                a_ts = a.last_seen or a.created_at
                e_ts = existing.last_seen or existing.created_at
                if a_ts and (not e_ts or a_ts > e_ts):
                    latest_by_hostname[key] = a

        deduped = list(latest_by_hostname.values())
        deduped.sort(
            key=lambda x: (
                1 if getattr(x.status, "value", str(x.status)).lower() in ("active", "online") else 0,
                x.last_seen or x.created_at or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True
        )
        return deduped[skip : skip + limit]

    async def delete_agent(self, agent_id: str) -> bool:
        return await self.repository.delete(agent_id)
