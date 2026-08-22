import uuid
from app.models import agent_history
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent import Agent
from app.repositories.agent_repository import AgentRepository
from app.schemas.agent import AgentCreate, AgentUpdate
from app.schemas.heartbeat import HeartbeatDTO
from app.schemas.enums import AgentStatus
from app.core.exceptions import AgentNotFoundError, ConflictError
from app.services.base import AbstractService
from app.models.agent_history import AgentHistory
from app.repositories.agent_history_repository import AgentHistoryRepository

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
                hostname=f"agent-{dto.agent_id[:8]}",
                ip_address=dto.ip_address,          # Lấy từ DTO
                mac_address=dto.mac_address,         # Lấy từ DTO
                status=AgentStatus.ACTIVE
            )
            await self.repository.add(agent)

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

    async def list_agents(self, skip: int = 0, limit: int = 100) -> List[Agent]:
        return await self.repository.list(skip=skip, limit=limit)

    async def delete_agent(self, agent_id: str) -> bool:
        return await self.repository.delete(agent_id)
