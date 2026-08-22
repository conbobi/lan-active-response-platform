from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.flow import Flow
from app.repositories.flow_repository import FlowRepository
from app.schemas.flow import FlowCreate
from app.core.exceptions import NotFoundError
from app.services.base import AbstractService


class FlowService(AbstractService[FlowRepository]):
    def __init__(self, session: AsyncSession):
        repo = FlowRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def create_flow(self, dto: FlowCreate) -> Flow:
        flow = Flow(
            id=dto.id,
            src_ip=dto.src_ip,
            dst_ip=dto.dst_ip,
            src_port=dto.src_port,
            dst_port=dto.dst_port,
            protocol=dto.protocol,
            bytes_sent=dto.bytes_sent,
            packets_sent=dto.packets_sent,
            start_time=dto.start_time,
            end_time=dto.end_time,
            agent_id=dto.agent_id
        )
        return await self.repository.add(flow)

    async def get_flow(self, flow_id: str) -> Flow:
        flow = await self.repository.get(flow_id)
        if not flow:
            raise NotFoundError(f"Flow '{flow_id}' not found.")
        return flow

    async def list_flows(self, skip: int = 0, limit: int = 100) -> List[Flow]:
        return await self.repository.list(skip=skip, limit=limit)

    async def check_agent_beaconing(self, agent_id: str) -> bool:
        flows = await self.repository.find_by_agent(agent_id)
        return Flow.check_beaconing(flows)
