from typing import List, Optional
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.agent_group import AgentGroup, AgentGroupMember
from app.models.agent import Agent
from app.repositories.base import SqlAlchemyRepository


class AgentGroupRepository(SqlAlchemyRepository[AgentGroup]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, AgentGroup)

    async def get_by_name(self, name: str) -> Optional[AgentGroup]:
        stmt = select(AgentGroup).where(AgentGroup.name == name)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_members(self, group_id: str) -> Optional[AgentGroup]:
        stmt = (
            select(AgentGroup)
            .where(AgentGroup.id == group_id)
            .options(
                selectinload(AgentGroup.members).selectinload(AgentGroupMember.agent)
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_all_with_count(self) -> List[tuple[AgentGroup, int]]:
        """Lấy tất cả nhóm kèm số lượng thành viên."""
        stmt = (
            select(AgentGroup, func.count(AgentGroupMember.agent_id).label("member_count"))
            .outerjoin(AgentGroupMember, AgentGroup.id == AgentGroupMember.group_id)
            .group_by(AgentGroup.id)
            .order_by(AgentGroup.name.asc())
        )
        result = await self.session.execute(stmt)
        return [(row[0], row[1]) for row in result.all()]

    async def add_agent_to_group(self, group_id: str, agent_id: str) -> AgentGroupMember:
        # Check if already a member
        stmt = select(AgentGroupMember).where(
            AgentGroupMember.group_id == group_id,
            AgentGroupMember.agent_id == agent_id
        )
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            return existing

        member = AgentGroupMember(group_id=group_id, agent_id=agent_id)
        self.session.add(member)
        await self.session.flush()
        return member

    async def remove_agent_from_group(self, group_id: str, agent_id: str) -> bool:
        stmt = (
            delete(AgentGroupMember)
            .where(
                AgentGroupMember.group_id == group_id,
                AgentGroupMember.agent_id == agent_id
            )
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    async def get_agents_in_group(self, group_id: str) -> List[Agent]:
        stmt = (
            select(Agent)
            .join(AgentGroupMember, Agent.id == AgentGroupMember.agent_id)
            .where(AgentGroupMember.group_id == group_id)
            .order_by(Agent.hostname.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_groups_for_agent(self, agent_id: str) -> List[AgentGroup]:
        stmt = (
            select(AgentGroup)
            .join(AgentGroupMember, AgentGroup.id == AgentGroupMember.group_id)
            .where(AgentGroupMember.agent_id == agent_id)
            .order_by(AgentGroup.name.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
