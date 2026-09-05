from typing import Optional, List
from sqlalchemy import select, func, or_
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.process_chain_rule import ProcessChainRule
from app.repositories.base import SqlAlchemyRepository


class ProcessChainRuleRepository(SqlAlchemyRepository[ProcessChainRule]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ProcessChainRule)

    async def get_with_groups(self, id: str) -> Optional[ProcessChainRule]:
        stmt = (
            select(ProcessChainRule)
            .options(
                joinedload(ProcessChainRule.parent_group),
                joinedload(ProcessChainRule.child_group),
            )
            .where(ProcessChainRule.id == id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_name(self, name: str) -> Optional[ProcessChainRule]:
        stmt = select(ProcessChainRule).where(ProcessChainRule.name == name)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_with_groups(self, skip: int = 0, limit: int = 100) -> List[ProcessChainRule]:
        stmt = (
            select(ProcessChainRule)
            .options(
                joinedload(ProcessChainRule.parent_group),
                joinedload(ProcessChainRule.child_group),
            )
            .order_by(ProcessChainRule.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_active(self) -> List[ProcessChainRule]:
        stmt = (
            select(ProcessChainRule)
            .options(
                joinedload(ProcessChainRule.parent_group),
                joinedload(ProcessChainRule.child_group),
            )
            .where(ProcessChainRule.is_active == True)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_group_id(self, group_id: str) -> int:
        stmt = select(func.count(ProcessChainRule.id)).where(
            or_(
                ProcessChainRule.parent_group_id == group_id,
                ProcessChainRule.child_group_id == group_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar() or 0
