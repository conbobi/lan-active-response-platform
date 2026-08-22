from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.rule import Rule
from app.repositories.base import SqlAlchemyRepository


class RuleRepository(SqlAlchemyRepository[Rule]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Rule)

    async def get_enabled_rules(self) -> List[Rule]:
        stmt = select(Rule).where(Rule.is_enabled == True)  # noqa: E712
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
