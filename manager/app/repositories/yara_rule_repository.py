from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.yara_rule import YaraRule
from app.repositories.base import SqlAlchemyRepository


class YaraRuleRepository(SqlAlchemyRepository[YaraRule]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, YaraRule)

    async def get_enabled_rules(self) -> List[YaraRule]:
        stmt = select(YaraRule).where(YaraRule.enabled == True)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_name(self, name: str) -> Optional[YaraRule]:
        stmt = select(YaraRule).where(YaraRule.name == name)
        result = await self.session.execute(stmt)
        return result.scalars().first()
