from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.detection_rule import DetectionRule
from app.repositories.base import SqlAlchemyRepository


class DetectionRuleRepository(SqlAlchemyRepository[DetectionRule]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, DetectionRule)

    async def get_by_rule_id(self, rule_id: str) -> Optional[DetectionRule]:
        stmt = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_enabled(self) -> List[DetectionRule]:
        stmt = select(DetectionRule).where(DetectionRule.enabled == True)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
