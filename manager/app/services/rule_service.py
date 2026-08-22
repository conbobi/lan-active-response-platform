from typing import List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.rule import Rule
from app.repositories.rule_repository import RuleRepository
from app.schemas.rule import RuleCreate
from app.core.exceptions import NotFoundError
from app.services.base import AbstractService


class RuleService(AbstractService[RuleRepository]):
    def __init__(self, session: AsyncSession):
        repo = RuleRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def create_rule(self, dto: RuleCreate) -> Rule:
        rule = Rule(
            id=dto.id,
            name=dto.name,
            description=dto.description,
            rule_type=dto.rule_type,
            pattern=dto.pattern,
            action=dto.action,
            is_enabled=dto.is_enabled,
            severity=dto.severity
        )
        return await self.repository.add(rule)

    async def get_rule(self, rule_id: str) -> Rule:
        rule = await self.repository.get(rule_id)
        if not rule:
            raise NotFoundError(f"Rule '{rule_id}' not found.")
        return rule

    async def list_rules(self, skip: int = 0, limit: int = 100) -> List[Rule]:
        return await self.repository.list(skip=skip, limit=limit)

    async def delete_rule(self, rule_id: str) -> bool:
        return await self.repository.delete(rule_id)

    async def evaluate_rules(self, target: Any) -> List[Rule]:
        """Evaluate enabled rules against target object and return matching rules."""
        enabled_rules = await self.repository.get_enabled_rules()
        matched = [r for r in enabled_rules if r.match(target)]
        return matched
