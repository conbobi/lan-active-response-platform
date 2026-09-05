import logging
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.process_group import ProcessGroup
from app.schemas.process_group import ProcessGroupCreate, ProcessGroupUpdate
from app.repositories.process_group_repository import ProcessGroupRepository
from app.repositories.process_chain_rule_repository import ProcessChainRuleRepository
from app.core.exceptions import AppException

logger = logging.getLogger(__name__)


class ProcessGroupService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ProcessGroupRepository(session)
        self.chain_rule_repo = ProcessChainRuleRepository(session)

    async def list_groups(self, skip: int = 0, limit: int = 100) -> List[ProcessGroup]:
        groups = await self.repo.list_all(skip=skip, limit=limit)
        if not groups and skip == 0:
            from app.services.process_chain_rule_service import ProcessChainRuleService
            chain_service = ProcessChainRuleService(self.session)
            await chain_service.seed_default_data()
            groups = await self.repo.list_all(skip=skip, limit=limit)
        return groups


    async def get_group(self, id: str) -> ProcessGroup:
        group = await self.repo.get(id)
        if not group:
            raise AppException(f"Process group '{id}' not found.", status_code=404)
        return group

    async def create_group(self, dto: ProcessGroupCreate) -> ProcessGroup:
        existing = await self.repo.get_by_name(dto.name)
        if existing:
            raise AppException(f"Process group with name '{dto.name}' already exists.", status_code=400)

        # Normalize patterns (strip whitespaces, remove empty items)
        cleaned_patterns = [p.strip().lower() for p in dto.patterns if p.strip()]

        group = ProcessGroup(
            name=dto.name.strip(),
            patterns=cleaned_patterns,
            description=dto.description or ""
        )
        await self.repo.add(group)
        await self.session.commit()
        await self.session.refresh(group)
        self._invalidate_chain_cache()
        return group

    async def update_group(self, id: str, dto: ProcessGroupUpdate) -> ProcessGroup:
        group = await self.get_group(id)

        if dto.name and dto.name.strip() != group.name:
            existing = await self.repo.get_by_name(dto.name.strip())
            if existing and existing.id != id:
                raise AppException(f"Process group with name '{dto.name}' already exists.", status_code=400)
            group.name = dto.name.strip()

        if dto.patterns is not None:
            group.patterns = [p.strip().lower() for p in dto.patterns if p.strip()]

        if dto.description is not None:
            group.description = dto.description

        await self.session.flush()
        await self.session.commit()
        await self.session.refresh(group)
        self._invalidate_chain_cache()
        return group

    async def delete_group(self, id: str) -> None:
        group = await self.get_group(id)

        # Check referential integrity: return HTTP 409 Conflict if referenced
        ref_count = await self.chain_rule_repo.count_by_group_id(id)
        if ref_count > 0:
            raise AppException(
                f"Cannot delete process group '{group.name}' because it is referenced by {ref_count} process chain rule(s).",
                status_code=409
            )

        await self.repo.delete(id)
        await self.session.commit()
        self._invalidate_chain_cache()

    def _invalidate_chain_cache(self) -> None:
        try:
            from app.services.risk_rules.process_chain_rule import ProcessChainRule as RiskProcessChainRule
            RiskProcessChainRule.invalidate_cache()
        except Exception as e:
            logger.debug(f"Could not invalidate process chain cache: {e}")
