import logging
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.process_group import ProcessGroup
from app.models.process_chain_rule import ProcessChainRule
from app.schemas.process_chain_rule import ProcessChainRuleCreate, ProcessChainRuleUpdate
from app.repositories.process_group_repository import ProcessGroupRepository
from app.repositories.process_chain_rule_repository import ProcessChainRuleRepository
from app.core.exceptions import AppException

logger = logging.getLogger(__name__)


class ProcessChainRuleService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ProcessChainRuleRepository(session)
        self.group_repo = ProcessGroupRepository(session)

    async def list_rules(self, skip: int = 0, limit: int = 100) -> List[ProcessChainRule]:
        rules = await self.repo.list_with_groups(skip=skip, limit=limit)
        if not rules and skip == 0:
            await self.seed_default_data()
            rules = await self.repo.list_with_groups(skip=skip, limit=limit)
        return rules


    async def list_active_rules(self) -> List[ProcessChainRule]:
        return await self.repo.list_active()

    async def get_rule(self, id: str) -> ProcessChainRule:
        rule = await self.repo.get_with_groups(id)
        if not rule:
            raise AppException(f"Process chain rule '{id}' not found.", status_code=404)
        return rule

    async def create_rule(self, dto: ProcessChainRuleCreate) -> ProcessChainRule:
        # Validate parent and child groups exist
        parent = await self.group_repo.get(dto.parent_group_id)
        if not parent:
            raise AppException(f"Parent process group '{dto.parent_group_id}' does not exist.", status_code=400)

        child = await self.group_repo.get(dto.child_group_id)
        if not child:
            raise AppException(f"Child process group '{dto.child_group_id}' does not exist.", status_code=400)

        action_val = str(dto.action).lower()
        if action_val not in ("alert", "block", "isolate"):
            action_val = "alert"

        rule = ProcessChainRule(
            name=dto.name.strip(),
            parent_group_id=dto.parent_group_id,
            child_group_id=dto.child_group_id,
            action=action_val,
            is_active=dto.is_active
        )
        await self.repo.add(rule)
        await self.session.commit()
        self._invalidate_chain_cache()
        return await self.get_rule(rule.id)

    async def update_rule(self, id: str, dto: ProcessChainRuleUpdate) -> ProcessChainRule:
        rule = await self.get_rule(id)

        if dto.name is not None:
            rule.name = dto.name.strip()

        if dto.parent_group_id is not None:
            parent = await self.group_repo.get(dto.parent_group_id)
            if not parent:
                raise AppException(f"Parent process group '{dto.parent_group_id}' does not exist.", status_code=400)
            rule.parent_group_id = dto.parent_group_id

        if dto.child_group_id is not None:
            child = await self.group_repo.get(dto.child_group_id)
            if not child:
                raise AppException(f"Child process group '{dto.child_group_id}' does not exist.", status_code=400)
            rule.child_group_id = dto.child_group_id

        if dto.action is not None:
            action_val = str(dto.action).lower()
            if action_val in ("alert", "block", "isolate"):
                rule.action = action_val

        if dto.is_active is not None:
            rule.is_active = dto.is_active

        await self.session.flush()
        await self.session.commit()
        self._invalidate_chain_cache()
        return await self.get_rule(rule.id)

    async def delete_rule(self, id: str) -> None:
        await self.get_rule(id)
        await self.repo.delete(id)
        await self.session.commit()
        self._invalidate_chain_cache()

    async def seed_default_data(self) -> None:
        """
        Idempotent seeding: checks if groups/rules exist by name before inserting.
        Prevents duplicate data across server restarts.
        """
        default_groups = [
            {
                "name": "Office Applications",
                "patterns": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
                "description": "Microsoft Office productivity applications",
            },
            {
                "name": "Command Shells",
                "patterns": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "bash"],
                "description": "System command-line shells and script interpreters",
            },
            {
                "name": "Web Downloaders",
                "patterns": ["curl", "wget", "certutil"],
                "description": "Utilities frequently abused to download external payloads",
            },
        ]

        group_map = {}
        for g_data in default_groups:
            existing = await self.group_repo.get_by_name(g_data["name"])
            if not existing:
                group = ProcessGroup(
                    name=g_data["name"],
                    patterns=g_data["patterns"],
                    description=g_data["description"]
                )
                await self.group_repo.add(group)
                group_map[g_data["name"]] = group
                logger.info(f"Seeded process group: '{g_data['name']}'")
            else:
                group_map[g_data["name"]] = existing

        await self.session.commit()

        default_rules = [
            {
                "name": "Office spawning shell",
                "parent": "Office Applications",
                "child": "Command Shells",
                "action": "alert",
                "is_active": True,
            },
            {
                "name": "Shell downloading payload",
                "parent": "Command Shells",
                "child": "Web Downloaders",
                "action": "block",
                "is_active": True,
            },
        ]

        for r_data in default_rules:
            existing = await self.repo.get_by_name(r_data["name"])
            if not existing:
                parent_grp = group_map.get(r_data["parent"]) or await self.group_repo.get_by_name(r_data["parent"])
                child_grp = group_map.get(r_data["child"]) or await self.group_repo.get_by_name(r_data["child"])
                if parent_grp and child_grp:
                    rule = ProcessChainRule(
                        name=r_data["name"],
                        parent_group_id=parent_grp.id,
                        child_group_id=child_grp.id,
                        action=r_data["action"],
                        is_active=r_data["is_active"]
                    )
                    await self.repo.add(rule)
                    logger.info(f"Seeded process chain rule: '{r_data['name']}'")

        await self.session.commit()
        self._invalidate_chain_cache()

    def _invalidate_chain_cache(self) -> None:
        try:
            from app.services.risk_rules.process_chain_rule import ProcessChainRule as RiskProcessChainRule
            RiskProcessChainRule.invalidate_cache()
        except Exception as e:
            logger.debug(f"Could not invalidate process chain cache: {e}")
