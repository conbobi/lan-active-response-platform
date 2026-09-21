import logging
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_group import AgentGroup, AgentGroupMember
from app.models.agent import Agent
from app.repositories.agent_group_repository import AgentGroupRepository
from app.repositories.agent_repository import AgentRepository
from app.services.response_action_service import ResponseActionService
from app.schemas.agent_group import (
    GroupBatchActionResponse,
    GroupBatchActionResult,
)
from app.core.exceptions import NotFoundError, BadRequestError, ConflictError

logger = logging.getLogger(__name__)


class AgentGroupService:
    """
    Service quản lý toàn bộ vòng đời của Agent Groups:
    CRUD nhóm, quản lý thành viên và thực thi Response Actions hàng loạt theo nhóm (Batch Group Execution).
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.group_repo = AgentGroupRepository(session)
        self.agent_repo = AgentRepository(session)
        self.action_service = ResponseActionService(session)

    async def create_group(
        self,
        name: str,
        description: Optional[str] = None,
        group_id: Optional[str] = None
    ) -> AgentGroup:
        """Tạo một Agent Group mới."""
        name = name.strip()
        existing = await self.group_repo.get_by_name(name)
        if existing:
            raise ConflictError(f"Agent group with name '{name}' already exists.")

        if group_id:
            group_id = group_id.strip()
            existing_id = await self.group_repo.get(group_id)
            if existing_id:
                raise ConflictError(f"Agent group with ID '{group_id}' already exists.")
        else:
            group_id = f"grp_{uuid.uuid4().hex[:12]}"

        group = AgentGroup(
            id=group_id,
            name=name,
            description=description
        )
        await self.group_repo.add(group)
        await self.session.commit()
        await self.session.refresh(group)
        logger.info(f"Created agent group '{group.name}' ({group.id}).")
        return group

    async def get_group(self, group_id: str) -> Optional[AgentGroup]:
        """Lấy thông tin nhóm theo ID."""
        return await self.group_repo.get(group_id)

    async def get_group_with_members(self, group_id: str) -> Optional[AgentGroup]:
        """Lấy chi tiết nhóm kèm danh sách thành viên."""
        return await self.group_repo.get_with_members(group_id)

    async def list_groups_with_count(self) -> List[tuple[AgentGroup, int]]:
        """Lấy danh sách tất cả các nhóm kèm số lượng thành viên."""
        return await self.group_repo.list_all_with_count()

    async def update_group(
        self,
        group_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None
    ) -> AgentGroup:
        """Cập nhật thông tin nhóm."""
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

        if name is not None:
            name = name.strip()
            if name != group.name:
                existing = await self.group_repo.get_by_name(name)
                if existing:
                    raise ConflictError(f"Agent group with name '{name}' already exists.")
                group.name = name

        if description is not None:
            group.description = description

        await self.session.commit()
        await self.session.refresh(group)
        logger.info(f"Updated agent group '{group.id}' (name: {group.name}).")
        return group

    async def delete_group(self, group_id: str) -> None:
        """Xóa một Agent Group."""
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

        await self.group_repo.delete(group.id)
        await self.session.commit()
        logger.info(f"Deleted agent group '{group.id}'.")

    async def add_agents_to_group(self, group_id: str, agent_ids: List[str]) -> List[AgentGroupMember]:
        """Thêm danh sách agent vào nhóm."""
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

        added_members = []
        for agent_id in agent_ids:
            agent = await self.agent_repo.get(agent_id)
            if not agent:
                logger.warning(f"Agent '{agent_id}' not found when adding to group '{group_id}'. Skipping.")
                continue
            member = await self.group_repo.add_agent_to_group(group_id, agent_id)
            added_members.append(member)

        await self.session.commit()
        logger.info(f"Added {len(added_members)} agents to group '{group.name}' ({group_id}).")
        return added_members

    async def remove_agent_from_group(self, group_id: str, agent_id: str) -> bool:
        """Xóa 1 agent khỏi nhóm."""
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

        removed = await self.group_repo.remove_agent_from_group(group_id, agent_id)
        if removed:
            await self.session.commit()
            logger.info(f"Removed agent '{agent_id}' from group '{group.name}' ({group_id}).")
        return removed

    async def list_agents_in_group(self, group_id: str) -> List[Agent]:
        """Lấy danh sách các Agent trong nhóm."""
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")
        return await self.group_repo.get_agents_in_group(group_id)

    async def list_groups_for_agent(self, agent_id: str) -> List[AgentGroup]:
        """Lấy danh sách các nhóm mà một Agent thuộc về."""
        return await self.group_repo.get_groups_for_agent(agent_id)

    async def execute_group_action(
        self,
        group_id: str,
        action_type: str,
        action_params: Optional[Dict[str, Any]] = None,
        actor: str = "analyst",
        auto_rollback_seconds: Optional[int] = None
    ) -> GroupBatchActionResponse:
        """
        Thực thi batch Response Action trên tất cả các agent thuộc một nhóm.
        Tái sử dụng ResponseActionService để mỗi agent có snapshot riêng, command riêng
        và action record riêng biệt.
        """
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

        agents = await self.group_repo.get_agents_in_group(group_id)
        action_params = action_params or {}

        # Gán metadata nhóm vào action_params để backward compatible và dễ rollback theo nhóm
        enriched_params = {
            **action_params,
            "group_id": group_id,
            "group_name": group.name,
            "batch_reason": action_params.get("reason", f"Batch {action_type} executed on group '{group.name}'")
        }

        results: List[GroupBatchActionResult] = []
        succeeded_count = 0
        failed_count = 0

        for agent in agents:
            try:
                action = await self.action_service.create_and_apply_action(
                    agent_id=agent.id,
                    action_type=action_type,
                    action_params=enriched_params,
                    actor=actor,
                    auto_rollback_seconds=auto_rollback_seconds
                )
                results.append(GroupBatchActionResult(
                    action_id=action.id,
                    agent_id=agent.id,
                    status="applied"
                ))
                succeeded_count += 1
            except Exception as exc:
                logger.error(f"Failed to execute {action_type} on agent '{agent.id}' in group '{group_id}': {exc}", exc_info=True)
                results.append(GroupBatchActionResult(
                    action_id=None,
                    agent_id=agent.id,
                    status="failed",
                    error=str(exc)
                ))
                failed_count += 1

        logger.info(
            f"Batch action '{action_type}' on group '{group.name}' completed: "
            f"{succeeded_count}/{len(agents)} succeeded, {failed_count} failed."
        )

        if succeeded_count == 0 and failed_count > 0:
            for r in results:
                if r.error and "cooldown" in r.error.lower():
                    from app.core.exceptions import FlappingCooldownError
                    raise FlappingCooldownError(r.error)

        return GroupBatchActionResponse(
            group_id=group_id,
            group_name=group.name,
            action_type=action_type,
            total_agents=len(agents),
            succeeded=succeeded_count,
            failed=failed_count,
            actions=results
        )
