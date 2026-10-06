import logging
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.response_policy import ResponsePolicy
from app.repositories.response_policy_repository import ResponsePolicyRepository
from app.repositories.agent_group_repository import AgentGroupRepository
from app.core.exceptions import NotFoundError, BadRequestError

logger = logging.getLogger(__name__)


class ResponsePolicyService:
    """
    Service quản lý cấu hình các Response Policy và thực hiện tìm kiếm (matching)
    policy dựa trên risk_score và agent/group context.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.policy_repo = ResponsePolicyRepository(session)
        self.group_repo = AgentGroupRepository(session)

    async def list_policies(self) -> List[ResponsePolicy]:
        """Lấy danh sách tất cả policies sắp xếp theo priority giảm dần."""
        return await self.policy_repo.list_all_ordered()

    async def get_policy(self, policy_id: str) -> Optional[ResponsePolicy]:
        """Lấy chi tiết 1 policy."""
        return await self.policy_repo.get_by_id_with_group(policy_id)

    async def create_policy(
        self,
        name: str,
        min_score: float,
        max_score: float,
        action_type: str,
        scope: str = "agent",
        target_group_id: Optional[str] = None,
        description: Optional[str] = None,
        action_params: Optional[Dict[str, Any]] = None,
        auto_rollback_seconds: Optional[int] = None,
        priority: int = 0,
        is_active: bool = True
    ) -> ResponsePolicy:
        """Tạo mới một Response Policy."""
        if min_score > max_score:
            raise BadRequestError(f"min_score ({min_score}) cannot be greater than max_score ({max_score}).")

        if scope not in ("agent", "group"):
            raise BadRequestError(f"Invalid scope '{scope}'. Allowed scopes are 'agent' or 'group'.")

        if target_group_id:
            group = await self.group_repo.get(target_group_id)
            if not group:
                raise NotFoundError(f"Target AgentGroup '{target_group_id}' was not found.")

        policy_id = f"pol_{uuid.uuid4().hex[:12]}"
        policy = ResponsePolicy(
            id=policy_id,
            name=name.strip(),
            description=description,
            min_score=min_score,
            max_score=max_score,
            action_type=action_type.strip(),
            scope=scope,
            target_group_id=target_group_id,
            action_params=action_params or {},
            auto_rollback_seconds=auto_rollback_seconds,
            priority=priority,
            is_active=is_active
        )
        await self.policy_repo.add(policy)
        await self.session.commit()
        await self.session.refresh(policy)
        logger.info(f"Created ResponsePolicy '{policy.name}' ({policy.id}) for score range {min_score}-{max_score}.")
        return policy

    async def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        action_type: Optional[str] = None,
        scope: Optional[str] = None,
        target_group_id: Optional[str] = None,
        action_params: Optional[Dict[str, Any]] = None,
        auto_rollback_seconds: Optional[int] = None,
        priority: Optional[int] = None,
        is_active: Optional[bool] = None
    ) -> ResponsePolicy:
        """Cập nhật chính sách phản ứng."""
        policy = await self.policy_repo.get(policy_id)
        if not policy:
            raise NotFoundError(f"ResponsePolicy with ID '{policy_id}' was not found.")

        new_min = min_score if min_score is not None else policy.min_score
        new_max = max_score if max_score is not None else policy.max_score
        if new_min > new_max:
            raise BadRequestError(f"min_score ({new_min}) cannot be greater than max_score ({new_max}).")

        if scope is not None:
            if scope not in ("agent", "group"):
                raise BadRequestError(f"Invalid scope '{scope}'. Allowed scopes are 'agent' or 'group'.")
            policy.scope = scope

        if target_group_id is not None:
            if target_group_id != "":
                group = await self.group_repo.get(target_group_id)
                if not group:
                    raise NotFoundError(f"Target AgentGroup '{target_group_id}' was not found.")
                policy.target_group_id = target_group_id
            else:
                policy.target_group_id = None

        if name is not None:
            policy.name = name.strip()
        if description is not None:
            policy.description = description
        if min_score is not None:
            policy.min_score = min_score
        if max_score is not None:
            policy.max_score = max_score
        if action_type is not None:
            policy.action_type = action_type.strip()
        if action_params is not None:
            policy.action_params = action_params
        if auto_rollback_seconds is not None:
            policy.auto_rollback_seconds = auto_rollback_seconds
        if priority is not None:
            policy.priority = priority
        if is_active is not None:
            policy.is_active = is_active

        await self.session.commit()
        await self.session.refresh(policy)
        logger.info(f"Updated ResponsePolicy '{policy.id}' ({policy.name}).")
        return policy

    async def delete_policy(self, policy_id: str) -> None:
        """Xóa một chính sách phản ứng."""
        policy = await self.policy_repo.get(policy_id)
        if not policy:
            raise NotFoundError(f"ResponsePolicy with ID '{policy_id}' was not found.")

        await self.policy_repo.delete(policy.id)
        await self.session.commit()
        logger.info(f"Deleted ResponsePolicy '{policy_id}'.")

    async def match_policy(
        self,
        score: float,
        group_ids: Optional[List[str]] = None
    ) -> Optional[ResponsePolicy]:
        """
        Tìm policy phù hợp nhất theo score và danh sách nhóm của agent.
        Trả về policy có priority cao nhất.
        """
        policies = await self.policy_repo.find_matching_policies(score, group_ids)
        return policies[0] if policies else None
