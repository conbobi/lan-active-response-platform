from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.response_policy import (
    ResponsePolicyCreate,
    ResponsePolicyUpdate,
    ResponsePolicyResponse,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse
)
from app.services.response_policy_service import ResponsePolicyService
from app.services.policy_engine_service import PolicyEngineService
from app.core.exceptions import NotFoundError

router = APIRouter(tags=["Response Policies & Policy Engine"])


# ==============================================================================
# RESPONSE POLICIES CRUD
# ==============================================================================

@router.get("/policies", response_model=List[ResponsePolicyResponse])
async def list_policies(
    db: AsyncSession = Depends(get_db)
):
    """Lấy danh sách tất cả các chính sách phản ứng (Response Policies) sắp xếp theo độ ưu tiên."""
    service = ResponsePolicyService(db)
    policies = await service.list_policies()
    res = []
    for p in policies:
        dto = ResponsePolicyResponse.model_validate(p)
        if p.target_group:
            dto.target_group_name = p.target_group.name
        res.append(dto)
    return res


@router.post("/policies", response_model=ResponsePolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    dto: ResponsePolicyCreate,
    db: AsyncSession = Depends(get_db)
):
    """Tạo mới một Response Policy (ánh xạ score -> action -> scope)."""
    service = ResponsePolicyService(db)
    policy = await service.create_policy(
        name=dto.name,
        min_score=dto.min_score,
        max_score=dto.max_score,
        action_type=dto.action_type,
        scope=dto.scope,
        target_group_id=dto.target_group_id,
        description=dto.description,
        action_params=dto.action_params,
        auto_rollback_seconds=dto.auto_rollback_seconds,
        priority=dto.priority,
        is_active=dto.is_active
    )
    res = ResponsePolicyResponse.model_validate(policy)
    if policy.target_group:
        res.target_group_name = policy.target_group.name
    return res


@router.get("/policies/{policy_id}", response_model=ResponsePolicyResponse)
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy thông tin chi tiết của một Response Policy."""
    service = ResponsePolicyService(db)
    policy = await service.get_policy(policy_id)
    if not policy:
        raise NotFoundError(f"ResponsePolicy with ID '{policy_id}' was not found.")
    res = ResponsePolicyResponse.model_validate(policy)
    if policy.target_group:
        res.target_group_name = policy.target_group.name
    return res


@router.put("/policies/{policy_id}", response_model=ResponsePolicyResponse)
async def update_policy(
    policy_id: str,
    dto: ResponsePolicyUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Cập nhật một Response Policy."""
    service = ResponsePolicyService(db)
    policy = await service.update_policy(
        policy_id=policy_id,
        name=dto.name,
        description=dto.description,
        min_score=dto.min_score,
        max_score=dto.max_score,
        action_type=dto.action_type,
        scope=dto.scope,
        target_group_id=dto.target_group_id,
        action_params=dto.action_params,
        auto_rollback_seconds=dto.auto_rollback_seconds,
        priority=dto.priority,
        is_active=dto.is_active
    )
    res = ResponsePolicyResponse.model_validate(policy)
    if policy.target_group:
        res.target_group_name = policy.target_group.name
    return res


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Xóa một Response Policy."""
    service = ResponsePolicyService(db)
    await service.delete_policy(policy_id)
    return None


# ==============================================================================
# POLICY ENGINE EVALUATION & DRY-RUN PREVIEW
# ==============================================================================

@router.post("/policies/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate_policy(
    req: PolicyEvaluateRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Đánh giá điểm rủi ro qua Policy Engine với hỗ trợ Dry-Run mode:
    - dry_run = true: Mô phỏng hành vi, trả về policy khớp và danh sách các máy/nhóm sẽ bị tác động mà KHÔNG thực thi lệnh thật.
    - dry_run = false: Tự động kích hoạt phản ứng thật dựa trên policy và scope đã xác định.
    """
    service = PolicyEngineService(db)
    return await service.evaluate_and_execute(
        agent_id=req.agent_id,
        risk_score=req.risk_score,
        context=req.context,
        dry_run=req.dry_run
    )
