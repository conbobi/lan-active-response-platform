from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.response_action import (
    ResponseActionCreate,
    ResponseActionResponse,
    UndoActionRequest,
    UndoBatchRequest,
    UndoBatchResponse
)
from app.schemas.action_audit_log import ActionAuditLogResponse
from app.schemas.auto_rollback_setting import (
    AutoRollbackSettingRequest,
    AutoRollbackSettingResponse
)
from app.services.response_action_service import ResponseActionService
from app.services.rollback_service import RollbackService
from app.services.action_audit_log_service import ActionAuditLogService
from app.services.setting_service import SettingService
from app.core.exceptions import NotFoundError

router = APIRouter(tags=["Response Actions & Rollback"])


# ==============================================================================
# RESPONSE ACTIONS CRUD & EXECUTION
# ==============================================================================

@router.post("/actions", response_model=ResponseActionResponse, status_code=status.HTTP_201_CREATED)
async def create_and_apply_action(
    dto: ResponseActionCreate,
    db: AsyncSession = Depends(get_db)
):
    """Thực thi một response action mới (isolate, kill, block_ip, quarantine) có lưu snapshot."""
    service = ResponseActionService(db)
    return await service.create_and_apply_action(
        agent_id=dto.agent_id,
        action_type=dto.action_type.value if hasattr(dto.action_type, "value") else str(dto.action_type),
        action_params=dto.action_params,
        incident_id=dto.incident_id,
        actor="analyst",
        auto_rollback_seconds=dto.auto_rollback_seconds
    )


@router.get("/actions/{action_id}", response_model=ResponseActionResponse)
async def get_response_action(
    action_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy thông tin chi tiết của một response action và snapshot của nó."""
    service = ResponseActionService(db)
    action = await service.get_action(action_id)
    if not action:
        raise NotFoundError(f"ResponseAction '{action_id}' was not found.")
    return action


@router.post("/actions/{action_id}/undo", response_model=ResponseActionResponse)
async def undo_single_action(
    action_id: str,
    req: Optional[UndoActionRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Undo thủ công 1 response action.
    Khôi phục trạng thái agent dựa trên snapshot và gửi lệnh đảo ngược tương ứng.
    """
    service = RollbackService(db)
    reason = req.reason if req and req.reason else "Manual undo via UI/API"
    return await service.rollback_action(action_id=action_id, reason=reason, actor="analyst")


@router.get("/actions/{action_id}/audit", response_model=List[ActionAuditLogResponse])
async def get_action_audit_logs(
    action_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy lịch sử audit log của một response action."""
    service = ActionAuditLogService(db)
    return await service.get_logs_for_action(action_id)


# ==============================================================================
# AGENT & INCIDENT BATCH ACTIONS
# ==============================================================================

@router.get("/agents/{agent_id}/actions", response_model=List[ResponseActionResponse])
async def list_agent_actions(
    agent_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """Lấy danh sách các response action đã thực hiện trên một agent."""
    service = ResponseActionService(db)
    return await service.list_actions_by_agent(agent_id, limit=limit, offset=offset)


@router.post("/agents/{agent_id}/undo-all", response_model=UndoBatchResponse)
async def undo_all_agent_actions(
    agent_id: str,
    req: Optional[UndoBatchRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """Undo toàn bộ các response action đang có hiệu lực trên một agent."""
    service = RollbackService(db)
    reason = req.reason if req and req.reason else "Batch agent undo via UI/API"
    return await service.rollback_agent_actions(agent_id=agent_id, reason=reason, actor="analyst")


@router.get("/incidents/{incident_id}/actions", response_model=List[ResponseActionResponse])
async def list_incident_actions(
    incident_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy danh sách các response action thuộc về một incident."""
    service = ResponseActionService(db)
    return await service.list_actions_by_incident(incident_id)


@router.post("/incidents/{incident_id}/undo-all", response_model=UndoBatchResponse)
async def undo_all_incident_actions(
    incident_id: str,
    req: Optional[UndoBatchRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """Undo toàn bộ các response action đang áp dụng thuộc về một incident."""
    service = RollbackService(db)
    reason = req.reason if req and req.reason else "Batch incident undo via UI/API"
    return await service.rollback_incident_actions(incident_id=incident_id, reason=reason, actor="analyst")


# ==============================================================================
# AUTO-ROLLBACK CONFIGURATION SETTINGS
# ==============================================================================

@router.get("/settings/auto-rollback", response_model=AutoRollbackSettingResponse)
async def get_auto_rollback_settings(
    db: AsyncSession = Depends(get_db)
):
    """Lấy cấu hình thời gian timeout và bật/tắt tính năng auto-rollback."""
    service = SettingService(db)
    res = await service.get_auto_rollback_settings()
    return AutoRollbackSettingResponse(**res)


@router.patch("/settings/auto-rollback", response_model=AutoRollbackSettingResponse)
async def update_auto_rollback_settings(
    req: AutoRollbackSettingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Cập nhật cấu hình auto-rollback (timeout, enabled, cooldown)."""
    service = SettingService(db)
    res = await service.update_auto_rollback_settings(
        timeout_seconds=req.timeout_seconds,
        enabled=req.enabled,
        cooldown_seconds=req.cooldown_seconds
    )
    return AutoRollbackSettingResponse(**res)
