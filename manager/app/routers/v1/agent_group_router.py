from typing import List, Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.agent_group import (
    AgentGroupCreate,
    AgentGroupUpdate,
    AgentGroupResponse,
    AgentGroupDetailResponse,
    AgentGroupMemberResponse,
    AddAgentsToGroupRequest,
    GroupBatchActionRequest,
    GroupBatchActionResponse
)
from app.schemas.response_action import UndoBatchRequest, UndoBatchResponse
from app.services.agent_group_service import AgentGroupService
from app.services.rollback_service import RollbackService
from app.core.exceptions import NotFoundError

router = APIRouter(tags=["Agent Groups & Batch Actions"])


# ==============================================================================
# AGENT GROUPS CRUD
# ==============================================================================

@router.get("/groups", response_model=List[AgentGroupResponse])
async def list_agent_groups(
    db: AsyncSession = Depends(get_db)
):
    """Lấy danh sách tất cả các Agent Group kèm số lượng thành viên."""
    service = AgentGroupService(db)
    rows = await service.list_groups_with_count()
    return [
        AgentGroupResponse(
            id=grp.id,
            name=grp.name,
            description=grp.description,
            member_count=count,
            created_at=grp.created_at,
            updated_at=grp.updated_at
        )
        for grp, count in rows
    ]


@router.post("/groups", response_model=AgentGroupResponse, status_code=status.HTTP_201_CREATED)
async def create_agent_group(
    dto: AgentGroupCreate,
    db: AsyncSession = Depends(get_db)
):
    """Tạo mới một Agent Group (HR, IT, Finance, Server...)."""
    service = AgentGroupService(db)
    grp = await service.create_group(name=dto.name, description=dto.description, group_id=dto.id)
    return AgentGroupResponse(
        id=grp.id,
        name=grp.name,
        description=grp.description,
        member_count=0,
        created_at=grp.created_at,
        updated_at=grp.updated_at
    )


@router.get("/groups/{group_id}", response_model=AgentGroupDetailResponse)
async def get_agent_group_detail(
    group_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy thông tin chi tiết một Agent Group cùng danh sách các máy thành viên."""
    service = AgentGroupService(db)
    grp = await service.get_group_with_members(group_id)
    if not grp:
        raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

    members_dto = []
    for m in grp.members:
        ag = m.agent
        members_dto.append(AgentGroupMemberResponse(
            agent_id=m.agent_id,
            added_at=m.added_at,
            hostname=ag.hostname if ag else None,
            ip_address=ag.ip_address if ag else None,
            status=ag.status.value if (ag and hasattr(ag.status, "value")) else str(ag.status) if ag else None,
            is_isolated=getattr(ag, "is_isolated", False) if ag else False
        ))

    return AgentGroupDetailResponse(
        id=grp.id,
        name=grp.name,
        description=grp.description,
        members=members_dto,
        created_at=grp.created_at,
        updated_at=grp.updated_at
    )


@router.put("/groups/{group_id}", response_model=AgentGroupResponse)
async def update_agent_group(
    group_id: str,
    dto: AgentGroupUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Cập nhật tên hoặc mô tả của nhóm."""
    service = AgentGroupService(db)
    grp = await service.update_group(
        group_id=group_id,
        name=dto.name,
        description=dto.description
    )
    agents = await service.list_agents_in_group(group_id)
    return AgentGroupResponse(
        id=grp.id,
        name=grp.name,
        description=grp.description,
        member_count=len(agents),
        created_at=grp.created_at,
        updated_at=grp.updated_at
    )


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent_group(
    group_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Xóa một Agent Group."""
    service = AgentGroupService(db)
    await service.delete_group(group_id)
    return None


# ==============================================================================
# GROUP MEMBERSHIP MANAGEMENT
# ==============================================================================

@router.post("/groups/{group_id}/agents", response_model=AgentGroupDetailResponse)
async def add_agents_to_group(
    group_id: str,
    dto: AddAgentsToGroupRequest,
    db: AsyncSession = Depends(get_db)
):
    """Thêm một hoặc nhiều agent vào một nhóm."""
    service = AgentGroupService(db)
    await service.add_agents_to_group(group_id, dto.agent_ids)
    return await get_agent_group_detail(group_id=group_id, db=db)


@router.delete("/groups/{group_id}/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_agent_from_group(
    group_id: str,
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Xóa một agent khỏi nhóm."""
    service = AgentGroupService(db)
    await service.remove_agent_from_group(group_id, agent_id)
    return None


@router.get("/agents/{agent_id}/groups", response_model=List[AgentGroupResponse])
async def list_agent_groups_for_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy danh sách tất cả các nhóm mà một agent đang trực thuộc."""
    service = AgentGroupService(db)
    groups = await service.list_groups_for_agent(agent_id)
    return [
        AgentGroupResponse(
            id=g.id,
            name=g.name,
            description=g.description,
            member_count=0,
            created_at=g.created_at,
            updated_at=g.updated_at
        )
        for g in groups
    ]


# ==============================================================================
# BATCH ACTIONS & BATCH ROLLBACK FOR GROUPS
# ==============================================================================

@router.post("/groups/{group_id}/actions", response_model=GroupBatchActionResponse, status_code=status.HTTP_201_CREATED)
async def execute_batch_group_action(
    group_id: str,
    req: GroupBatchActionRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Thực thi một response action (isolate, block_ip, quarantine) trên TOÀN BỘ agent trong nhóm.
    Tái sử dụng ResponseActionService: mỗi agent có snapshot riêng, command riêng, và auto-rollback độc lập.
    """
    service = AgentGroupService(db)
    return await service.execute_group_action(
        group_id=group_id,
        action_type=req.action_type,
        action_params=req.action_params,
        actor="analyst",
        auto_rollback_seconds=req.auto_rollback_seconds
    )


@router.post("/groups/{group_id}/undo-all", response_model=UndoBatchResponse)
async def undo_all_group_actions(
    group_id: str,
    req: Optional[UndoBatchRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Hoàn nguyên (Undo/Rollback) toàn bộ response action đang có hiệu lực trên nhóm.
    Khôi phục trạng thái mạng, gỡ cô lập (unisolate) cho tất cả các máy trong nhóm.
    """
    service = RollbackService(db)
    reason = req.reason if req and req.reason else f"Batch group undo via API for group '{group_id}'"
    return await service.rollback_group_actions(
        group_id=group_id,
        reason=reason,
        actor="analyst"
    )
