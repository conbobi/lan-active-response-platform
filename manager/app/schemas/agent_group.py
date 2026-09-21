from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AgentGroupCreate(BaseModel):
    id: Optional[str] = Field(None, max_length=64, description="Mã định danh nhóm (tùy chọn, ví dụ: grp_sales)")
    name: str = Field(..., min_length=1, max_length=128, description="Tên nhóm (ví dụ: HR, IT, Server)")
    description: Optional[str] = Field(None, max_length=256, description="Mô tả nhóm")


class AgentGroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=256)


class AgentGroupMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    agent_id: str
    added_at: datetime
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: Optional[str] = None
    is_isolated: Optional[bool] = None


class AgentGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    member_count: int = 0
    created_at: datetime
    updated_at: datetime


class AgentGroupDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    members: List[AgentGroupMemberResponse] = []
    created_at: datetime
    updated_at: datetime


class AddAgentsToGroupRequest(BaseModel):
    agent_ids: List[str] = Field(..., min_length=1, description="Danh sách agent_id cần thêm vào nhóm")


class GroupBatchActionRequest(BaseModel):
    action_type: str = Field(..., description="Loại phản ứng: isolate, block_ip, quarantine, kill...")
    action_params: Dict[str, Any] = Field(default_factory=dict, description="Tham số đi kèm action")
    auto_rollback_seconds: Optional[int] = Field(None, ge=0, description="Thời gian tự động hoàn nguyên (giây). None để dùng mặc định")


class GroupBatchActionResult(BaseModel):
    action_id: Optional[str] = None
    agent_id: str
    status: str  # applied | failed
    error: Optional[str] = None


class GroupBatchActionResponse(BaseModel):
    group_id: str
    group_name: str
    action_type: str
    total_agents: int
    succeeded: int
    failed: int
    actions: List[GroupBatchActionResult]
