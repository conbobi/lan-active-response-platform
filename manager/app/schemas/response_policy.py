from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ResponsePolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Tên chính sách phản ứng")
    description: Optional[str] = Field(None, max_length=256)
    min_score: float = Field(..., ge=0.0, le=100.0, description="Ngưỡng điểm rủi ro tối thiểu")
    max_score: float = Field(..., ge=0.0, le=100.0, description="Ngưỡng điểm rủi ro tối đa")
    action_type: str = Field(..., description="Hành động: alert, block_ip, isolate, kill...")
    scope: str = Field(default="agent", description="Phạm vi phản ứng: agent hoặc group")
    target_group_id: Optional[str] = Field(None, description="Nhóm áp dụng (None nếu áp dụng chung)")
    action_params: Dict[str, Any] = Field(default_factory=dict, description="Tham số bổ sung cho action")
    auto_rollback_seconds: Optional[int] = Field(None, ge=0, description="Thời gian tự động rollback")
    priority: int = Field(default=0, description="Thứ tự ưu tiên đánh giá (số lớn ưu tiên trước)")
    is_active: bool = Field(default=True, description="Trạng thái kích hoạt")


class ResponsePolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=256)
    min_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    max_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    action_type: Optional[str] = None
    scope: Optional[str] = None
    target_group_id: Optional[str] = None
    action_params: Optional[Dict[str, Any]] = None
    auto_rollback_seconds: Optional[int] = None
    priority: Optional[int] = None
    is_active: Optional[bool] = None


class ResponsePolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    min_score: float
    max_score: float
    action_type: str
    scope: str
    target_group_id: Optional[str] = None
    target_group_name: Optional[str] = None
    action_params: Optional[Dict[str, Any]] = Field(default_factory=dict)
    auto_rollback_seconds: Optional[int] = None
    priority: int
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PolicyEvaluateRequest(BaseModel):
    agent_id: str = Field(..., description="ID của agent phát sinh sự kiện rủi ro")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Điểm rủi ro (smoothed score)")
    dry_run: bool = Field(default=True, description="Chế độ chạy thử: true = chỉ mô phỏng, false = thực thi thật")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Ngữ cảnh bổ sung")


class AffectedGroupInfo(BaseModel):
    id: str
    name: str


class SimulatedActionInfo(BaseModel):
    agent_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    action_type: str
    auto_rollback_seconds: Optional[int] = None


class PolicyEvaluateResponse(BaseModel):
    dry_run: bool
    agent_id: str
    risk_score: float
    matched_policy: Optional[ResponsePolicyResponse] = None
    scope: str  # agent | group | none
    action_type: Optional[str] = None
    affected_groups: List[AffectedGroupInfo] = []
    affected_agents: List[Dict[str, Any]] = []
    simulated_actions: List[SimulatedActionInfo] = []
    executed: bool = False
    execution_summary: Optional[Dict[str, Any]] = None
