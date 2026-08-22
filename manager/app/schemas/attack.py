from pydantic import BaseModel, Field

class AttackRequestDTO(BaseModel):
    target_agent_id: str = Field(..., description="Agent ID mục tiêu")
    target_ip: str = Field(..., description="IP đích")
    target_port: int = Field(80, ge=1, le=65535)
    duration: int = Field(10, ge=1, le=300)