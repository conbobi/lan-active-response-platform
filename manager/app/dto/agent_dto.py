# manager/app/dto/agent_dto.py
from pydantic import BaseModel

class AgentDataIn(BaseModel):
    agent_id: str
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    firewall_active: bool
    timestamp: int