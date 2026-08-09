# manager/app/services/agent_service.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.agent import Agent, AgentStats
from datetime import datetime

async def process_agent_data(db: AsyncSession, data: dict):
    agent_id = data["agent_id"]
    # Cập nhật hoặc tạo mới Agent
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        agent = Agent(agent_id=agent_id, hostname=agent_id, is_online=True, last_seen=datetime.utcnow())
        db.add(agent)
    else:
        agent.is_online = True
        agent.last_seen = datetime.utcnow()

    # Lưu thống kê mới
    stats = AgentStats(
        agent_id=agent_id,
        cpu_percent=data["cpu_percent"],
        ram_percent=data["ram_percent"],
        disk_percent=data["disk_percent"],
        firewall_active=data["firewall_active"],
        timestamp=datetime.fromtimestamp(data["timestamp"])
    )
    db.add(stats)
    await db.commit()