# manager/app/routers/dashboard.py
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.deps import get_db
from app.models.agent import Agent, AgentStats
from fastapi.responses import HTMLResponse
import os

router = APIRouter()
templates = Jinja2Templates(directory="/app/app/templates")

@router.get("/")
async def dashboard(request: Request):
    template = templates.env.get_template("dashboard.html")
    rendered = template.render({"request": request})
    return HTMLResponse(content=rendered)


@router.get("/api/agents")
async def get_agents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent))
    agents = result.scalars().all()
    data = []
    for agent in agents:
        stmt = select(AgentStats).where(
            AgentStats.agent_id == agent.agent_id
        ).order_by(desc(AgentStats.timestamp)).limit(1)
        last_stat = (await db.execute(stmt)).scalar_one_or_none()
        data.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "is_online": agent.is_online,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "cpu_percent": last_stat.cpu_percent if last_stat else None,
            "ram_percent": last_stat.ram_percent if last_stat else None,
            "disk_percent": last_stat.disk_percent if last_stat else None,
            "firewall_active": last_stat.firewall_active if last_stat else None,
        })
    return data
