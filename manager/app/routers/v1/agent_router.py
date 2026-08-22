import uuid
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, status, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.agent import AgentCreate, AgentUpdate, AgentOut, AgentHistoryOut
from app.schemas.heartbeat import HeartbeatDTO
from app.schemas.command import CommandOut
from app.schemas.enums import CommandStatus, AgentStatus
from app.models.command import Command
from app.services.agent_service import AgentService
from app.services.topology_service import topology_facade
from app.services.command_dispatcher import command_dispatcher
from app.repositories.agent_history_repository import AgentHistoryRepository
from app.repositories.command_repository import CommandRepository

router = APIRouter(tags=["Agents"])


@router.post("/heartbeat", status_code=status.HTTP_200_OK)
async def agent_heartbeat(dto: HeartbeatDTO, db: AsyncSession = Depends(get_db)):
    """Update agent heartbeat and metrics."""
    await topology_facade.process_heartbeat(dto, db)
    return {"status": "ok", "message": "Heartbeat received"}


@router.get("/{agent_id}/history", response_model=List[AgentHistoryOut])
async def get_agent_history(agent_id: str, limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Retrieve agent telemetry history logs."""
    repo = AgentHistoryRepository(db)
    return await repo.get_history(agent_id, limit)


@router.get("/", response_model=List[AgentOut])
async def list_agents(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List all registered agents."""
    service = AgentService(db)
    return await service.list_agents(skip=skip, limit=limit)


@router.post("/", response_model=AgentOut, status_code=status.HTTP_201_CREATED)
async def create_agent(dto: AgentCreate, db: AsyncSession = Depends(get_db)):
    """Register a new agent."""
    service = AgentService(db)
    return await service.register_agent(dto)


@router.get("/{agent_id}", response_model=AgentOut)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed information for a specific agent."""
    service = AgentService(db)
    return await service.get_agent(agent_id)


@router.put("/{agent_id}", response_model=AgentOut)
async def update_agent(agent_id: str, dto: AgentUpdate, db: AsyncSession = Depends(get_db)):
    """Update agent parameters."""
    service = AgentService(db)
    return await service.repository.update(agent_id, dto)


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Unregister/delete an agent."""
    service = AgentService(db)
    await service.delete_agent(agent_id)


@router.post("/{agent_id}/isolate", response_model=AgentOut)
async def isolate_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Isolate an agent from network operations."""
    service = AgentService(db)
    return await service.isolate_agent(agent_id)


@router.post("/{agent_id}/unisolate", response_model=AgentOut)
async def unisolate_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Restore isolated agent to active network operations."""
    service = AgentService(db)
    return await service.unisolate_agent(agent_id)


@router.post("/{agent_id}/update", response_model=CommandOut, status_code=status.HTTP_202_ACCEPTED)
async def trigger_agent_self_update(
    agent_id: str,
    payload: Dict[str, str] = Body(..., example={"download_url": "http://manager:8000/static/agent_v2.tar.gz", "version": "2.0.0"}),
    db: AsyncSession = Depends(get_db)
):
    """Issue self_update command to trigger agent code/binary update."""
    cmd_repo = CommandRepository(db)
    cmd = Command(
        id=f"cmd_{uuid.uuid4().hex[:12]}",
        agent_id=agent_id,
        action="self_update",
        payload=payload,
        status=CommandStatus.PENDING
    )
    await cmd_repo.add(cmd)
    await command_dispatcher.push_command(cmd.id, agent_id)
    await db.flush()
    return cmd


@router.post("/{agent_id}/quarantine", response_model=AgentOut)
async def quarantine_agent(
    agent_id: str,
    payload: Dict[str, str] = Body(default={"reason": "Quarantine mode requested"}),
    db: AsyncSession = Depends(get_db)
):
    """Switch agent to quarantine mode (restricted communication channel)."""
    service = AgentService(db)
    agent = await service.get_agent(agent_id)
    agent.status = AgentStatus.QUARANTINE
    agent.is_isolated = True

    cmd_repo = CommandRepository(db)
    cmd = Command(
        id=f"cmd_{uuid.uuid4().hex[:12]}",
        agent_id=agent_id,
        action="quarantine",
        payload=payload,
        status=CommandStatus.PENDING
    )
    await cmd_repo.add(cmd)
    await command_dispatcher.push_command(cmd.id, agent_id)
    await db.flush()
    return agent


@router.post("/{agent_id}/release-quarantine", response_model=AgentOut)
async def release_quarantine_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Release agent from quarantine mode back to active state."""
    service = AgentService(db)
    agent = await service.get_agent(agent_id)
    agent.status = AgentStatus.ACTIVE
    agent.is_isolated = False

    cmd_repo = CommandRepository(db)
    cmd = Command(
        id=f"cmd_{uuid.uuid4().hex[:12]}",
        agent_id=agent_id,
        action="release_quarantine",
        payload={"reason": "Quarantine released by operator"},
        status=CommandStatus.PENDING
    )
    await cmd_repo.add(cmd)
    await command_dispatcher.push_command(cmd.id, agent_id)
    await db.flush()
    return agent