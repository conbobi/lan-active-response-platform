from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.agent import AgentCreate, AgentUpdate, AgentOut
from app.schemas.heartbeat import HeartbeatDTO
from app.services.agent_service import AgentService
from app.services.topology_service import topology_facade
from app.schemas.agent import AgentHistoryOut
from app.repositories.agent_history_repository import AgentHistoryRepository
router = APIRouter(tags=["Agents"])


@router.post("/heartbeat", status_code=status.HTTP_200_OK)
async def agent_heartbeat(dto: HeartbeatDTO, db: AsyncSession = Depends(get_db)):
    """Update agent heartbeat and metrics."""
    await topology_facade.process_heartbeat(dto, db)
    return {"status": "ok", "message": "Heartbeat received"}

@router.get("/{agent_id}/history", response_model=List[AgentHistoryOut])
async def get_agent_history(agent_id: str, limit: int = 50, db: AsyncSession = Depends(get_db)):
    repo = AgentHistoryRepository(db)
    history = await repo.get_history(agent_id, limit)
    return history

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
    agent = await service.get_agent(agent_id)
    updated = await service.repository.update(agent_id, dto)
    return updated


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