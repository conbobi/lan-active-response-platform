from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.flow import FlowCreate, FlowOut
from app.services.flow_service import FlowService

router = APIRouter(tags=["Flows"])


@router.post("/", response_model=FlowOut, status_code=status.HTTP_201_CREATED)
async def create_flow(dto: FlowCreate, db: AsyncSession = Depends(get_db)):
    """Record network flow metrics."""
    service = FlowService(db)
    return await service.create_flow(dto)


@router.get("/traffic-stats")
async def get_traffic_stats(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID or server"),
    minutes: int = Query(5, ge=1, le=60, description="Time window in minutes"),
    db: AsyncSession = Depends(get_db)
):
    """Get aggregated traffic statistics (SYN, UDP, Total) for charts."""
    service = FlowService(db)
    return await service.get_traffic_series(agent_id=agent_id, minutes=minutes)


@router.get("", response_model=List[FlowOut], include_in_schema=False)
@router.get("/", response_model=List[FlowOut])
async def list_flows(
    skip: int = 0,
    limit: int = 100,
    agent_id: Optional[str] = Query(None, description="Filter by agent ID or manager"),
    minutes: int = Query(5, ge=1, le=60, description="Recent time window in minutes"),
    db: AsyncSession = Depends(get_db)
):
    """List network flows."""
    service = FlowService(db)
    return await service.list_flows(skip=skip, limit=limit, agent_id=agent_id, minutes=minutes)


@router.get("/{flow_id}", response_model=FlowOut)
async def get_flow(flow_id: str, db: AsyncSession = Depends(get_db)):
    """Get flow details."""
    service = FlowService(db)
    return await service.get_flow(flow_id)


@router.get("/beaconing/{agent_id}")
async def check_agent_beaconing(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Check if agent exhibits beaconing traffic behavior."""
    service = FlowService(db)
    is_beaconing = await service.check_agent_beaconing(agent_id)
    return {"agent_id": agent_id, "is_beaconing": is_beaconing}
