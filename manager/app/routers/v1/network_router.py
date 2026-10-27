from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List, Dict, Any
from app.core.deps import get_session
from app.repositories.network_repository import NetworkRepository

router = APIRouter(prefix="/network", tags=["network"])

@router.get("/suspicious")
async def suspicious_connections(
    agent: Optional[str] = Query(None),
    time: str = Query("1h", regex="^(1h|24h|7d)$"),
    risk: Optional[str] = Query(None, regex="^(high|medium|low)$"),
    limit: int = Query(50, le=200),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    repo = NetworkRepository(session)
    return await repo.get_suspicious(
        agent_id=agent, time_range=time, risk=risk, limit=limit
    )

@router.get("/top-talkers")
async def top_talkers(
    agent: Optional[str] = Query(None),
    time: str = Query("1h", regex="^(1h|24h|7d)$"),
    limit: int = Query(10, le=50),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    repo = NetworkRepository(session)
    return await repo.get_top_talkers(agent_id=agent, time_range=time, limit=limit)

@router.get("/protocols")
async def protocols(
    agent: Optional[str] = Query(None),
    time: str = Query("1h", regex="^(1h|24h|7d)$"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    repo = NetworkRepository(session)
    return await repo.get_protocols(agent_id=agent, time_range=time)

@router.get("/{flow_id}")
async def flow_detail(
    flow_id: str,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    repo = NetworkRepository(session)
    flow = await repo.get_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return {
        'id': flow.id,
        'process_name': flow.process_name or 'unknown',
        'pid': flow.pid,
        'src_ip': flow.src_ip,
        'src_port': flow.src_port,
        'dst_ip': flow.dst_ip,
        'dst_port': flow.dst_port,
        'protocol': flow.protocol,
        'agent_id': flow.agent_id,
        'bytes_sent': flow.bytes_sent,
        'packets_sent': flow.packets_sent,
        'created_at': flow.created_at.isoformat() if flow.created_at else None,
    }
