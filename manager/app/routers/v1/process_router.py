from typing import Dict, Any, List
from fastapi import APIRouter, Depends, status, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.services.process_tree_service import ProcessTreeService
from app.schemas.command import CommandOut

router = APIRouter(tags=["Process & Root Cause Analysis"])


@router.get("/{agent_id}/tree", response_model=Dict[str, Any])
async def get_process_tree(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve process hierarchy tree graph for an agent."""
    service = ProcessTreeService(db)
    return await service.build_tree(agent_id)


@router.get("/{agent_id}/suspicious", response_model=List[Dict[str, Any]])
async def get_suspicious_processes(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Find suspicious processes and trace parent execution chain."""
    service = ProcessTreeService(db)
    return await service.find_suspicious_process(agent_id)


@router.post("/{agent_id}/kill", response_model=CommandOut, status_code=status.HTTP_202_ACCEPTED)
async def kill_agent_process(
    agent_id: str,
    payload: Dict[str, Any] = Body(..., example={"pid": 1234}),
    db: AsyncSession = Depends(get_db)
):
    """Issue kill_process command to terminate a specified PID on an agent."""
    pid = payload.get("pid")
    if not pid:
        from app.core.exceptions import BadRequestError
        raise BadRequestError("Field 'pid' is required.")

    service = ProcessTreeService(db)
    cmd = await service.kill_process(agent_id, int(pid))
    return cmd


@router.post("/{agent_id}/kill_tree", response_model=CommandOut, status_code=status.HTTP_202_ACCEPTED)
async def kill_agent_process_tree(
    agent_id: str,
    payload: Dict[str, Any] = Body(..., example={"pid": 1234, "process_name": "nc"}),
    db: AsyncSession = Depends(get_db)
):
    """Issue kill_process_tree command to terminate a process and its child processes on an agent."""
    pid = payload.get("pid")
    if not pid:
        from app.core.exceptions import BadRequestError
        raise BadRequestError("Field 'pid' is required.")

    service = ProcessTreeService(db)
    cmd = await service.kill_process_tree(agent_id, int(pid), process_name=payload.get("process_name"))
    return cmd
