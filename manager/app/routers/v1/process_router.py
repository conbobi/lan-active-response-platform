from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, status, Body, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.services.process.process_tree_service import ProcessTreeService
from app.services.response.response_action_service import ResponseActionService
from app.models.process_info import ProcessInfo
from app.schemas.command import CommandOut

router = APIRouter(tags=["Process & Root Cause Analysis"])


class KillProcessRequest(BaseModel):
    reason: Optional[str] = "Manual analyst action"
    kill_tree: bool = False  # False = kill single, True = kill tree



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


@router.post("/{agent_id}/process/{pid}/kill")
async def kill_process_on_agent(
    agent_id: str,
    pid: int,
    body: KillProcessRequest,
    db: AsyncSession = Depends(get_db),
):
    """Trigger kill_process or kill_process_tree command on agent via ResponseActionService."""
    action_type = "kill_process_tree" if body.kill_tree else "kill_process"

    svc = ResponseActionService(db)
    action = await svc.create_and_apply_action(
        agent_id=agent_id,
        action_type=action_type,
        action_params={
            "pid": pid,
            "reason": body.reason,
        },
        actor="analyst",
    )

    return {
        "action_id": action.id,
        "status": action.status,
        "action_type": action_type,
        "pid": pid,
    }


@router.get("/{agent_id}/process/{pid}")
async def get_process_detail(agent_id: str, pid: int, db: AsyncSession = Depends(get_db)):
    """Get process info by PID."""
    stmt = select(ProcessInfo).where(
        ProcessInfo.agent_id == agent_id,
        ProcessInfo.pid == pid,
    ).order_by(ProcessInfo.created_at.desc()).limit(1)

    result = await db.execute(stmt)
    proc = result.scalar_one_or_none()

    if not proc:
        raise HTTPException(404, f"Process PID {pid} not found on agent {agent_id}")

    return {
        "pid": proc.pid,
        "ppid": proc.parent_pid,
        "name": proc.name,
        "exe": proc.exe_path or proc.exe,
        "cmdline": proc.cmdline,
        "is_suspicious": proc.is_suspicious,
    }

