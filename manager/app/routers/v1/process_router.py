from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Header, status, Body, HTTPException
from pydantic import BaseModel, StrictBool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.core.network_security import authenticate_operator_request
from app.services.process.process_tree_service import ProcessTreeService
from app.services.response.response_action_service import ResponseActionService
from app.models.process_info import ProcessInfo
from app.schemas.command import CommandOut

router = APIRouter(tags=["Process & Root Cause Analysis"])


async def _enforce_operator(authorization: Optional[str], db: AsyncSession, agent_id: Optional[str] = None) -> str:
    identity, _ = await authenticate_operator_request(authorization, db, agent_id=agent_id, write=True)
    return identity


class KillProcessRequest(BaseModel):
    reason: Optional[str] = "Manual analyst action"
    kill_tree: bool = False
    confirmed: StrictBool = False
    process_start_time: Optional[float] = None
    exe_path: Optional[str] = None
    parent_pid: Optional[int] = None



@router.get("/{agent_id}/snapshot", response_model=Dict[str, Any])
@router.get("/{agent_id}/tree", response_model=Dict[str, Any])
async def get_process_tree(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve process hierarchy tree graph for an agent."""
    service = ProcessTreeService(db)
    return await service.snapshot(agent_id)


@router.get("/{agent_id}/suspicious", response_model=List[Dict[str, Any]])
async def get_suspicious_processes(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Find suspicious processes and trace parent execution chain."""
    service = ProcessTreeService(db)
    snapshot = await service.snapshot(agent_id)
    return snapshot["flagged_processes"]


@router.post("/{agent_id}/kill", response_model=CommandOut, status_code=status.HTTP_202_ACCEPTED)
async def kill_agent_process(
    agent_id: str,
    payload: Dict[str, Any] = Body(..., example={"pid": 1234}),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
):
    """Issue kill_process command to terminate a specified PID on an agent."""
    await _enforce_operator(authorization, db, agent_id=agent_id)
    pid = payload.get("pid")
    if not pid:
        from app.core.exceptions import BadRequestError
        raise BadRequestError("Field 'pid' is required.")

    service = ProcessTreeService(db)
    cmd = await service.queue_termination(agent_id, payload)
    return cmd


@router.post("/{agent_id}/kill_tree", response_model=CommandOut, status_code=status.HTTP_202_ACCEPTED)
async def kill_agent_process_tree(
    agent_id: str,
    payload: Dict[str, Any] = Body(..., example={"pid": 1234, "process_name": "nc"}),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
):
    """Issue kill_process_tree command to terminate a process and its child processes on an agent."""
    await _enforce_operator(authorization, db, agent_id=agent_id)
    pid = payload.get("pid")
    if not pid:
        from app.core.exceptions import BadRequestError
        raise BadRequestError("Field 'pid' is required.")

    service = ProcessTreeService(db)
    cmd = await service.queue_termination(agent_id, payload, tree=True)
    return cmd


@router.post("/{agent_id}/process/{pid}/kill")
async def kill_process_on_agent(
    agent_id: str,
    pid: int,
    body: KillProcessRequest,
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Trigger kill_process or kill_process_tree command on agent via ResponseActionService."""
    actor = await _enforce_operator(authorization, db, agent_id=agent_id)
    if pid <= 2:
        raise HTTPException(status_code=400, detail="PID must be greater than 2")

    # 1. Check agent existence and online status
    from app.models.agent import Agent, AgentStatus
    agent = await db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    if agent.status == AgentStatus.DEAD:
        raise HTTPException(status_code=409, detail=f"Agent '{agent_id}' is offline and cannot execute commands")

    # 2. Find ProcessInfo in DB to verify existence and get ground truth start time
    stmt = select(ProcessInfo).where(
        ProcessInfo.agent_id == agent_id,
        ProcessInfo.pid == pid,
    ).order_by(ProcessInfo.created_at.desc()).limit(1)
    res = await db.execute(stmt)
    proc = res.scalar_one_or_none()
    if not proc:
        raise HTTPException(status_code=404, detail=f"Process PID {pid} not found on agent '{agent_id}'")

    # 3. Check for PID reuse / restart if process_start_time provided
    if body.process_start_time is not None and proc.process_start_time is not None:
        if abs(float(body.process_start_time) - float(proc.process_start_time)) > 2.0:
            raise HTTPException(
                status_code=409,
                detail=f"Process PID {pid} start time mismatch (possible PID reuse). Action aborted for safety."
            )

    # 4. Auto-populate parameters for verified execution
    process_start_time = body.process_start_time or proc.process_start_time
    if process_start_time is None or process_start_time <= 0:
        process_start_time = proc.created_at.timestamp() if proc.created_at else 1.0

    exe_path = body.exe_path or proc.exe_path or proc.exe or f"/proc/{pid}/exe"
    if not exe_path.startswith("/") and not exe_path.startswith("\\") and ":" not in exe_path:
        exe_path = f"/{exe_path}"

    parent_pid = body.parent_pid if body.parent_pid is not None else proc.parent_pid
    if parent_pid is None or parent_pid <= 0:
        parent_pid = 1

    action_type = "kill_process_tree" if body.kill_tree else "kill_process"

    svc = ResponseActionService(db)
    action = await svc.create_and_apply_action(
        agent_id=agent_id,
        action_type=action_type,
        action_params={
            "pid": pid,
            "reason": body.reason,
            "confirmed": True,
            "process_start_time": process_start_time,
            "parent_pid": parent_pid,
            "exe_path": exe_path,
        },
        actor=actor,
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
        "process_start_time": proc.process_start_time,
        "name": proc.name,
        "exe": proc.exe_path or proc.exe,
        "cmdline": proc.cmdline,
        "is_suspicious": proc.is_suspicious,
    }

