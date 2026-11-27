"""Incident containment API. Read: operator with Agent scope. Request: operator/admin. Approve: admin."""
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.core.deps import get_db
from app.core.network_security import authenticate_operator_request
from app.models.containment import ContainmentAction
from app.models.incident import Incident
from app.services.response import containment as ct

router = APIRouter(prefix="/containment", tags=["Containment"])


class ActionRequest(BaseModel):
    kind: Literal["collect_process_evidence", "inspect_file", "quarantine_file", "terminate_process"]
    target: Dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(..., max_length=2000)


class ReasonBody(BaseModel):
    reason: Optional[str] = Field(None, max_length=2000)


async def _incident(db, incident_id, authorization, roles=None):
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Không tìm thấy incident")
    actor, _ = await authenticate_operator_request(authorization, db, agent_id=incident.agent_id,
                                                   write=roles is not None, allowed_write_roles=roles)
    return incident, actor


@router.get("/incidents/{incident_id}/overview")
async def overview(incident_id: str, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    incident, _ = await _incident(db, incident_id, authorization)
    view = await ct.overview(db, incident)
    await db.commit()
    return view


@router.post("/incidents/{incident_id}/actions", status_code=201)
async def request_action(incident_id: str, body: ActionRequest, authorization: Optional[str] = Header(None),
                         db=Depends(get_db)):
    incident, actor = await _incident(db, incident_id, authorization, {"admin", "operator"})
    action = await ct.request(db, incident, body.kind, body.target, body.reason, actor)
    await db.commit()
    return {"action_id": action.id, "status": action.status, "status_label": ct.STATUS_LABEL.get(action.status)}


@router.post("/actions/{action_id}/{operation}")
async def decide(action_id: str, operation: Literal["approve", "reject", "restore"], body: ReasonBody,
                 authorization: Optional[str] = Header(None), db=Depends(get_db)):
    action = await db.get(ContainmentAction, action_id)
    if action is None:
        raise HTTPException(404, "Không tìm thấy hành động")
    incident = await db.get(Incident, action.incident_id) if action.incident_id else None
    roles = {"admin"} if operation in ("approve", "reject") else {"admin", "operator"}
    actor, _ = await authenticate_operator_request(authorization, db, agent_id=action.agent_id, write=True,
                                                   allowed_write_roles=roles)
    if operation == "approve":
        action = await ct.approve(db, action_id, actor)
    elif operation == "reject":
        action = await ct.reject(db, action_id, actor)
    else:
        if incident is None:
            raise HTTPException(409, "Hành động không gắn với incident")
        action = await ct.request(db, incident, "restore_file", {}, body.reason or "", actor, parent=action)
    await db.commit()
    return {"action_id": action.id, "status": action.status, "status_label": ct.STATUS_LABEL.get(action.status)}
