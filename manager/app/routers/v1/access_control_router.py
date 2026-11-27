"""Access control (host IP block / unblock / restore verification) API.

Roles: analyst reads; operator/admin request; only admin approves block and unblock.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.deps import get_db
from app.core.network_security import authenticate_operator_request
from app.models.incident import Incident
from app.models.ip_block import IpBlock, IpUnblock
from app.services.response import access_control as ac

router = APIRouter(prefix="/access-control", tags=["Access Control"])
REQUEST_ROLES = {"admin", "operator"}
APPROVE_ROLES = {"admin"}


class BlockRequest(BaseModel):
    agent_id: str = Field(..., max_length=64)
    target_ip: str = Field(..., max_length=64)
    incident_id: Optional[str] = Field(None, max_length=64)
    reason: str = Field(..., max_length=2000)


class ReasonRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=2000)


async def _auth(db, authorization, agent_id, roles=None):
    identity, _ = await authenticate_operator_request(
        authorization, db, agent_id=agent_id, write=roles is not None, allowed_write_roles=roles)
    return identity


async def _block(db, block_id) -> IpBlock:
    block = await db.get(IpBlock, block_id)
    if block is None:
        raise HTTPException(404, "Không tìm thấy yêu cầu chặn")
    return block


@router.get("/blocks")
async def list_blocks(agent_id: Optional[str] = None, state: Optional[str] = None, incident_id: Optional[str] = None,
                      limit: int = Query(100, ge=1, le=500), authorization: Optional[str] = Header(None),
                      db=Depends(get_db)):
    await _auth(db, authorization, agent_id)
    await ac.expire(db, agent_id)
    await db.commit()
    query = select(IpBlock).order_by(IpBlock.created_at.desc()).limit(limit)
    if agent_id:
        query = query.where(IpBlock.agent_id == agent_id)
    if incident_id:
        query = query.where(IpBlock.incident_id == incident_id)
    if state == "active":
        query = query.where(IpBlock.effective_state.in_(ac.ACTIVE_EFFECT) | IpBlock.status.in_(["PENDING_APPROVAL"]))
    elif state:
        query = query.where(IpBlock.effective_state == state)
    items = []
    for block in (await db.scalars(query)).all():
        try:
            await authenticate_operator_request(authorization, db, agent_id=block.agent_id, write=False)
        except HTTPException:
            continue  # outside this operator's Agent scope
        items.append(await ac.load_view(db, block))
    return {"items": items}


@router.get("/blocks/{block_id}")
async def get_block(block_id: str, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    block = await _block(db, block_id)
    await _auth(db, authorization, block.agent_id)
    await ac.expire(db, block.agent_id)
    await db.commit()
    await db.refresh(block)
    return await ac.load_view(db, block)


@router.get("/incidents/{incident_id}/suggestions")
async def incident_suggestions(incident_id: str, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Không tìm thấy incident")
    await _auth(db, authorization, incident.agent_id)
    return {"incident_id": incident_id, "agent_id": incident.agent_id, "items": await ac.suggestions(db, incident)}


@router.post("/blocks", status_code=201)
async def request_block(body: BlockRequest, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    actor = await _auth(db, authorization, body.agent_id, REQUEST_ROLES)
    block = await ac.request_block(db, body.agent_id, body.target_ip, body.incident_id, body.reason, actor)
    await db.commit()
    return await ac.load_view(db, block)


@router.post("/blocks/{block_id}/approve")
async def approve_block(block_id: str, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    block = await _block(db, block_id)
    actor = await _auth(db, authorization, block.agent_id, APPROVE_ROLES)
    block = await ac.approve_block(db, block_id, actor)
    await db.commit()
    return await ac.load_view(db, block)


@router.post("/blocks/{block_id}/reject")
async def reject_block(block_id: str, body: ReasonRequest, authorization: Optional[str] = Header(None),
                       db=Depends(get_db)):
    block = await _block(db, block_id)
    actor = await _auth(db, authorization, block.agent_id, APPROVE_ROLES)
    block = await ac.reject_block(db, block_id, actor, body.reason)
    await db.commit()
    return await ac.load_view(db, block)


@router.post("/blocks/{block_id}/unblock", status_code=201)
async def request_unblock(block_id: str, body: ReasonRequest, authorization: Optional[str] = Header(None),
                          db=Depends(get_db)):
    block = await _block(db, block_id)
    actor = await _auth(db, authorization, block.agent_id, REQUEST_ROLES)
    await ac.request_unblock(db, block_id, body.reason, actor)
    await db.commit()
    await db.refresh(block)
    return await ac.load_view(db, block)


@router.post("/unblocks/{unblock_id}/{operation}")
async def decide_unblock(unblock_id: str, operation: str, authorization: Optional[str] = Header(None),
                         db=Depends(get_db)):
    if operation not in ("approve", "reject"):
        raise HTTPException(404, "Thao tác không hợp lệ")
    unblock = await db.get(IpUnblock, unblock_id)
    if unblock is None:
        raise HTTPException(404, "Không tìm thấy yêu cầu bỏ chặn")
    actor = await _auth(db, authorization, unblock.agent_id, APPROVE_ROLES)
    if operation == "approve":
        await ac.approve_unblock(db, unblock_id, actor)
    else:
        await ac.reject_unblock(db, unblock_id, actor)
    await db.commit()
    return await ac.load_view(db, await _block(db, unblock.block_id))


@router.post("/blocks/{block_id}/check", status_code=202)
async def check_block(block_id: str, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    block = await _block(db, block_id)
    actor = await _auth(db, authorization, block.agent_id, REQUEST_ROLES)
    cmd = await ac.request_check(db, block.agent_id, actor)
    await db.commit()
    return {"command_id": cmd.id, "message": "Đã gửi yêu cầu kiểm tra firewall tới Agent"}
