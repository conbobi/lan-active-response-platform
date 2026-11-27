"""Block / unblock / restore-access lifecycle for host IP blocks.

Action state (``status``):
    PENDING_APPROVAL → APPROVED → DISPATCHED → (TIMEOUT) → SUCCEEDED/FAILED → VERIFIED/VERIFICATION_FAILED
    (or REJECTED). A late receipt after TIMEOUT is still applied: no receipt ≠ not executed.
Firewall state (``effective_state``), only from Agent evidence:
    NOT_BLOCKED, BLOCKING, BLOCKED, PARTIALLY_BLOCKED, UNBLOCKING, UNBLOCKED, UNKNOWN.
Access after unblock (``IpUnblock.access_state``):
    PENDING → UNVERIFIED (rule removed, client not yet seen) → RESTORED (client traffic observed after
    the unblock: packets counted by the Agent's verification rule or a new HTTP request from it), or
    STILL_BLOCKED when another LARP block still drops the address.

Transitions use compare-and-set updates so two operators cannot both move the same action.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import or_, select, update

from app.models.agent import Agent
from app.models.command import Command
from app.models.incident import Incident
from app.models.ip_block import IpBlock, IpBlockEvent, IpUnblock
from app.models.web_access_log import WebAccessLog
from app.schemas.enums import CommandStatus
from app.services.core.command_dispatcher import command_dispatcher

logger = logging.getLogger("larp.access_control")

BLOCK, UNBLOCK, STATUS = "block_ip", "unblock_ip", "blocklist_status"
ACTIONS = {BLOCK, UNBLOCK, STATUS}
DISPATCH_TIMEOUT = timedelta(seconds=int(os.getenv("ACCESS_CONTROL_TIMEOUT_SECONDS", "90")))
OPEN_UNBLOCK = {"PENDING_APPROVAL", "APPROVED", "DISPATCHED", "TIMEOUT"}
ACTIVE_EFFECT = {"BLOCKING", "BLOCKED", "PARTIALLY_BLOCKED", "UNKNOWN", "UNBLOCKING"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def online(agent_id: str) -> bool:
    from app.websocket.agent_ws import connection_manager
    return agent_id in connection_manager.authenticated_connections


def target(ip: str) -> str:
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError as exc:
        raise HTTPException(422, "Địa chỉ IP không hợp lệ: chỉ chặn một địa chỉ host, không chặn dải mạng") from exc
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        raise HTTPException(422, "Không chặn địa chỉ loopback, link-local hoặc multicast")
    return str(address)


def manager_protected(ip: str, agent: Agent) -> Optional[str]:
    """Manager-side protection (the Agent runs its own, stricter preflight before applying)."""
    address = ipaddress.ip_address(ip)
    for cidr in filter(None, (c.strip() for c in os.getenv("LARP_PROTECTED_CIDRS", "").split(","))):
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return f"IP nằm trong danh sách bảo vệ {cidr}"
        except ValueError:
            continue
    if agent.ip_address and ip == agent.ip_address:
        return "Đây là địa chỉ của chính Agent"
    return None


async def event(db, block_id, name, actor, unblock_id=None, **detail):
    db.add(IpBlockEvent(id=uuid.uuid4().hex, block_id=block_id, unblock_id=unblock_id, event=name, actor=actor,
                        detail=detail or None, at=now()))


async def _cas(db, model, row_id, expected, **values) -> bool:
    expected = {expected} if isinstance(expected, str) else set(expected)
    result = await db.execute(update(model).where(model.id == row_id, model.status.in_(expected)).values(**values))
    return result.rowcount == 1


def _dispatch(db, agent_id, action, payload) -> Command:
    cmd = Command(id=f"cmd_{uuid.uuid4().hex[:16]}", agent_id=agent_id, action=action, status=CommandStatus.PENDING,
                  payload={**payload, "confirmed": True}, max_retries=0)  # never re-sent automatically
    db.add(cmd)
    return cmd


# ── requests and approvals ──────────────────────────────────────────────────────────────────
async def request_block(db, agent_id, ip, incident_id, reason, actor, evidence=None) -> IpBlock:
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "Agent không tồn tại")
    ip = target(ip)
    protected = manager_protected(ip, agent)
    if protected:
        raise HTTPException(409, protected)
    if incident_id:
        incident = await db.get(Incident, incident_id)
        if incident is None or incident.agent_id != agent_id:
            raise HTTPException(404, "Incident không thuộc Agent này")
    if not reason or len(reason.strip()) < 5:
        raise HTTPException(422, "Cần nhập lý do chặn (ít nhất 5 ký tự)")
    await db.scalar(select(Agent.id).where(Agent.id == agent_id).with_for_update())
    existing = (await db.scalars(select(IpBlock).where(
        IpBlock.agent_id == agent_id, IpBlock.target_ip == ip,
        or_(IpBlock.status.in_(["PENDING_APPROVAL", "APPROVED", "DISPATCHED"]),
            IpBlock.effective_state.in_(ACTIVE_EFFECT)),
    ).order_by(IpBlock.created_at.desc()))).first()
    if existing is not None:
        return existing  # same request again: no second block for the same Agent+IP
    block = IpBlock(id=uuid.uuid4().hex, agent_id=agent_id, incident_id=incident_id, target_ip=ip,
                    reason=reason.strip()[:2000], requested_by=actor, evidence=evidence, status="PENDING_APPROVAL",
                    effective_state="NOT_BLOCKED", created_at=now(), updated_at=now())
    db.add(block)
    await db.flush()
    await event(db, block.id, "requested", actor, ip=ip, reason=block.reason, incident_id=incident_id)
    return block


async def approve_block(db, block_id, actor) -> IpBlock:
    block = await _get(db, IpBlock, block_id)
    if block.status != "PENDING_APPROVAL":
        if block.status in ("APPROVED", "DISPATCHED", "SUCCEEDED", "VERIFIED", "TIMEOUT"):
            return block  # approved concurrently / replay: nothing sent twice
        raise HTTPException(409, "Yêu cầu chặn không còn ở trạng thái chờ phê duyệt")
    if not online(block.agent_id):
        raise HTTPException(409, "Agent đang offline: chưa gửi lệnh chặn. Thử lại khi Agent kết nối.")
    stamp = now()
    if not await _cas(db, IpBlock, block.id, "PENDING_APPROVAL", status="DISPATCHED", approved_by=actor,
                      approved_at=stamp, dispatched_at=stamp, effective_state="BLOCKING", updated_at=stamp):
        await db.refresh(block)
        return block
    cmd = _dispatch(db, block.agent_id, BLOCK, {"block_id": block.id, "ip": block.target_ip, "action_id": block.id,
                                                "idempotency_key": block.id, "incident_id": block.incident_id})
    await db.execute(update(IpBlock).where(IpBlock.id == block.id).values(command_id=cmd.id))
    await event(db, block.id, "approved", actor)
    await event(db, block.id, "dispatched", "manager", command_id=cmd.id)
    await db.flush()
    await command_dispatcher.push_command(cmd.id, block.agent_id)
    await db.refresh(block)
    return block


async def reject_block(db, block_id, actor, reason=None) -> IpBlock:
    block = await _get(db, IpBlock, block_id)
    if block.status == "REJECTED":
        return block
    if not await _cas(db, IpBlock, block.id, "PENDING_APPROVAL", status="REJECTED", updated_at=now()):
        raise HTTPException(409, "Yêu cầu chặn không còn ở trạng thái chờ phê duyệt")
    await event(db, block.id, "rejected", actor, reason=reason)
    await db.refresh(block)
    return block


async def request_unblock(db, block_id, reason, actor) -> IpUnblock:
    block = await _get(db, IpBlock, block_id)
    if not reason or len(reason.strip()) < 5:
        raise HTTPException(422, "Cần nhập lý do bỏ chặn (ít nhất 5 ký tự)")
    if block.effective_state not in {"BLOCKED", "PARTIALLY_BLOCKED", "UNKNOWN"}:
        raise HTTPException(409, "Chỉ bỏ chặn khi chặn đang hiệu lực hoặc chưa rõ trạng thái")
    await db.scalar(select(IpBlock.id).where(IpBlock.id == block.id).with_for_update())
    open_unblock = (await db.scalars(select(IpUnblock).where(
        IpUnblock.block_id == block.id, IpUnblock.status.in_(OPEN_UNBLOCK)))).first()
    if open_unblock is not None:
        return open_unblock  # one unblock in flight per block
    unblock = IpUnblock(id=uuid.uuid4().hex, block_id=block.id, agent_id=block.agent_id, target_ip=block.target_ip,
                        reason=reason.strip()[:2000], requested_by=actor, status="PENDING_APPROVAL",
                        access_state="PENDING", created_at=now())
    db.add(unblock)
    await db.flush()
    await event(db, block.id, "unblock_requested", actor, unblock_id=unblock.id, reason=unblock.reason)
    return unblock


async def approve_unblock(db, unblock_id, actor) -> IpUnblock:
    unblock = await _get(db, IpUnblock, unblock_id)
    if unblock.status != "PENDING_APPROVAL":
        if unblock.status in ("DISPATCHED", "SUCCEEDED", "VERIFIED", "TIMEOUT"):
            return unblock
        raise HTTPException(409, "Yêu cầu bỏ chặn không còn ở trạng thái chờ phê duyệt")
    if not online(unblock.agent_id):
        raise HTTPException(409, "Agent đang offline: chưa gửi lệnh bỏ chặn. Trạng thái chặn giữ nguyên theo lần "
                                 "xác minh gần nhất.")
    stamp = now()
    if not await _cas(db, IpUnblock, unblock.id, "PENDING_APPROVAL", status="DISPATCHED", approved_by=actor,
                      approved_at=stamp, dispatched_at=stamp):
        await db.refresh(unblock)
        return unblock
    cmd = _dispatch(db, unblock.agent_id, UNBLOCK, {"block_id": unblock.block_id, "unblock_id": unblock.id,
                                                    "ip": unblock.target_ip, "action_id": unblock.id,
                                                    "idempotency_key": unblock.id, "verify_seconds": 600})
    await db.execute(update(IpUnblock).where(IpUnblock.id == unblock.id).values(command_id=cmd.id))
    await db.execute(update(IpBlock).where(IpBlock.id == unblock.block_id).values(
        effective_state="UNBLOCKING", updated_at=stamp))
    await event(db, unblock.block_id, "unblock_approved", actor, unblock_id=unblock.id)
    await event(db, unblock.block_id, "unblock_dispatched", "manager", unblock_id=unblock.id, command_id=cmd.id)
    await db.flush()
    await command_dispatcher.push_command(cmd.id, unblock.agent_id)
    await db.refresh(unblock)
    return unblock


async def reject_unblock(db, unblock_id, actor) -> IpUnblock:
    unblock = await _get(db, IpUnblock, unblock_id)
    if not await _cas(db, IpUnblock, unblock.id, "PENDING_APPROVAL", status="REJECTED"):
        raise HTTPException(409, "Yêu cầu bỏ chặn không còn ở trạng thái chờ phê duyệt")
    await event(db, unblock.block_id, "unblock_rejected", actor, unblock_id=unblock.id)
    await db.refresh(unblock)
    return unblock


async def request_check(db, agent_id, actor) -> Command:
    """Read-only firewall check on the Agent ("Kiểm tra lại"); never re-sends block or unblock."""
    if not online(agent_id):
        raise HTTPException(409, "Agent đang offline: hiển thị kết quả xác minh gần nhất")
    cmd = _dispatch(db, agent_id, STATUS, {"action_id": f"check_{uuid.uuid4().hex[:12]}", "requested_by": actor})
    await db.flush()
    await command_dispatcher.push_command(cmd.id, agent_id)
    return cmd


async def _get(db, model, row_id):
    row = await db.get(model, row_id)
    if row is None:
        raise HTTPException(404, "Không tìm thấy")
    await db.refresh(row)
    return row


# ── Agent results ───────────────────────────────────────────────────────────────────────────
async def handle_ack(db, agent_id: str, cmd: Command, payload: Dict[str, Any]) -> None:
    receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else {}
    ok = payload.get("status") == "success" and receipt.get("status") == "success"
    stamp = now()
    cmd.status = CommandStatus.SUCCESS if ok else CommandStatus.FAILED
    cmd.executed_at = stamp
    cmd.error_message = (None if ok else str(receipt.get("message") or payload.get("error_message") or "")[:512]) or None
    params = cmd.payload or {}
    if cmd.action == BLOCK:
        block = await db.get(IpBlock, params.get("block_id"))
        if block is None or block.agent_id != agent_id or block.command_id != cmd.id:
            return
        verified = ok and receipt.get("rule_verified") is True and receipt.get("ip") == block.target_ip
        values = {"receipt": receipt, "executed_at": stamp, "updated_at": stamp}
        if verified:
            values.update(status="VERIFIED", effective_state="BLOCKED", verified_at=stamp,
                          firewall_rules=receipt.get("rules"), error=None,
                          last_verification={"source": "execution_receipt", "observed_at": stamp.isoformat(),
                                             "complete": True, "packets": 0})
        else:
            code = receipt.get("code") or "EXECUTION_FAILED"
            refused = code in ("PROTECTED_TARGET", "MANAGEMENT_UNVERIFIED") or receipt.get("rolled_back") is True
            values.update(status="FAILED", effective_state="NOT_BLOCKED" if refused else "UNKNOWN",
                          error=f"{code}: {receipt.get('message') or cmd.error_message or ''}"[:512])
        await db.execute(update(IpBlock).where(IpBlock.id == block.id).values(**values))
        await event(db, block.id, "verified" if verified else "failed", "agent", command_id=cmd.id,
                    outcome=receipt.get("outcome"), code=receipt.get("code"), chains=receipt.get("chains"))
    elif cmd.action == UNBLOCK:
        unblock = await db.get(IpUnblock, params.get("unblock_id"))
        if unblock is None or unblock.agent_id != agent_id or unblock.command_id != cmd.id:
            return
        removed = ok and receipt.get("rule_absent_verified") is True
        others = receipt.get("other_larp_blocks") or []
        values = {"firewall_removal_result": receipt, "executed_at": stamp}
        if removed:
            values.update(status="VERIFIED", verified_at=stamp, error=None,
                          access_state="STILL_BLOCKED" if others else "UNVERIFIED",
                          connectivity_verification={"method": "agent_counter_and_http_logs",
                                                     "window_until": (receipt.get("verification_counter") or {}).get("deadline"),
                                                     "result": "pending" if not others else "blocked_by_other_policy"})
            await db.execute(update(IpBlock).where(IpBlock.id == unblock.block_id).values(
                effective_state="UNBLOCKED", updated_at=stamp,
                last_verification={"source": "unblock_receipt", "observed_at": stamp.isoformat(), "complete": False}))
        else:
            values.update(status="FAILED", error=str(receipt.get("message") or cmd.error_message or "")[:512])
            await db.execute(update(IpBlock).where(IpBlock.id == unblock.block_id).values(
                effective_state="UNKNOWN", updated_at=stamp))
        await db.execute(update(IpUnblock).where(IpUnblock.id == unblock.id).values(**values))
        await event(db, unblock.block_id, "unblock_verified" if removed else "unblock_failed", "agent",
                    unblock_id=unblock.id, command_id=cmd.id, other_larp_blocks=others)
    elif cmd.action == STATUS and ok:
        await reconcile(db, agent_id, receipt, source="status_check")


async def reconcile(db, agent_id: str, state: Dict[str, Any], source: str = "periodic") -> None:
    """Align recorded blocks with what the Agent firewall actually holds."""
    blocks_state = state.get("blocks") if isinstance(state.get("blocks"), dict) else {}
    verifications = state.get("verifications") if isinstance(state.get("verifications"), dict) else {}
    stamp = now()
    observed = stamp.isoformat()
    rows = (await db.scalars(select(IpBlock).where(
        IpBlock.agent_id == agent_id, IpBlock.effective_state.in_(ACTIVE_EFFECT)))).all()
    for block in rows:
        entry = blocks_state.get(block.id)
        previous = block.last_verification or {}
        if entry and entry.get("ip") == block.target_ip:
            new_state = "BLOCKED" if entry.get("complete") else "PARTIALLY_BLOCKED"
            packets = int(entry.get("packets") or 0)
            values = {"effective_state": new_state, "updated_at": stamp,
                      "last_verification": {"source": source, "observed_at": observed, "complete": bool(entry.get("complete")),
                                            "packets": packets, "bytes": int(entry.get("bytes") or 0),
                                            "sessions": int(entry.get("sessions") or 0)}}
            if block.status in ("DISPATCHED", "TIMEOUT"):
                values.update(status="VERIFIED", verified_at=stamp)  # receipt lost, firewall shows it applied
            if packets > int(previous.get("packets") or 0) and block.traffic_verified_at is None:
                values["traffic_verified_at"] = stamp
            await db.execute(update(IpBlock).where(IpBlock.id == block.id).values(**values))
            if new_state != block.effective_state:
                await event(db, block.id, "state_" + new_state.lower(), "agent", source=source)
        elif block.effective_state in ("BLOCKED", "PARTIALLY_BLOCKED", "UNKNOWN", "UNBLOCKING", "BLOCKING"):
            if block.status in ("DISPATCHED",) and utc(block.dispatched_at) > stamp - DISPATCH_TIMEOUT:
                continue  # still being applied
            done = (await db.scalars(select(IpUnblock).where(
                IpUnblock.block_id == block.id, IpUnblock.status.in_(["VERIFIED", "SUCCEEDED"])))).first()
            new_state = "UNBLOCKED" if done else "NOT_BLOCKED"
            await db.execute(update(IpBlock).where(IpBlock.id == block.id).values(
                effective_state=new_state, updated_at=stamp,
                last_verification={"source": source, "observed_at": observed, "complete": False, "rule_absent": True}))
            await event(db, block.id, "state_" + new_state.lower(), "agent", source=source,
                        note=None if done else "Rule không còn trên Agent dù LARP chưa bỏ chặn")
    await _verify_access(db, agent_id, verifications, source)


async def _verify_access(db, agent_id, verifications, source):
    stamp = now()
    pending = (await db.scalars(select(IpUnblock).where(
        IpUnblock.agent_id == agent_id, IpUnblock.status == "VERIFIED", IpUnblock.access_state == "UNVERIFIED"))).all()
    for unblock in pending:
        counter = verifications.get(unblock.id) or {}
        since = utc(unblock.executed_at) or stamp
        http = (await db.scalars(select(WebAccessLog).where(
            WebAccessLog.agent_id == agent_id, WebAccessLog.src_ip == unblock.target_ip,
            WebAccessLog.timestamp >= since).order_by(WebAccessLog.timestamp).limit(1))).first()
        packets = int(counter.get("packets") or 0)
        if packets > 0 or http is not None:
            evidence = {"method": "agent_counter_and_http_logs", "result": "restored", "observed_at": stamp.isoformat(),
                        "packets_from_client": packets, "source": source,
                        "http_request": {"id": http.id, "path": http.path, "status": http.status_code,
                                         "at": utc(http.timestamp).isoformat()} if http else None}
            await db.execute(update(IpUnblock).where(IpUnblock.id == unblock.id).values(
                access_state="RESTORED", connectivity_verification=evidence))
            await event(db, unblock.block_id, "access_restored", "agent", unblock_id=unblock.id,
                        packets=packets, http_request=evidence["http_request"])
        elif counter.get("expired"):
            await db.execute(update(IpUnblock).where(IpUnblock.id == unblock.id).values(connectivity_verification={
                **(unblock.connectivity_verification or {}), "result": "no_client_traffic_in_window",
                "observed_at": stamp.isoformat()}))


async def expire(db, agent_id: Optional[str] = None) -> None:
    """DISPATCHED without a receipt past the timeout → TIMEOUT; the firewall state becomes UNKNOWN."""
    limit = now() - DISPATCH_TIMEOUT
    query = select(IpBlock).where(IpBlock.status == "DISPATCHED", IpBlock.dispatched_at < limit)
    if agent_id:
        query = query.where(IpBlock.agent_id == agent_id)
    for block in (await db.scalars(query)).all():
        if await _cas(db, IpBlock, block.id, "DISPATCHED", status="TIMEOUT", effective_state="UNKNOWN", updated_at=now()):
            await event(db, block.id, "timeout", "manager", note="Chưa nhận receipt; lệnh có thể đã chạy")
    query = select(IpUnblock).where(IpUnblock.status == "DISPATCHED", IpUnblock.dispatched_at < limit)
    if agent_id:
        query = query.where(IpUnblock.agent_id == agent_id)
    for unblock in (await db.scalars(query)).all():
        if await _cas(db, IpUnblock, unblock.id, "DISPATCHED", status="TIMEOUT"):
            await db.execute(update(IpBlock).where(IpBlock.id == unblock.block_id).values(effective_state="UNKNOWN"))
            await event(db, unblock.block_id, "unblock_timeout", "manager", unblock_id=unblock.id,
                        note="Chưa nhận receipt; rule có thể đã được gỡ")


# ── views ───────────────────────────────────────────────────────────────────────────────────
STATUS_LABEL = {
    "PENDING_APPROVAL": "Chờ phê duyệt", "APPROVED": "Đã phê duyệt", "DISPATCHED": "Đang thực thi",
    "TIMEOUT": "Chưa nhận phản hồi", "SUCCEEDED": "Đã thực thi", "VERIFIED": "Đã xác minh", "FAILED": "Thất bại",
    "REJECTED": "Bị từ chối", "VERIFICATION_FAILED": "Xác minh thất bại",
}
EFFECT_LABEL = {
    "NOT_BLOCKED": "Chưa chặn", "BLOCKING": "Đang chặn…", "BLOCKED": "Đã chặn & xác minh",
    "PARTIALLY_BLOCKED": "Chặn một phần", "UNBLOCKING": "Đang bỏ chặn…", "UNBLOCKED": "Đã bỏ chặn & xác minh",
    "UNKNOWN": "Không xác minh được",
}
ACCESS_LABEL = {
    "PENDING": "—", "UNVERIFIED": "Đã gỡ rule — chưa xác minh kết nối",
    "RESTORED": "Đã khôi phục truy cập", "STILL_BLOCKED": "IP vẫn bị chặn bởi một chặn khác",
}


def iso(value):
    return utc(value).isoformat() if value else None


def unblock_view(u: IpUnblock) -> Dict[str, Any]:
    return {"id": u.id, "block_id": u.block_id, "status": u.status, "status_label": STATUS_LABEL.get(u.status, u.status),
            "access_state": u.access_state, "access_label": ACCESS_LABEL.get(u.access_state, u.access_state),
            "reason": u.reason, "requested_by": u.requested_by, "approved_by": u.approved_by,
            "created_at": iso(u.created_at), "approved_at": iso(u.approved_at), "executed_at": iso(u.executed_at),
            "verified_at": iso(u.verified_at), "error": u.error,
            "firewall_removal": {k: (u.firewall_removal_result or {}).get(k) for k in (
                "outcome", "removed_rules", "rule_absent_verified", "other_larp_blocks")} if u.firewall_removal_result else None,
            "connectivity": u.connectivity_verification}


def block_view(b: IpBlock, unblocks: List[IpUnblock], events: List[IpBlockEvent], is_online: bool) -> Dict[str, Any]:
    open_unblock = next((u for u in unblocks if u.status in OPEN_UNBLOCK), None)
    latest = unblocks[0] if unblocks else None
    verification = b.last_verification or {}
    return {
        "id": b.id, "agent_id": b.agent_id, "incident_id": b.incident_id, "target_ip": b.target_ip,
        "reason": b.reason, "backend": b.firewall_backend, "enforcement_layer": "Agent Firewall (nftables)",
        "status": b.status, "status_label": STATUS_LABEL.get(b.status, b.status),
        "effective_state": b.effective_state, "effective_label": EFFECT_LABEL.get(b.effective_state, b.effective_state),
        "requested_by": b.requested_by, "approved_by": b.approved_by, "created_at": iso(b.created_at),
        "approved_at": iso(b.approved_at), "executed_at": iso(b.executed_at), "verified_at": iso(b.verified_at),
        "traffic_verified_at": iso(b.traffic_verified_at), "expires_at": iso(b.expires_at), "error": b.error,
        "agent_online": is_online,
        "verification": {
            "rule_verified": b.effective_state in ("BLOCKED", "PARTIALLY_BLOCKED") or b.status == "VERIFIED",
            "traffic_blocked_packets": verification.get("packets"), "observed_at": verification.get("observed_at"),
            "source": verification.get("source"),
            "management_preserved": bool((b.receipt or {}).get("management_after", {}).get("reachable")),
        },
        "unblock": unblock_view(open_unblock or latest) if (open_unblock or latest) else None,
        "unblocks": [unblock_view(u) for u in unblocks],
        "history": [{"event": e.event, "actor": e.actor, "at": iso(e.at), "unblock_id": e.unblock_id,
                     "detail": e.detail} for e in events],
        "can": {
            "approve": b.status == "PENDING_APPROVAL",
            "unblock": b.effective_state in ("BLOCKED", "PARTIALLY_BLOCKED", "UNKNOWN") and open_unblock is None,
            "approve_unblock": bool(open_unblock and open_unblock.status == "PENDING_APPROVAL"),
            "check": is_online and b.status not in ("PENDING_APPROVAL", "REJECTED"),
        },
    }


async def load_view(db, block: IpBlock) -> Dict[str, Any]:
    unblocks = (await db.scalars(select(IpUnblock).where(IpUnblock.block_id == block.id)
                                 .order_by(IpUnblock.created_at.desc()))).all()
    events = (await db.scalars(select(IpBlockEvent).where(IpBlockEvent.block_id == block.id)
                               .order_by(IpBlockEvent.at))).all()
    return block_view(block, list(unblocks), list(events), online(block.agent_id))


async def suggestions(db, incident: Incident) -> List[Dict[str, Any]]:
    """IPs the Detection Engine attributed to this incident, with the evidence for each (deterministic)."""
    evidence = incident.detection_evidence or {}
    out: Dict[str, Dict[str, Any]] = {}
    chain = evidence.get("chain") or {}
    for ip in chain.get("source_ips") or []:
        out.setdefault(ip, {"ip": ip, "basis": [], "evidence_ids": []})["basis"].append(
            "Nguồn của chuỗi tấn công web (request đã quan sát)")
    for net in chain.get("network") or []:
        ip = str(net.get("dst", "")).rsplit(":", 1)[0]
        if ip:
            item = out.setdefault(ip, {"ip": ip, "basis": [], "evidence_ids": []})
            item["basis"].append(f"Đích kết nối ra ngoài của PID {net.get('pid')} (xác minh qua inode)")
            item["evidence_ids"].append(net.get("flow_id"))
    behavior = evidence.get("behavior") or {}
    if behavior.get("source_ip"):
        item = out.setdefault(behavior["source_ip"], {"ip": behavior["source_ip"], "basis": [], "evidence_ids": []})
        item["basis"].append(f"Nguồn của {behavior.get('classification') or 'hành vi'} trong incident")
        if behavior.get("evidence_id"):
            item["evidence_ids"].append(behavior["evidence_id"])
    agent = await db.get(Agent, incident.agent_id)
    result = []
    for ip, item in out.items():
        try:
            target(ip)
        except HTTPException:
            continue
        protected = manager_protected(ip, agent) if agent else None
        result.append({**item, "evidence_ids": [e for e in item["evidence_ids"] if e],
                       "allowed": protected is None, "protected_reason": protected})
    return result
