"""Incident containment: evidence collection, suspicious-file quarantine/restore, verified process stop.

Every target comes from the incident's own evidence (chain process tree, files those processes ran,
earlier inspections); the API never accepts a free-text path or PID that the evidence does not
contain. Read-only collection runs for operators without approval; anything that changes the host
needs SOC Admin approval. Results come only from Agent receipts and later telemetry: TIMEOUT means
"unknown", never "not executed" or "done". No model output or cache creates or runs an action.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import select, update

from app.models.command import Command
from app.models.containment import ContainmentAction, ContainmentEvent
from app.models.flow import Flow
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.process_instance import ProcessInstance
from app.schemas.enums import CommandStatus
from app.services.core.command_dispatcher import command_dispatcher

logger = logging.getLogger("larp.containment")

TIMEOUT = timedelta(seconds=int(os.getenv("CONTAINMENT_TIMEOUT_SECONDS", "90")))
# kind → (Agent command, capability required, needs approval)
KINDS = {
    "collect_process_evidence": (None, None, False),
    "inspect_file": ("inspect_file", "inspect_file", False),
    "quarantine_file": ("quarantine_file", "quarantine_file", True),
    "restore_file": ("restore_file", "restore_file", True),
    "terminate_process": ("kill_process_tree_verified", "kill_process_tree_verified", True),
}
AGENT_COMMANDS = {cmd for cmd, _, _ in KINDS.values() if cmd}
CAPABILITIES: Dict[str, Dict[str, Any]] = {}  # agent_id → {"items": set, "reported_at": iso}

STATUS_LABEL = {
    "PENDING_APPROVAL": "Chờ phê duyệt", "DISPATCHED": "Đang thực thi", "TIMEOUT": "Không xác minh được (chưa nhận phản hồi)",
    "SUCCEEDED": "Thực thi thành công — đang xác minh", "VERIFIED": "Đã thực hiện và xác minh",
    "VERIFICATION_FAILED": "Thực thi nhưng xác minh thất bại", "FAILED": "Thất bại", "REJECTED": "Bị từ chối",
    "ROLLED_BACK": "Đã hoàn tác",
}
KIND_LABEL = {
    "collect_process_evidence": "Bảo toàn bằng chứng", "inspect_file": "Thu thập bằng chứng file",
    "quarantine_file": "Cách ly file", "restore_file": "Khôi phục file", "terminate_process": "Dừng tiến trình",
}


def now() -> datetime:
    return datetime.now(timezone.utc)


def utc(value):
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def iso(value):
    return utc(value).isoformat() if value else None


def record_capabilities(agent_id: str, items: Any) -> None:
    if isinstance(items, list) and all(isinstance(i, str) for i in items):
        CAPABILITIES[agent_id] = {"items": set(items[:100]), "reported_at": now().isoformat()}


def capable(agent_id: str, kind: str) -> bool:
    _, needed, _ = KINDS[kind]
    return needed is None or needed in (CAPABILITIES.get(agent_id) or {}).get("items", set())


def online(agent_id: str) -> bool:
    from app.websocket.agent_ws import connection_manager
    return agent_id in connection_manager.authenticated_connections


async def event(db, action_id, name, actor, **detail):
    db.add(ContainmentEvent(id=uuid.uuid4().hex, action_id=action_id, event=name, actor=actor,
                            detail=detail or None, at=now()))


# ── evidence-derived targets ───────────────────────────────────────────────────────────────
def chain_of(incident: Incident) -> dict:
    return (incident.detection_evidence or {}).get("chain") or {}


def suspicious_files(incident: Incident) -> List[dict]:
    from app.services.ai.chain_report import suspicious_files as derive
    return derive(chain_of(incident))


def chain_processes(incident: Incident) -> List[dict]:
    chain = chain_of(incident)
    anchor = (chain.get("anchor") or {}).get("id")
    return [p for p in chain.get("process_tree") or [] if p.get("id") != anchor]


async def latest_snapshot(db, agent_id: str, pid: int, start) -> Optional[ProcessInfo]:
    return (await db.scalars(select(ProcessInfo).where(
        ProcessInfo.agent_id == agent_id, ProcessInfo.pid == pid, ProcessInfo.process_start_time == start)
        .order_by(ProcessInfo.created_at.desc()).limit(1))).first()


async def process_state(db, agent_id: str, proc: dict) -> Dict[str, Any]:
    inst = await db.get(ProcessInstance, proc.get("id")) if proc.get("id") else None
    if inst and inst.exited_at:
        return {"state": "EXITED", "label": "Đã thoát", "at": iso(inst.exited_at)}
    snap = await latest_snapshot(db, agent_id, proc.get("pid"), proc.get("process_start_time"))
    if snap is not None:
        return {"state": "RUNNING", "label": "Đang chạy", "at": iso(snap.created_at), "current_ppid": snap.parent_pid}
    return {"state": "UNKNOWN", "label": "Không thấy trong snapshot gần nhất (chưa xác minh đã dừng)",
            "at": iso(inst.last_seen) if inst else None}


async def connection_state(db, agent_id: str, net: dict) -> Dict[str, Any]:
    dst_ip, _, dst_port = str(net.get("dst", "")).rpartition(":")
    rows = (await db.scalars(select(Flow).where(
        Flow.agent_id == agent_id, Flow.dst_ip == dst_ip, Flow.dst_port == int(dst_port or 0),
        Flow.created_at >= now() - timedelta(minutes=2)).order_by(Flow.created_at.desc()).limit(20))).all()
    live = [r for r in rows if any(h.get("pid") == net.get("pid") for h in (r.socket_evidence or {}).get("holders") or [])]
    if live:
        return {"state": "ESTABLISHED", "label": "Đang kết nối", "at": iso(live[0].created_at)}
    return {"state": "NOT_SEEN", "label": "Không còn thấy trong 2 phút gần nhất", "at": None}


# ── requests and approvals ─────────────────────────────────────────────────────────────────
async def request(db, incident: Incident, kind: str, target: Dict[str, Any], reason: str, actor: str,
                  parent: Optional[ContainmentAction] = None) -> ContainmentAction:
    if kind not in KINDS:
        raise HTTPException(422, "Loại hành động không được hỗ trợ")
    if not reason or len(reason.strip()) < 5:
        raise HTTPException(422, "Cần nhập lý do (ít nhất 5 ký tự)")
    if not capable(incident.agent_id, kind):
        raise HTTPException(409, "Agent chưa báo hỗ trợ hành động này (capability chưa có)")
    target = await _validated_target(db, incident, kind, target, parent)
    _, _, approval = KINDS[kind]
    existing = (await db.scalars(select(ContainmentAction).where(
        ContainmentAction.incident_id == incident.id, ContainmentAction.kind == kind,
        ContainmentAction.status.in_(["PENDING_APPROVAL", "DISPATCHED"])))).all()
    for row in existing:
        if row.target.get("key") == target["key"]:
            return row  # same request again: one action in flight per target
    action = ContainmentAction(id=uuid.uuid4().hex, incident_id=incident.id, agent_id=incident.agent_id, kind=kind,
                               target=target, reason=reason.strip()[:2000], requires_approval=approval,
                               status="PENDING_APPROVAL", requested_by=actor,
                               parent_action_id=parent.id if parent else None, created_at=now())
    db.add(action)
    await db.flush()
    await event(db, action.id, "requested", actor, target=target["key"])
    if kind == "collect_process_evidence":
        await _preserve(db, incident, action, actor)
    elif not approval:
        await _dispatch(db, action, actor)
    return action


async def _validated_target(db, incident, kind, target, parent) -> Dict[str, Any]:
    target = dict(target or {})
    if kind in ("inspect_file", "quarantine_file"):
        paths = {f["path"] for f in suspicious_files(incident)}
        path = target.get("path")
        if path not in paths:
            raise HTTPException(422, "File không thuộc bằng chứng của incident này")
        out = {"path": path, "key": f"file:{path}"}
        if kind == "quarantine_file":
            inspection = await latest_inspection(db, incident, path)
            sha = (inspection or {}).get("sha256")
            if not sha or not (inspection or {}).get("exists"):
                raise HTTPException(409, "Cần thu thập bằng chứng file (SHA-256) trước khi đề xuất cách ly")
            out["sha256"] = sha
        return out
    if kind == "restore_file":
        if parent is None or parent.kind != "quarantine_file" or parent.effect != "QUARANTINED":
            raise HTTPException(409, "Chỉ khôi phục file đang được cách ly bởi LARP")
        return {"path": parent.target["path"], "sha256": parent.target["sha256"], "quarantine_id": parent.id,
                "key": f"restore:{parent.id}"}
    if kind == "terminate_process":
        procs = {(p.get("pid"), p.get("process_start_time")): p for p in chain_processes(incident)}
        proc = procs.get((target.get("pid"), target.get("process_start_time")))
        if proc is None:
            raise HTTPException(422, "Tiến trình không thuộc chuỗi bằng chứng của incident (hoặc là web service gốc)")
        snap = await latest_snapshot(db, incident.agent_id, proc["pid"], proc["process_start_time"])
        if snap is None:
            raise HTTPException(409, "Tiến trình không còn trong snapshot gần nhất; không gửi lệnh dừng")
        return {"pid": proc["pid"], "process_start_time": proc["process_start_time"], "exe_path": proc.get("exe"),
                "parent_pid": snap.parent_pid, "cmdline": (proc.get("cmdline") or "")[:300], "process_id": proc.get("id"),
                "key": f"process:{proc['pid']}:{proc['process_start_time']}"}
    if kind == "collect_process_evidence":
        return {"key": "bundle"}
    raise HTTPException(422, "Target không hợp lệ")


async def latest_inspection(db, incident: Incident, path: str) -> Optional[dict]:
    row = (await db.scalars(select(ContainmentAction).where(
        ContainmentAction.incident_id == incident.id, ContainmentAction.kind == "inspect_file",
        ContainmentAction.status == "VERIFIED").order_by(ContainmentAction.executed_at.desc()))).all()
    for action in row:
        if action.target.get("path") == path:
            return action.receipt
    return None


async def approve(db, action_id: str, actor: str) -> ContainmentAction:
    action = await _get(db, action_id)
    if action.status != "PENDING_APPROVAL":
        if action.status in ("DISPATCHED", "SUCCEEDED", "VERIFIED", "TIMEOUT"):
            return action  # approved concurrently / replay: nothing is sent twice
        raise HTTPException(409, "Hành động không còn chờ phê duyệt")
    if not online(action.agent_id):
        raise HTTPException(409, "Agent đang offline: chưa gửi lệnh. Trạng thái giữ nguyên.")
    stamp = now()
    claimed = await db.execute(update(ContainmentAction).where(
        ContainmentAction.id == action.id, ContainmentAction.status == "PENDING_APPROVAL").values(
        approved_by=actor, approved_at=stamp))
    if claimed.rowcount != 1:
        await db.refresh(action)
        return action
    await db.refresh(action)
    await event(db, action.id, "approved", actor)
    await _dispatch(db, action, actor)
    return action


async def reject(db, action_id: str, actor: str) -> ContainmentAction:
    action = await _get(db, action_id)
    result = await db.execute(update(ContainmentAction).where(
        ContainmentAction.id == action.id, ContainmentAction.status == "PENDING_APPROVAL").values(status="REJECTED"))
    if result.rowcount != 1:
        raise HTTPException(409, "Hành động không còn chờ phê duyệt")
    await event(db, action.id, "rejected", actor)
    await db.refresh(action)
    return action


async def _dispatch(db, action: ContainmentAction, actor: str):
    if not online(action.agent_id):
        raise HTTPException(409, "Agent đang offline: chưa gửi lệnh")
    command, _, _ = KINDS[action.kind]
    t = action.target
    payload = {"confirmed": True, "action_id": action.id, "containment_id": action.id, "incident_id": action.incident_id}
    if action.kind == "inspect_file":
        payload["path"] = t["path"]
    elif action.kind == "quarantine_file":
        payload.update(path=t["path"], sha256=t["sha256"], quarantine_id=action.id)
    elif action.kind == "restore_file":
        payload.update(quarantine_id=t["quarantine_id"], sha256=t["sha256"])
    elif action.kind == "terminate_process":
        payload.update(pid=t["pid"], process_start_time=t["process_start_time"], exe_path=t["exe_path"],
                       parent_pid=t["parent_pid"])
    cmd = Command(id=f"cmd_{uuid.uuid4().hex[:16]}", agent_id=action.agent_id, action=command, payload=payload,
                  status=CommandStatus.PENDING, max_retries=0)
    db.add(cmd)
    stamp = now()
    await db.execute(update(ContainmentAction).where(ContainmentAction.id == action.id).values(
        status="DISPATCHED", dispatched_at=stamp, command_id=cmd.id,
        effect={"quarantine_file": "QUARANTINING", "restore_file": "RESTORING", "terminate_process": "STOPPING"}.get(
            action.kind, "COLLECTING")))
    await event(db, action.id, "dispatched", "manager", command_id=cmd.id)
    await db.flush()
    await command_dispatcher.push_command(cmd.id, action.agent_id)
    await db.refresh(action)


async def _preserve(db, incident: Incident, action: ContainmentAction, actor: str):
    """Manager-side evidence bundle: chain, process records, sockets, file inspections — hashed, immutable."""
    procs = []
    for proc in chain_of(incident).get("process_tree") or []:
        inst = await db.get(ProcessInstance, proc.get("id")) if proc.get("id") else None
        procs.append({**proc, "recorded": bool(inst), "sources": inst.sources if inst else None,
                      "exited_at": iso(inst.exited_at) if inst else None})
    inspections = (await db.scalars(select(ContainmentAction).where(
        ContainmentAction.incident_id == incident.id, ContainmentAction.kind == "inspect_file",
        ContainmentAction.status == "VERIFIED"))).all()
    bundle = {
        "incident_id": incident.id, "agent_id": incident.agent_id, "collected_at": now().isoformat(),
        "collected_by": actor, "chain": chain_of(incident), "processes": procs,
        "file_inspections": [a.receipt for a in inspections],
        "detection": {k: (incident.detection_evidence or {}).get(k) for k in ("rule_id", "rule_version", "factors")},
    }
    digest = hashlib.sha256(json.dumps(bundle, sort_keys=True, default=str).encode()).hexdigest()
    stamp = now()
    await db.execute(update(ContainmentAction).where(ContainmentAction.id == action.id).values(
        status="VERIFIED", effect="PRESERVED", receipt={"bundle": bundle, "sha256": digest},
        executed_at=stamp, verified_at=stamp, verification={"bundle_sha256": digest}))
    await event(db, action.id, "preserved", "manager", sha256=digest)
    await db.refresh(action)


async def _get(db, action_id):
    action = await db.get(ContainmentAction, action_id)
    if action is None:
        raise HTTPException(404, "Không tìm thấy hành động")
    await db.refresh(action)
    return action


# ── Agent results ───────────────────────────────────────────────────────────────────────────
async def handle_ack(db, agent_id: str, cmd: Command, payload: Dict[str, Any]) -> None:
    action = await db.get(ContainmentAction, (cmd.payload or {}).get("containment_id"))
    if action is None or action.agent_id != agent_id or action.command_id != cmd.id:
        return
    receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else {}
    stamp = now()
    ok = payload.get("status") == "success"
    cmd.status, cmd.executed_at = (CommandStatus.SUCCESS if ok else CommandStatus.FAILED), stamp
    cmd.error_message = None if ok else str(payload.get("error_message") or receipt.get("message") or "")[:512]
    values: Dict[str, Any] = {"executed_at": stamp, "receipt": receipt or None}
    if action.kind == "terminate_process":
        killed = payload.get("killed_pids") if isinstance(payload.get("killed_pids"), list) else []
        verified = ok and payload.get("validation") == "validated" and action.target["pid"] in killed
        receipt = {"validation": payload.get("validation"), "killed_pids": killed, "message": payload.get("error_message")}
        values["receipt"] = receipt
        if verified:  # the Agent signalled through pidfds and confirmed each process exited
            values.update(status="VERIFIED", effect="TERMINATED", verified_at=stamp,
                          verification={"process_exit_confirmed_by_agent": True, "killed_pids": killed})
        else:
            values.update(status="FAILED", effect="NOT_APPLIED", error=str(payload.get("error_message") or "Không xác minh được")[:512])
    elif action.kind == "inspect_file":
        values.update(status="VERIFIED" if ok else "FAILED", effect="COLLECTED" if ok else "NOT_APPLIED",
                      verified_at=stamp if ok else None, error=None if ok else str(receipt.get("message"))[:512])
    elif action.kind == "quarantine_file":
        verified = ok and receipt.get("original_absent") and receipt.get("stored_hash_verified")
        values.update(status="VERIFIED" if verified else "FAILED" if not ok else "VERIFICATION_FAILED",
                      effect="QUARANTINED" if verified else "NOT_APPLIED" if not ok else "UNKNOWN",
                      verified_at=stamp if verified else None,
                      verification={"original_absent": receipt.get("original_absent"),
                                    "stored_hash_verified": receipt.get("stored_hash_verified"),
                                    "processes_still_running": receipt.get("processes_still_running")} if ok else None,
                      error=None if ok else f"{receipt.get('code')}: {receipt.get('message')}"[:512])
    elif action.kind == "restore_file":
        verified = ok and receipt.get("restored_hash_verified")
        values.update(status="VERIFIED" if verified else "FAILED", effect="RESTORED" if verified else "NOT_APPLIED",
                      verified_at=stamp if verified else None,
                      error=None if verified else f"{receipt.get('code')}: {receipt.get('message')}"[:512])
        if verified and action.parent_action_id:
            await db.execute(update(ContainmentAction).where(ContainmentAction.id == action.parent_action_id).values(
                effect="RESTORED", status="ROLLED_BACK"))
            await event(db, action.parent_action_id, "restored", "agent", restore_action_id=action.id)
    await db.execute(update(ContainmentAction).where(ContainmentAction.id == action.id).values(**values))
    await event(db, action.id, "verified" if values.get("status") == "VERIFIED" else "agent_result", "agent",
                status=values.get("status"), code=(receipt or {}).get("code"))


async def expire(db, incident_id: Optional[str] = None) -> None:
    limit = now() - TIMEOUT
    query = select(ContainmentAction).where(ContainmentAction.status == "DISPATCHED", ContainmentAction.dispatched_at < limit)
    if incident_id:
        query = query.where(ContainmentAction.incident_id == incident_id)
    for action in (await db.scalars(query)).all():
        result = await db.execute(update(ContainmentAction).where(
            ContainmentAction.id == action.id, ContainmentAction.status == "DISPATCHED").values(
            status="TIMEOUT", effect="UNKNOWN"))
        if result.rowcount == 1:
            await event(db, action.id, "timeout", "manager", note="Chưa nhận receipt; lệnh có thể đã chạy")


# ── views ───────────────────────────────────────────────────────────────────────────────────
def action_view(a: ContainmentAction, events: List[ContainmentEvent]) -> Dict[str, Any]:
    return {
        "id": a.id, "command_id": a.command_id, "kind": a.kind, "kind_label": KIND_LABEL.get(a.kind, a.kind), "target": {k: v for k, v in a.target.items() if k != "key"},
        "status": a.status, "status_label": STATUS_LABEL.get(a.status, a.status), "effect": a.effect, "reason": a.reason,
        "requires_approval": a.requires_approval, "requested_by": a.requested_by, "approved_by": a.approved_by,
        "parent_action_id": a.parent_action_id, "error": a.error, "receipt": a.receipt if a.kind != "collect_process_evidence"
        else {"sha256": (a.receipt or {}).get("sha256")}, "verification": a.verification,
        "created_at": iso(a.created_at), "approved_at": iso(a.approved_at), "executed_at": iso(a.executed_at),
        "verified_at": iso(a.verified_at),
        "history": [{"event": e.event, "actor": e.actor, "at": iso(e.at), "detail": e.detail} for e in events],
    }


async def overview(db, incident: Incident) -> Dict[str, Any]:
    from app.services.response import access_control
    await expire(db, incident.id)
    evidence = incident.detection_evidence or {}
    target_incident = incident
    link = evidence.get("correlated_chain")
    chain = chain_of(incident)
    actions = (await db.scalars(select(ContainmentAction).where(ContainmentAction.incident_id == incident.id)
                                .order_by(ContainmentAction.created_at))).all()
    views = []
    for a in actions:
        events = (await db.scalars(select(ContainmentEvent).where(ContainmentEvent.action_id == a.id)
                                   .order_by(ContainmentEvent.at))).all()
        views.append(action_view(a, list(events)))
    processes = []
    for proc in chain_processes(incident):
        processes.append({**{k: proc.get(k) for k in ("id", "pid", "parent_pid", "name", "exe", "cmdline", "euid",
                                                       "process_start_time", "started_at")},
                          "live": await process_state(db, incident.agent_id, proc),
                          "holds_connection": any(n.get("pid") == proc.get("pid") for n in chain.get("network") or [])})
    network = []
    for net in chain.get("network") or []:
        network.append({**{k: net.get(k) for k in ("dst", "src", "pid", "socket_stdio", "direction", "first_seen", "flow_id")},
                        "live": await connection_state(db, incident.agent_id, net)})
    files = []
    for f in suspicious_files(incident):
        inspection = await latest_inspection(db, incident, f["path"])
        quarantine = next((v for v in reversed(views) if v["kind"] == "quarantine_file" and v["target"].get("path") == f["path"]), None)
        state = ("QUARANTINED" if quarantine and quarantine["effect"] == "QUARANTINED" else
                 "RESTORED" if quarantine and quarantine["effect"] == "RESTORED" else
                 "EXECUTION_OBSERVED" if f["executed_by"] else "UPLOADED" if f["uploaded"] else "SUSPICIOUS")
        file_status = (
            "FILE_QUARANTINED" if quarantine and quarantine["effect"] == "QUARANTINED" else
            "FILE_REMOVED" if inspection and inspection.get("exists") is False else
            "FILE_EXECUTION_CORRELATED" if f["executed_by"] and f["uploaded"] else
            "FILE_EXECUTION_OBSERVED" if f["executed_by"] else
            "FILE_UPLOADED" if f["uploaded"] else "FILE_SUSPICIOUS"
        )
        files.append({**f, "inspection": inspection, "state": state, "file_status": file_status,
                      "sha256": f.get("sha256") or (inspection or {}).get("sha256")})
    blocks = [await access_control.load_view(db, b) for b in (await db.scalars(
        select(access_control.IpBlock).where(access_control.IpBlock.incident_id == incident.id))).all()]
    caps = {kind: capable(incident.agent_id, kind) for kind in KINDS}
    caps["block_ip"] = "block_ip" in (CAPABILITIES.get(incident.agent_id) or {}).get("items", set())
    return {
        "incident_id": incident.id, "agent_id": incident.agent_id, "severity": str(getattr(incident.severity, "value", incident.severity)),
        "risk_score": incident.risk_score, "title": incident.title, "is_chain": bool(chain),
        "correlated_chain": link if target_incident is incident else None,
        "stages": [{k: c.get(k) for k in ("id", "label", "status", "detail", "evidence_ids", "observed_at", "contribution")}
                   for c in chain.get("conditions") or []],
        "inferred_requests": chain.get("inferred_requests") or [],
        "processes": processes, "network": network, "files": files, "actions": views, "ip_blocks": blocks,
        "capabilities": caps, "capabilities_reported_at": (CAPABILITIES.get(incident.agent_id) or {}).get("reported_at"),
        "agent_online": online(incident.agent_id),
    }
