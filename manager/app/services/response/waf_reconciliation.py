"""Reconcile an approved lab lease with its application-side receipt."""
import asyncio
import sqlite3

from fastapi import HTTPException
from sqlalchemy import update

from app.models.response_action import ResponseAction
from app.services.agent.network_service import now
from app.services.common.audit_log_service import ActionAuditLogService
from app.services.response import lab_waf
from app.services.response.http_investigation import WAF_TYPES, REVOKE


async def reconcile(db, row, *, undo_actor=None):
    if row.action_type not in WAF_TYPES or row.status not in {"dispatched", "verifying", "succeeded", "rollback_failed", "partial"}:
        return
    # Serialize both readers reconciling and explicit rollback, including on SQLite.
    owned = await db.execute(update(ResponseAction).where(
        ResponseAction.id == row.id, ResponseAction.status == row.status
    ).values(status=row.status))
    if not owned.rowcount:
        await db.refresh(row)
        return
    before = row.status
    snap = dict(row.snapshot)
    target = row.action_params["target_resource"]
    peer = target.get("source_ip")
    stamp = now()
    refs = []
    method = "application_lease_and_http_receipt"
    audit = ActionAuditLogService(db)
    try:
        if row.action_type == REVOKE:
            if before == "dispatched":
                await asyncio.to_thread(lab_waf.revoke, row.agent_id, target["session_ref"], row.id)
                await audit.record_event(row.id, "executed", "lab_waf")
            receipt = await asyncio.to_thread(lab_waf.revocation_receipt, row.agent_id, target["session_ref"], row.id)
            refs = list(receipt or [])
            status = "succeeded" if refs else ("partial" if stamp.timestamp() >= snap["deadline"] else "verifying")
            method = "targeted_session_rejection"
        elif undo_actor:
            await asyncio.to_thread(lab_waf.rollback, row.agent_id, peer, row.id)
            status, method = "rolled_back", "owned_lease_absence"
        elif before == "dispatched" and stamp.timestamp() >= snap["deadline"]:
            status = "expired"
        else:
            if before == "dispatched":
                await asyncio.to_thread(lab_waf.activate, row.agent_id, peer, row.id, snap["deadline"], row.action_type)
                await audit.record_event(row.id, "executed", "lab_waf")
            status, refs = await asyncio.to_thread(lab_waf.verify, row.agent_id, peer, row.id,
                                                    snap["start"], snap["deadline"], row.action_type)
    except (HTTPException, sqlite3.Error, OSError):
        status = "rollback_failed" if undo_actor else ("partial" if before != "dispatched" else "failed")
    if before == "rollback_failed" and not undo_actor and status != "expired":
        return
    if before != status or undo_actor:
        verification = {"timestamp": stamp.isoformat(), "status": status, "method": method,
                        "evidence_refs": refs, "elapsed_ms": round((stamp.timestamp() - snap["start"]) * 1000)}
        row.status = status
        row.snapshot = {**snap, "verification": verification}
        await audit.record_event(row.id, status, undo_actor or "lab_waf", metadata=verification)
