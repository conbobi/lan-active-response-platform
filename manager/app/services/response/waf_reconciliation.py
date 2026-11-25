"""Reconcile an approved lab lease with its application-side receipt."""
import asyncio
import sqlite3
import uuid

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
        failure_reason = None if status in {"succeeded", "rolled_back", "verifying"} else ("Application lease expired before receipt" if status == "expired" else "Verification failed")
        expected_map = {
            "temporary_ip_block": "HTTP 403 response on POST /login from direct peer",
            "apply_rate_limit": "HTTP 429 rate limit response on POST /login exceeding 3 requests in 10s",
            "revoke_session": "HTTP 401 response on targeted session cookie via response_guard",
        }
        actual_map = {
            "succeeded": f"Observed HTTP rejection receipt: {', '.join(refs)}",
            "verifying": "Active lease registered; awaiting direct peer verification receipt",
            "expired": "Lease expired without HTTP rejection receipt",
            "rolled_back": "Owned application lease removed and verified absent",
            "rollback_failed": "Could not remove lease from durable store",
            "failed": "Verification failed due to store error",
            "partial": "Partial receipt observed before deadline",
        }
        verification = {
            "verification_id": (snap.get("verification") or {}).get("verification_id") or uuid.uuid4().hex,
            "action_id": row.id,
            "verification_method": method,
            "method": method,
            "observed_at": stamp.isoformat(),
            "timestamp": stamp.isoformat(),
            "expected_result": "Removal of application lease" if undo_actor else expected_map.get(row.action_type, "HTTP response enforcement"),
            "actual_result": actual_map.get(status, status),
            "evidence_refs": refs,
            "verification_status": status,
            "status": status,
            "failure_reason": failure_reason,
            "elapsed_ms": round((stamp.timestamp() - snap["start"]) * 1000)
        }
        row.status = status
        row.snapshot = {**snap, "verification": verification}
        await audit.record_event(row.id, status, undo_actor or "lab_waf", metadata=verification)
