"""Manager-local, bounded read-only monitoring and remediation notes."""
from datetime import datetime, timezone
import uuid

from sqlalchemy import select, update
from app.models.incident_note import IncidentNote
from app.models.response_action import ResponseAction
from app.models.web_access_log import WebAccessLog
from app.services.common.audit_log_service import ActionAuditLogService
from app.services.response.http_investigation import WATCH


async def record_guidance(db, action, actor):
    note = IncidentNote(id=action.id, incident_id=action.incident_id, user=actor, content=(
        "Review the affected application query and use parameterized statements. "
        "Check application-side authentication outcomes around the observed request. "
        "Evidence: " + ", ".join(action.action_params["evidence_ids"])))
    db.add(note)
    await db.flush()
    persisted = await db.scalar(select(IncidentNote.id).where(IncidentNote.id == note.id,
        IncidentNote.incident_id == action.incident_id, IncidentNote.content == note.content))
    stamp = datetime.now(timezone.utc)
    action.status = "succeeded" if persisted else "failed"
    verification = {
        "verification_id": (action.snapshot or {}).get("verification", {}).get("verification_id") or uuid.uuid4().hex,
        "action_id": action.id,
        "verification_method": "persisted_incident_note",
        "method": "persisted_incident_note",
        "observed_at": stamp.isoformat(),
        "timestamp": stamp.isoformat(),
        "expected_result": "Remediation note attached to incident in database",
        "actual_result": f"Note persisted with ID {persisted}" if persisted else "Failed to persist note",
        "evidence_refs": [persisted] if persisted else [],
        "verification_status": action.status,
        "status": action.status,
        "failure_reason": None if persisted else "Database persistence failure"
    }
    action.snapshot = {"verification": verification}
    await ActionAuditLogService(db).record_event(action.id, action.status, "manager", metadata=action.snapshot)


async def reconcile_watch(db, action, stop_actor=None):
    if action.action_type != WATCH or action.status not in {"dispatched", "monitoring"}:
        return
    claim = await db.execute(update(ResponseAction).where(ResponseAction.id == action.id,
        ResponseAction.status == action.status).values(status=action.status))
    if not claim.rowcount:
        await db.refresh(action)
        return
    stamp = datetime.now(timezone.utc)
    snap = action.snapshot
    start = datetime.fromtimestamp(snap["start"], timezone.utc)
    end = datetime.fromtimestamp(snap["deadline"], timezone.utc)
    refs = list(await db.scalars(select(WebAccessLog.id).where(WebAccessLog.agent_id == action.agent_id,
        WebAccessLog.src_ip == action.action_params["target_resource"]["source_ip"],
        WebAccessLog.timestamp.between(start, min(stamp, end))).order_by(WebAccessLog.timestamp.desc()).limit(25)))
    state = "rolled_back" if stop_actor else ("expired" if stamp >= end else "monitoring")
    result = {
        "verification_id": (snap.get("verification") or {}).get("verification_id") or uuid.uuid4().hex,
        "action_id": action.id,
        "verification_method": "time_bounded_http_query",
        "method": "time_bounded_http_query",
        "observed_at": stamp.isoformat(),
        "timestamp": stamp.isoformat(),
        "expected_result": "Bounded database query for matching HTTP access logs",
        "actual_result": f"Found {len(refs)} matching log entries within window",
        "evidence_refs": refs,
        "verification_status": state,
        "status": state,
        "failure_reason": None
    }
    if state != action.status or refs != snap.get("verification", {}).get("evidence_refs", []):
        await ActionAuditLogService(db).record_event(action.id, state, stop_actor or "manager", metadata=result)
    action.snapshot = {**snap, "verification": result}
    action.status = state
