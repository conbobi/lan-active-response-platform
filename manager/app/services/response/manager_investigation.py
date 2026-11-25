"""Manager-local, bounded read-only monitoring and remediation notes."""
from datetime import datetime, timezone

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
    action.snapshot = {"verification": {"timestamp": stamp.isoformat(), "status": action.status,
                       "method": "persisted_incident_note", "evidence_refs": [persisted] if persisted else []}}
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
    result = {"timestamp": stamp.isoformat(), "status": state, "method": "time_bounded_http_query", "evidence_refs": refs}
    if state != action.status or refs != snap.get("verification", {}).get("evidence_refs", []):
        await ActionAuditLogService(db).record_event(action.id, state, stop_actor or "manager", metadata=result)
    action.snapshot = {**snap, "verification": result}
    action.status = state
