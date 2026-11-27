"""AI Threat Memory management and per-incident analysis source.

Reads need an authenticated operator (incident reads also need the incident's Agent scope).
Revoking an entry: operator/admin. Marking an entry SOC-verified: admin only.
"""
import asyncio
import json
import logging
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.deps import get_db
from app.core.network_security import authenticate_operator_request
from app.models.ai_analysis import AIAnalysis
from app.models.ai_cache import ThreatMemory
from app.models.incident import Incident
from app.services.ai import threat_memory as tm

logger = logging.getLogger("larp.ai.threat_memory.api")
router = APIRouter(prefix="/ai", tags=["AI Threat Memory"])


class ReasonBody(BaseModel):
    reason: Optional[str] = Field(None, max_length=255)


class RunBody(BaseModel):
    mode: Literal["reuse", "fresh"] = "reuse"


async def _auth(db, authorization, agent_id=None, roles=None):
    identity, _ = await authenticate_operator_request(authorization, db, agent_id=agent_id, write=roles is not None,
                                                      allowed_write_roles=roles)
    return identity


async def _incident(db, incident_id, authorization, roles=None):
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Không tìm thấy incident")
    actor = await _auth(db, authorization, incident.agent_id, roles)
    return incident, actor


async def _latest(db, incident_id) -> Optional[AIAnalysis]:
    return await db.scalar(select(AIAnalysis).where(AIAnalysis.incident_id == incident_id,
                                                    AIAnalysis.analysis_type == "triage")
                           .order_by(AIAnalysis.created_at.desc()).limit(1))


def _source(analysis: Optional[AIAnalysis]) -> dict:
    try:
        raw = json.loads(analysis.raw_response or "{}") if analysis else {}
    except ValueError:
        raw = {}
    return raw if isinstance(raw, dict) else {}


@router.get("/threat-memory")
async def list_memory(status: Optional[str] = None, limit: int = 100, authorization: Optional[str] = Header(None),
                      db=Depends(get_db)):
    await _auth(db, authorization)
    query = select(ThreatMemory).order_by(ThreatMemory.updated_at.desc()).limit(max(1, min(limit, 500)))
    if status:
        query = query.where(ThreatMemory.validation_status == status)
    return {"items": [tm.entry_view(r) for r in (await db.scalars(query)).all()]}


@router.get("/threat-memory/metrics")
async def memory_metrics(days: int = 7, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    await _auth(db, authorization)
    return await tm.metrics(db, max(1, min(days, 90)))


@router.post("/threat-memory/{memory_id}/{operation}")
async def change_memory(memory_id: str, operation: Literal["verify", "revoke"], body: ReasonBody,
                        authorization: Optional[str] = Header(None), db=Depends(get_db)):
    actor = await _auth(db, authorization, roles={"admin"} if operation == "verify" else {"admin", "operator"})
    try:
        row = await tm.set_status(db, memory_id, "soc_verified" if operation == "verify" else "revoked", actor,
                                  body.reason or ("SOC xác nhận" if operation == "verify" else "SOC thu hồi"))
    except KeyError as exc:
        raise HTTPException(404, "Không tìm thấy mẫu") from exc
    await db.commit()
    return tm.entry_view(row)


@router.get("/incidents/{incident_id}/analysis-source")
async def analysis_source(incident_id: str, authorization: Optional[str] = Header(None), db=Depends(get_db)):
    incident, _ = await _incident(db, incident_id, authorization)
    analysis = await _latest(db, incident_id)
    raw = _source(analysis)
    similar = []
    for item in raw.get("similar_cases") or []:
        row = await db.get(ThreatMemory, item.get("id")) if item.get("id") else None
        case = {k: item.get(k) for k in ("id", "attack_pattern", "platform", "validation_status", "similarity",
                                         "mitre_techniques", "updated_at")}
        source_incident = await db.get(Incident, row.source_incident_id) if row and row.source_incident_id else None
        if source_incident is not None:
            try:  # reveal the originating incident only within the caller's Agent scope
                await authenticate_operator_request(authorization, db, agent_id=source_incident.agent_id, write=False)
                case["source_incident_id"] = source_incident.id
            except HTTPException:
                pass
        similar.append(case)
    memory = raw.get("memory")
    if memory and memory.get("id"):
        row = await db.get(ThreatMemory, memory["id"])
        if row is not None:
            memory = {**memory, "validation_status": row.validation_status, "updated_at": tm.iso(row.updated_at),
                      "usage_count": row.usage_count}
    return {
        "incident_id": incident.id, "analysis_id": analysis.id if analysis else None,
        "analysis_source": raw.get("analysis_source") or ("RULE_BASED_FALLBACK" if analysis else None),
        "model_called": bool(raw.get("model_called")), "model_name": analysis.model_name if analysis and raw.get("model_called") else None,
        "memory": memory, "learned_memory_id": raw.get("learned_memory_id"), "similar_cases": similar,
        "cache_reason": raw.get("cache_reason"), "latency_ms": raw.get("latency_ms") or {},
        "evidence_completeness": raw.get("evidence_completeness"), "status": raw.get("status"),
        "analyst_rating": analysis.analyst_rating if analysis else None,
        "created_at": tm.iso(analysis.created_at) if analysis else None,
    }


@router.post("/incidents/{incident_id}/analysis/run", status_code=202)
async def run_analysis(incident_id: str, body: RunBody, background: BackgroundTasks,
                       authorization: Optional[str] = Header(None), db=Depends(get_db)):
    """mode=reuse: normal analysis (Threat Memory allowed). mode=fresh: bypass analysis caches, still validated."""
    await _incident(db, incident_id, authorization)

    async def run():
        from app.services.ai.ai_triage_service import AITriageService
        try:
            await AITriageService().analyze_incident(incident_id, manual=body.mode == "fresh",
                                                     use_memory=body.mode == "reuse")
        except Exception:  # noqa: BLE001
            logger.exception("Analysis run failed incident=%s", incident_id)
    background.add_task(run)
    return {"status": "analyzing", "mode": body.mode}


@router.post("/incidents/{incident_id}/analysis/incorrect")
async def mark_incorrect(incident_id: str, body: ReasonBody, authorization: Optional[str] = Header(None),
                         db=Depends(get_db)):
    """SOC marks the latest analysis wrong; the memory entry it came from (or created) stops being reused."""
    _, actor = await _incident(db, incident_id, authorization, roles={"admin", "operator"})
    analysis = await _latest(db, incident_id)
    if analysis is None:
        raise HTTPException(404, "Chưa có phân tích cho incident này")
    raw = _source(analysis)
    analysis.analyst_rating = "wrong"
    affected = [m for m in ((raw.get("memory") or {}).get("id"), raw.get("learned_memory_id")) if m]
    for memory_id in affected:
        try:
            await tm.set_status(db, memory_id, "incorrect", actor, body.reason or "SOC đánh dấu phân tích không chính xác")
        except KeyError:
            continue
    await db.commit()
    return {"analysis_id": analysis.id, "rating": "wrong", "memory_invalidated": affected}
