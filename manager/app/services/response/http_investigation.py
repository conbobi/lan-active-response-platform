"""Project incident-scoped, stored HTTP observations into bounded response proposals."""
import asyncio
import re
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.core.agent_health import as_utc
from app.models.auth_event import AuthEvent
from app.models.event import Event
from app.services.response import lab_waf
from app.services.detection.behavior_evidence import stable_id
from app.models.web_access_log import WebAccessLog
from app.services.detection.behavior_evidence import SQLI_TOOL_UA, TOOL_UA, valid_indicators


COLLECT = "collect_additional_evidence"
BLOCK = "temporary_ip_block"
RATE = "apply_rate_limit"
REVOKE = "revoke_session"
GUIDE = "generate_remediation_guidance"
WATCH = "increase_monitoring"
TRAFFIC = (BLOCK, RATE)
WAF_TYPES = (*TRAFFIC, REVOKE)
ASSIST_TYPES = (COLLECT, GUIDE, WATCH, *WAF_TYPES)
VERSION = "http-1"


class CollectionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: str
    incident_id: str
    action_type: Literal["collect_additional_evidence"] = COLLECT
    target_agent_id: str
    target_resource: dict[str, str]
    evidence_ids: list[str]
    evidence_snapshot_hash: str = ""
    evidence_observed_at: str = ""
    proposal_created_at: str = ""
    evidence_completeness: str = "partial"
    ai_confidence: float = 0.5
    approval_requirement: str = "operator_approval"
    rationale: str
    expected_effect: str = "Collect related records and a fresh Agent network snapshot."
    potential_impact: str = "One bounded collection on the endpoint."
    prerequisites: tuple[str, ...] = ("Scoped operator", "Enrolled Linux Agent")
    required_capabilities: tuple[str, ...] = ("network_refresh",)
    rollback_strategy: str = "Read-only collection"
    proposed_ttl_seconds: None = None
    requires_approval: Literal[True] = True
    policy_version: Literal["http-1"] = VERSION


class BlockProposal(CollectionProposal):
    action_type: Literal["temporary_ip_block"] = BLOCK
    expected_effect: str = "Reject POST /login from the observed disposable peer for five minutes."
    potential_impact: str = "All login requests from that peer receive HTTP 403 during the lease."
    prerequisites: tuple[str, ...] = ("Fresh direct-peer receipt", "Disposable peer configured by administrator")
    required_capabilities: tuple[str, ...] = ("flask_lab_guard",)
    rollback_strategy: str = "Remove the owned application lease or allow it to expire."
    proposed_ttl_seconds: Literal[300] = 300


class RateProposal(BlockProposal):
    action_type: Literal["apply_rate_limit"] = RATE
    expected_effect: str = "Limit the disposable peer to three POST /login requests per ten-second window."
    potential_impact: str = "Additional login requests from that peer receive HTTP 429 during the lease."


class RevokeProposal(CollectionProposal):
    action_type: Literal["revoke_session"] = REVOKE
    expected_effect: str = "Reject the targeted Flask session when its signed cookie is next presented."
    potential_impact: str = "The affected session must authenticate again."
    prerequisites: tuple[str, ...] = ("Correlated credential mismatch grant", "Flask session guard")
    required_capabilities: tuple[str, ...] = ("session_denylist",)
    rollback_strategy: str = "Irreversible for this cookie; the user may authenticate again."


class GuideProposal(CollectionProposal):
    action_type: Literal["generate_remediation_guidance"] = GUIDE
    expected_effect: str = "Attach an evidence-linked remediation note to the incident."
    potential_impact: str = "Adds one analyst-visible note."
    requires_approval: Literal[False] = False
    approval_requirement: str = "automatic"
    prerequisites: tuple[str, ...] = ("Incident HTTP evidence",)
    required_capabilities: tuple[str, ...] = ("incident_notes",)


class WatchProposal(CollectionProposal):
    action_type: Literal["increase_monitoring"] = WATCH
    expected_effect: str = "Review matching Manager HTTP records every 10 seconds for five minutes."
    potential_impact: str = "Additional bounded database reads for the observed source."
    prerequisites: tuple[str, ...] = ("Stored source observation",)
    required_capabilities: tuple[str, ...] = ("web_access_logs",)
    proposed_ttl_seconds: Literal[300] = 300
    rollback_strategy: str = "Stop the Manager watch."


def match_proposal(investigation, key):
    for item in (investigation or {}).get("recommended_responses", []):
        if item["action_id"] == key:
            schema = {BLOCK: BlockProposal, RATE: RateProposal, COLLECT: CollectionProposal, GUIDE: GuideProposal, WATCH: WatchProposal, REVOKE: RevokeProposal}[item["action_type"]]
            return schema.model_validate(item)
    return None


def http_behavior(incident):
    evidence = incident.detection_evidence
    behavior = evidence.get("behavior") if isinstance(evidence, dict) else None
    if isinstance(behavior, dict) and (behavior.get("evidence_type") == "http" or
            (behavior.get("source") == "auth_events" and behavior.get("service") == "flask_web")):
        return behavior
    return {}


async def investigate(db, incident):
    behavior = http_behavior(incident)
    ids = behavior.get("source_event_ids")
    group = behavior.get("evidence_id")
    auth_source = behavior.get("source") == "auth_events"
    if (behavior.get("source") not in {"auth_events", "web_access_logs"} or behavior.get("agent_id") != incident.agent_id
            or not isinstance(group, str) or not 0 < len(group) <= 64
            or not isinstance(ids, list) or not 0 < len(ids) <= 64
            or not all(isinstance(i, str) and 0 < len(i) <= 64 for i in ids)):
        return None, None
    auth_refs = []
    if auth_source:
        # Bind the detector's cohort to persisted failures and one particular Flask request.
        rid = behavior.get("request_id")
        peer = behavior.get("source_ip")
        if (not isinstance(rid, str) or not rid or behavior.get("request_method") != "POST"
                or behavior.get("request_path") != "/login"
                or behavior.get("http_event_id") != stable_id("wlog_", incident.agent_id, rid)):
            return None, None
        auth_refs = list((await db.scalars(select(AuthEvent.id).where(
            AuthEvent.id.in_(ids), AuthEvent.agent_id == incident.agent_id, AuthEvent.service == "flask_web",
            AuthEvent.source_ip == peer, AuthEvent.status == "failed", AuthEvent.count == 1
        ).order_by(AuthEvent.id))).all())
        if len(auth_refs) != len(set(ids)) or stable_id("auth_", incident.agent_id, "flask_web", rid) not in auth_refs:
            return None, None
        ids = [behavior["http_event_id"]]
    rows = (await db.scalars(select(WebAccessLog).where(
        WebAccessLog.agent_id == incident.agent_id, WebAccessLog.id.in_(ids),
    ).order_by(WebAccessLog.timestamp, WebAccessLog.id))).all()
    if len(rows) != len(set(ids)):
        return None, None
    facts = []
    candidates = []
    grants = []
    for row in rows:
        try:
            meta = json.loads(row.raw_message or "{}")
        except (ValueError, TypeError):
            meta = {}
        indicators = sorted(valid_indicators(meta.get("payload_indicators"))) if isinstance(meta, dict) else []
        if auth_source and (row.src_ip != peer or row.method != "POST" or row.path != "/login"
                            or not isinstance(meta, dict) or meta.get("request_id") != rid):
            return None, None
        burst = len(auth_refs) >= 5 and behavior.get("classification") == "authentication_brute_force"
        if (burst or indicators) and isinstance(meta, dict) and meta.get("source") == "normalized_http" and meta.get("service") == "flask_web" and row.path == "/login" and row.method == "POST":
            if meta.get("request_id") and row.id == stable_id("wlog_", incident.agent_id, meta["request_id"]):
                candidates.append((row, meta["request_id"]))
            session_ref = meta.get("session_ref")
            request_id = meta.get("request_id")
            if (row.status_code == 302 and isinstance(session_ref, str) and re.fullmatch(r"[a-f0-9]{64}", session_ref)
                    and isinstance(request_id, str) and row.id == stable_id("wlog_", incident.agent_id, request_id)):
                grants.append((row, request_id, session_ref))
        ua = row.user_agent or ""
        tool = SQLI_TOOL_UA.search(ua) or TOOL_UA.search(ua)
        facts.append({
            "evidence_ids": [row.id], "provenance": "web_access_logs", "observed_at": as_utc(row.timestamp).isoformat(),
            "method": row.method, "http_status": row.status_code, "source_ip": row.src_ip,
            "automation_hint": tool[1].lower() if tool else None, "payload_indicators": indicators,
        })
    if any(f["payload_indicators"] for f in facts):
        cls, confidence = "sqli_probe_observed", 0.85
    elif auth_refs:
        cls, confidence = "observed_login_failures", 0.85
    elif any(SQLI_TOOL_UA.fullmatch(f["automation_hint"] or "") for f in facts):
        cls, confidence = "sqli_tool_indicator", 0.60
    elif any(f["automation_hint"] for f in facts):
        cls, confidence = "automated_http_activity", 0.50
    else:
        return None, None
    refs = [group, *auth_refs, *(row.id for row in rows)]
    compromised = None
    if grants:
        auth_ids = {stable_id("auth_", incident.agent_id, "flask_web", rid): (row, rid, ref) for row, rid, ref in grants}
        result = await db.execute(select(AuthEvent, Event).join(Event, Event.id == AuthEvent.id).where(
            AuthEvent.id.in_(auth_ids), AuthEvent.agent_id == incident.agent_id, AuthEvent.service == "flask_web",
            AuthEvent.status == "success", AuthEvent.count == 1, Event.agent_id == incident.agent_id,
            Event.source == "AGENT_AUTH", Event.event_type == "AUTH_OBSERVATION"))
        for auth, event in result:
            row, rid, ref = auth_ids[auth.id]
            detail = event.details or {}
            if (detail.get("request_id") != rid or detail.get("session_ref") != ref or auth.source_ip != row.src_ip
                    or detail.get("timestamp_source") not in {"application", "log"}
                    or detail.get("request_method") != "POST" or detail.get("request_path") != "/login"
                    or abs((as_utc(auth.timestamp) - as_utc(row.timestamp)).total_seconds()) > 5):
                continue
            confirmed = await asyncio.to_thread(lab_waf.credential_mismatch, incident.agent_id, row.src_ip, rid, ref,
                                                as_utc(row.timestamp).timestamp())
            refs.append(auth.id)
            facts.append({"evidence_ids": [row.id, auth.id], "provenance": "auth_events + web_access_logs",
                          "observed_at": as_utc(auth.timestamp).isoformat(), "source_ip": row.src_ip,
                          "outcome": "session_granted"})
            if confirmed:
                cls, confidence = "sqli_exploitation_confirmed", 0.95
                compromised = (rid, ref, row.src_ip, as_utc(row.timestamp).timestamp())
                refs.append(rid)
                facts.append({"evidence_ids": [rid, auth.id, row.id], "provenance": "lab grant_observation",
                              "observed_at": as_utc(row.timestamp).isoformat(), "source_ip": row.src_ip,
                              "outcome": "credential_mismatch_grant"})
            elif cls != "sqli_exploitation_confirmed":
                cls, confidence = "sqli_exploitation_suspected", 0.85
    fingerprint = json.dumps([VERSION, incident.id, incident.agent_id, refs, facts], sort_keys=True)
    action_id = hashlib.sha256(fingerprint.encode()).hexdigest()
    rationale = {
        "observed_login_failures": f"Application authentication records contain {len(auth_refs)} failed login attempts.",
        "sqli_exploitation_confirmed": "The application granted a session despite an independently verified credential mismatch on the correlated request.",
        "sqli_exploitation_suspected": "A request with SQL indicators correlates to an application session grant.",
        "sqli_probe_observed": "A stored HTTP observation contains a recognized SQL payload indicator.",
        "sqli_tool_indicator": "The HTTP client identified itself as a SQL testing tool.",
        "automated_http_activity": "The HTTP client identified itself as an automated client.",
    }[cls]
    snap_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
    obs_at = facts[-1]["observed_at"] if facts else ""
    created_at = as_utc(rows[-1].timestamp).isoformat() if rows else ""
    comp = "complete_for_session_grant" if cls == "sqli_exploitation_confirmed" else "partial"
    common_meta = {
        "evidence_snapshot_hash": snap_hash,
        "evidence_observed_at": obs_at,
        "proposal_created_at": created_at,
        "evidence_completeness": comp,
        "ai_confidence": confidence,
    }
    proposal = CollectionProposal(action_id=action_id, incident_id=incident.id, target_agent_id=incident.agent_id,
                                  target_resource={"evidence_group": group}, evidence_ids=refs, rationale=rationale, **common_meta)
    proposals = [proposal]
    for schema, kind in [(GuideProposal, GUIDE), (WatchProposal, WATCH)]:
        proposals.append(schema(action_id=hashlib.sha256((action_id + kind).encode()).hexdigest(),
                                incident_id=incident.id, target_agent_id=incident.agent_id,
                                target_resource={"evidence_group": group, "source_ip": rows[-1].src_ip},
                                evidence_ids=refs, rationale=rationale, **common_meta))
    if candidates:
        row, request_id = candidates[-1]
        if await asyncio.to_thread(lab_waf.direct_observation, incident.agent_id, row.src_ip,
                                   request_id, as_utc(row.timestamp).timestamp()):
            target = {"source_ip": row.src_ip, "endpoint": "/login", "method": "POST", "request_id": request_id}
            proposals.append(RateProposal(
                action_id=hashlib.sha256((action_id + RATE).encode()).hexdigest(), incident_id=incident.id,
                target_agent_id=incident.agent_id, target_resource=target,
                evidence_ids=list(dict.fromkeys([*refs, request_id])), rationale=rationale, **common_meta
            ))
            proposals.append(BlockProposal(
                action_id=hashlib.sha256((action_id + BLOCK).encode()).hexdigest(), incident_id=incident.id,
                target_agent_id=incident.agent_id, target_resource=target, evidence_ids=list(dict.fromkeys([*refs, request_id])), rationale=rationale, **common_meta
            ))
    if compromised:
        rid, ref, peer, stamp = compromised
        if await asyncio.to_thread(lab_waf.direct_observation, incident.agent_id, peer, rid, stamp):
            proposals.append(RevokeProposal(
                action_id=hashlib.sha256((action_id + REVOKE + ref).encode()).hexdigest(), incident_id=incident.id,
                target_agent_id=incident.agent_id, target_resource={"session_ref": ref, "request_id": rid},
                evidence_ids=refs, rationale=rationale, **common_meta))
    from app.models.response_action import ResponseAction
    history = (await db.execute(select(ResponseAction.action_type, ResponseAction.outcome).where(
        ResponseAction.agent_id == incident.agent_id, ResponseAction.action_type.in_(ASSIST_TYPES),
        ResponseAction.outcome.is_not(None)).order_by(ResponseAction.updated_at.desc()).limit(5))).all()
    return {
        "asset_criticality": None,
        "recent_outcomes": [{"action_type": kind, "outcome": outcome} for kind, outcome in history
                            if outcome in {"effective", "ineffective", "caused_side_effect", "rolled_back_by_analyst"}],
        "classification": cls, "observed_facts": facts, "behavioral_interpretation": rationale,
        "attack_hypotheses": ["Possible application probing"], "evidence_completeness": "complete_for_session_grant" if cls == "sqli_exploitation_confirmed" else "partial",
        "confidence": confidence, "confidence_source": "detection rule", "risk_score": incident.risk_score,
        "potential_impact": "Unauthorized session granted." if cls == "sqli_exploitation_confirmed" else "Application impact undetermined.",
        "mitre_techniques": ["T1190"] if cls in {"sqli_probe_observed", "sqli_exploitation_confirmed", "sqli_exploitation_suspected"} else [],
        "missing_evidence": ([] if cls == "sqli_exploitation_confirmed" else ["Verified application-side credential mismatch"])
                            + ([] if any(p.action_type in TRAFFIC for p in proposals) else ["Verified enforcement point"]),
        "recommended_investigation": ["Correlate request, authentication and endpoint observations."],
        "recommended_responses": [p.model_dump(mode="json") for p in proposals],
    }, (proposals[-1] if proposals[-1].action_type in WAF_TYPES else proposal)


async def related_records(db, incident, investigation):
    """Return candidate records near the HTTP event, without inferring attribution."""
    from datetime import timedelta
    from app.models.auth_event import AuthEvent
    from app.models.flow import Flow
    from app.models.incident_note import IncidentNote
    from app.models.process_info import ProcessInfo

    fact = investigation["observed_facts"][-1]
    stamp = as_utc(fact["observed_at"])
    window = (stamp - timedelta(minutes=2), stamp + timedelta(minutes=2))
    scope = incident.agent_id
    source = fact["source_ip"]
    queries = {
        "http": select(WebAccessLog.id, WebAccessLog.method, WebAccessLog.status_code, WebAccessLog.timestamp)
        .where(WebAccessLog.agent_id == scope, WebAccessLog.src_ip == source, WebAccessLog.timestamp.between(*window))
        .order_by(WebAccessLog.timestamp.desc()),
        "authentication": select(AuthEvent.id, AuthEvent.status, AuthEvent.timestamp)
        .where(AuthEvent.agent_id == scope, AuthEvent.source_ip == source, AuthEvent.timestamp.between(*window))
        .order_by(AuthEvent.timestamp.desc()),
        "flows": select(Flow.id, Flow.start_time, Flow.protocol, Flow.pid)
        .where(Flow.agent_id == scope, (Flow.src_ip == source) | (Flow.dst_ip == source), Flow.start_time.between(*window))
        .order_by(Flow.start_time.desc()),
        "process_metadata_in_window": select(ProcessInfo.id, ProcessInfo.name, ProcessInfo.pid, ProcessInfo.process_start_time,
                                             ProcessInfo.created_at).where(ProcessInfo.agent_id == scope,
                                             ProcessInfo.created_at.between(*window)).order_by(ProcessInfo.created_at.desc()),
        "timeline": select(IncidentNote.id, IncidentNote.created_at)
        .where(IncidentNote.incident_id == incident.id, IncidentNote.created_at.between(*window))
        .order_by(IncidentNote.created_at.desc()),
    }
    from fastapi.encoders import jsonable_encoder
    records = {}
    for name, query in queries.items():
        records[name] = [jsonable_encoder(dict(row)) for row in (await db.execute(query.limit(25))).mappings()]
    return records
