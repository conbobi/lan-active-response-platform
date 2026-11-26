"""Incident-scoped response proposals. All targets and capabilities are server derived."""
import logging
from typing import Literal
from time import monotonic

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.core.deps import get_db
from app.core.network_security import (
    authenticate_operator_request,
    is_enrolled,
    issue_session,
    token_matches,
    verify_operator_or_admin,
)
from app.core.config import settings
from app.core import response_outcome as oc
from app.core.response_outcome import OutcomeHTTPException
from app.models.agent import Agent
from app.models.command import Command
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.services.agent import network_service
from app.services.common.audit_log_service import ActionAuditLogService
from app.services.response.assist_policy import decision, recommend
from app.services.response.http_investigation import ASSIST_TYPES, TRAFFIC, WAF_TYPES, GUIDE, WATCH, COLLECT, CollectionProposal, investigate, match_proposal, related_records
from app.services.response.waf_reconciliation import reconcile
from app.services.response.manager_investigation import reconcile_watch, record_guidance
from app.services.response import response_plan
from app.websocket.connection_manager import connection_manager

router = APIRouter(tags=["AI Response Assist"])
logger = logging.getLogger(__name__)
ProposalType = Literal["collect_additional_evidence", "temporary_ip_block", "apply_rate_limit", "revoke_session", "generate_remediation_guidance", "increase_monitoring"]


class EmptyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProposalRequest(EmptyRequest):
    model_review: bool = False
    action_type: ProposalType | None = None


class BatchProposalRequest(EmptyRequest):
    action_types: list[ProposalType] = Field(min_length=1, max_length=8)


class BatchActionRequest(EmptyRequest):
    action_ids: list[str] = Field(min_length=1, max_length=16)


def mock_mode():
    """Mock execution is a development aid: it is ignored unless the Manager runs with DEBUG."""
    if settings.RESPONSE_MOCK_MODE and not settings.DEBUG:
        logger.warning("RESPONSE_MOCK_MODE ignored because DEBUG is false")
    return bool(settings.RESPONSE_MOCK_MODE and settings.DEBUG)


async def operator(token, db, agent=None, write=False):
    identity, _ = await authenticate_operator_request(
        token, db, agent_id=agent, write=write, allowed_write_roles={"admin", "operator"}
    )
    return identity


@router.post("/auth/session", deprecated=True)
async def sign_in(response: Response, authorization: str | None = Header(None)):
    if not settings.ALLOW_LEGACY_OPERATOR_TOKENS:
        raise OutcomeHTTPException(401, "Legacy operator token login disabled; use /auth/login", oc.AUTHORIZATION_FAILED)
    identity, config = verify_operator_or_admin(authorization)
    digest = config.token_sha256 if getattr(config, "token_sha256", None) else None
    if digest is None:
        # Look up digest from settings for OperatorContext returned by legacy verifier
        if identity == "legacy_admin":
            digest = settings.NETWORK_LEGACY_ADMIN_TOKEN
        elif identity in settings.NETWORK_OPERATORS:
            digest = settings.NETWORK_OPERATORS[identity].token_sha256
    if not token_matches((authorization or "").partition(" ")[2].strip(), digest):
        raise OutcomeHTTPException(401, "Operator credential required to sign in", oc.AUTHORIZATION_FAILED)
    session, expires = issue_session(digest)
    response.headers["Cache-Control"] = "no-store"
    return {"access_token": session, "expires_at": expires, "actor": identity,
            "role": config.role if config else "admin"}


async def scoped_incident(db, key, token, lock=False):
    await operator(token, db)
    query = select(Incident).where(Incident.id == key).execution_options(populate_existing=True)
    incident = await db.scalar(query.with_for_update() if lock else query)
    if not incident or not incident.agent_id:
        raise OutcomeHTTPException(404, "Incident unavailable", oc.NOT_FOUND)
    await operator(token, db, incident.agent_id)
    return incident


OUTCOME_BY_STATUS = {"pending_approval": oc.APPROVAL_REQUIRED, "not_recommended": oc.POLICY_DENIED,
                     "failed": oc.INTERNAL_ERROR, "rollback_failed": oc.INTERNAL_ERROR,
                     "mock_succeeded": oc.MOCK_ONLY}


def view(action):
    return {**action.action_params, "status": action.status, "result": action.snapshot or {},
            "outcome_code": OUTCOME_BY_STATUS.get(action.status, oc.SUCCESS),
            "mock": bool((action.snapshot or {}).get("mock")),
            "rollback_available": action.action_type == WATCH and action.status in {"dispatched", "monitoring"} or action.action_type in TRAFFIC and action.status in {"dispatched", "verifying", "succeeded", "partial", "rollback_failed"}}


@router.get("/incidents/{incident_id}/response-proposals")
async def proposals(incident_id: str, authorization: str | None = Header(None), db=Depends(get_db)):
    incident = await scoped_incident(db, incident_id, authorization)
    await network_service.expire_commands(db, incident.agent_id)
    investigation, proposal = await investigate(db, incident)
    actions = (await db.scalars(select(ResponseAction).where(
        ResponseAction.incident_id == incident.id, ResponseAction.agent_id == incident.agent_id,
        ResponseAction.action_type.in_(ASSIST_TYPES),
    ).order_by(ResponseAction.created_at.desc()).limit(25))).all()
    for row in actions:
        await reconcile(db, row)
        await reconcile_watch(db, row)
    _, config = await authenticate_operator_request(authorization, db, agent_id=incident.agent_id)
    views = [view(row) for row in actions]
    try:
        analysis, plan = await response_plan.build(db, incident, investigation, views)
    except Exception:
        # The analysis is advisory; the proposals and actions above stay usable without it.
        logger.exception("Response plan failed for incident %s", incident.id)
        analysis, plan = None, []
    return {"can_execute": config is None or config.role in {"admin", "operator"},
            "agent_online": is_enrolled(incident.agent_id) and incident.agent_id in connection_manager.authenticated_connections,
            "investigation": investigation, "policy_decision": decision(proposal.action_type if proposal else COLLECT, proposal),
            "actions": views, "analysis": analysis, "plan": plan,
            "historical": response_plan.is_historical(incident), "mock_mode": mock_mode()}


@router.post("/incidents/{incident_id}/response-proposals")
async def propose(incident_id: str, body: ProposalRequest, authorization: str | None = Header(None), db=Depends(get_db)):
    return await _propose(incident_id, body, authorization, db)


def _batch_item(key_name, key, exc=None, action=None):
    if exc is None:
        return {key_name: key, "status_code": 200, "outcome_code": action["outcome_code"], "action": action, "detail": None}
    if isinstance(exc, HTTPException):
        return {key_name: key, "status_code": exc.status_code,
                "outcome_code": getattr(exc, "outcome", None) or oc.default_outcome(exc.status_code),
                "action": None, "detail": exc.detail}
    logger.exception("Batch item %s failed", key, exc_info=exc)
    return {key_name: key, "status_code": 500, "outcome_code": oc.INTERNAL_ERROR, "action": None, "detail": "Internal error"}


@router.post("/incidents/{incident_id}/response-proposals/batch")
async def propose_batch(incident_id: str, body: BatchProposalRequest, authorization: str | None = Header(None),
                        db=Depends(get_db)):
    """Each action type goes through the single-proposal path and is reported on its own."""
    await operator(authorization, db)  # Unauthenticated callers fail as a whole; scope is checked per item.
    results = []
    for kind in dict.fromkeys(body.action_types):
        try:
            async with db.begin_nested():
                action = await _propose(incident_id, ProposalRequest(action_type=kind), authorization, db)
            results.append(_batch_item("action_type", kind, action=action))
        except Exception as exc:  # noqa: BLE001 - every item reports its own outcome
            results.append(_batch_item("action_type", kind, exc))
    return {"results": results}


async def _propose(incident_id, body, authorization, db):
    started = monotonic()
    incident = await scoped_incident(db, incident_id, authorization)
    actor = await operator(authorization, db, incident.agent_id)
    investigation, proposal = await investigate(db, incident)
    if body.action_type:
        candidate = next((p for p in (investigation or {}).get("recommended_responses", [])
                          if p["action_type"] == body.action_type), None)
        proposal = match_proposal(investigation, candidate["action_id"]) if candidate else None
    if not proposal:
        raise OutcomeHTTPException(409, "Correlated source evidence required for this action", oc.INSUFFICIENT_EVIDENCE)
    previous = await db.get(ResponseAction, proposal.action_id)
    if previous:
        return view(previous)
    current = proposal
    stages = {"evidence_and_projection_ms": round((monotonic() - started) * 1000, 2)}
    selected, origin, latency = True, "evidence_policy", 0
    if body.model_review:
        selected, origin, latency = await recommend(investigation, proposal, db, stages)
        incident = await scoped_incident(db, incident_id, authorization, lock=True)
        reviewed, _ = await investigate(db, incident)
        current = match_proposal(reviewed, proposal.action_id)
        if not current or current != proposal:
            raise OutcomeHTTPException(409, "Evidence changed during review; investigate again", oc.INSUFFICIENT_EVIDENCE)
        if origin == "policy_fallback" and current.action_type in WAF_TYPES:
            current = CollectionProposal.model_validate(investigation["recommended_responses"][0])
        previous = await db.get(ResponseAction, current.action_id)
        if previous:
            return view(previous)
    policy_start = monotonic()
    policy = decision(current.action_type, current)
    stages["policy_ms"] = round((monotonic() - policy_start) * 1000, 4)
    write_start = monotonic()
    action = ResponseAction(id=current.action_id, agent_id=incident.agent_id, incident_id=incident.id,
                            action_type=current.action_type, status=("pending_approval" if current.requires_approval else "approved") if selected else "not_recommended",
                            action_params={**current.model_dump(mode="json"), "recommendation_source": origin,
                                           "policy_decision": policy})
    try:
        async with db.begin_nested():
            db.add(action)
            await db.flush()
    except IntegrityError:
        existing = await db.get(ResponseAction, current.action_id)
        if existing:
            return view(existing)
        raise
    stages["action_write_ms"] = round((monotonic() - write_start) * 1000, 2)
    audit = ActionAuditLogService(db)
    await audit.record_event(action.id, "proposed", actor, metadata={"origin": origin, "analysis_ms": latency, "stage_ms": stages})
    await audit.record_event(action.id, action.status, "policy", metadata={
        "policy_version": current.policy_version, "proposal_ms": round((monotonic() - started) * 1000)})
    return view(action)


async def scoped_action(db, key, token, *, write=False, lock=False):
    await operator(token, db)
    query = select(ResponseAction).where(ResponseAction.id == key, ResponseAction.action_type.in_(ASSIST_TYPES))
    row = await db.scalar(query.with_for_update() if lock else query)
    if not row:
        raise OutcomeHTTPException(404, "Action unavailable", oc.NOT_FOUND)
    return row, await operator(token, db, row.agent_id, write)


@router.post("/response-actions/batch/{operation}")
async def transition_batch(operation: Literal["approve", "reject"], body: BatchActionRequest,
                           authorization: str | None = Header(None), db=Depends(get_db)):
    """Each action is scoped, authorized and transitioned exactly like the single route."""
    await operator(authorization, db)
    results = []
    for key in dict.fromkeys(body.action_ids):
        try:
            async with db.begin_nested():
                action = await _transition(key, operation, authorization, db)
            results.append(_batch_item("action_id", key, action=action))
        except Exception as exc:  # noqa: BLE001
            results.append(_batch_item("action_id", key, exc))
    return {"results": results}


@router.get("/response-actions/{action_id}")
async def detail(action_id: str, authorization: str | None = Header(None), db=Depends(get_db)):
    row, _ = await scoped_action(db, action_id, authorization)
    await network_service.expire_commands(db, row.agent_id)
    await reconcile(db, row)
    await reconcile_watch(db, row)
    audit = await ActionAuditLogService(db).get_logs_for_action(row.id)
    return {**view(row), "audit": [{"event": e.event, "actor": e.actor, "at": e.created_at,
                                    "metadata": e.metadata_} for e in audit]}


@router.post("/response-actions/{action_id}/{operation}")
async def transition(action_id: str, operation: Literal["approve", "reject", "execute", "rollback"],
                     body: EmptyRequest, authorization: str | None = Header(None), db=Depends(get_db)):
    return await _transition(action_id, operation, authorization, db)


ACTIVE_STATES = {"dispatched", "executing", "verifying", "monitoring", "succeeded", "partial", "applied", "pending"}


async def _blocking_actions(db, action, current):
    """Active actions on the same Agent that this action conflicts with (playbook + same-peer traffic)."""
    conflicts = response_plan.conflicting_types(action.action_type)
    if not conflicts:
        return []
    # Serialize conflict checks per Agent (row lock on PostgreSQL).
    await db.scalar(select(Agent.id).where(Agent.id == action.agent_id).with_for_update())
    rows = (await db.scalars(select(ResponseAction).where(
        ResponseAction.agent_id == action.agent_id, ResponseAction.id != action.id,
        ResponseAction.action_type.in_(conflicts), ResponseAction.status.in_(ACTIVE_STATES)))).all()
    peer = (current.target_resource or {}).get("source_ip")
    stamp = network_service.now().timestamp()
    blocking = []
    for row in rows:
        if row.action_type in TRAFFIC:
            if ((row.action_params or {}).get("target_resource") or {}).get("source_ip") != peer:
                continue
            if (row.snapshot or {}).get("deadline", float("inf")) <= stamp:
                continue
        blocking.append(row.id)
    return blocking


async def _transition(action_id, operation, authorization, db):
    action, actor = await scoped_action(db, action_id, authorization, write=True, lock=True)
    if operation == "rollback":
        if action.status == "rolled_back":
            return view(action)
        if not view(action)["rollback_available"]:
            raise OutcomeHTTPException(409, "No reversible effect for this action", oc.POLICY_DENIED)
        await reconcile(db, action, undo_actor=actor)
        await reconcile_watch(db, action, stop_actor=actor)
        return view(action)
    if operation in {"approve", "reject"}:
        target = "approved" if operation == "approve" else "rejected"
        if action.status == target:
            return view(action)
        if action.status != "pending_approval":
            raise OutcomeHTTPException(409, "Action is not awaiting approval", oc.CONFLICT)
    else:
        if action.status in {"dispatched", "executing", "succeeded", "partial", "failed", "verifying", "monitoring"}:
            return view(action)
        if action.status != "approved":
            raise OutcomeHTTPException(409, "Approved action required", oc.APPROVAL_REQUIRED)
        target = "dispatched"
    if operation != "reject":
        incident = await scoped_incident(db, action.incident_id, authorization)
        investigation, _ = await investigate(db, incident)
        current = match_proposal(investigation, action.id)
        if current is None:
            raise OutcomeHTTPException(409, "Current incident evidence no longer supports this proposal",
                                       oc.INSUFFICIENT_EVIDENCE)
        if decision(action.action_type, current) not in {"ALLOW_AUTOMATIC", "REQUIRE_APPROVAL"} or current.action_id != action.id:
            raise OutcomeHTTPException(409, "Current incident evidence does not match this proposal", oc.POLICY_DENIED)
        if operation == "execute":
            if response_plan.is_historical(incident) and action.action_type in response_plan.ENFORCEMENT:
                raise OutcomeHTTPException(409, "Incident is closed: only read-only collection and guidance are allowed",
                                           oc.POLICY_DENIED)
            blocked_by = await _blocking_actions(db, action, current)
            if blocked_by:
                raise OutcomeHTTPException(409, "A conflicting response action is active", oc.POLICY_DENIED,
                                           extra={"blocked_by": blocked_by})
    claim = await db.execute(update(ResponseAction).where(ResponseAction.id == action.id,
                             ResponseAction.status == action.status).values(status=target))
    if claim.rowcount != 1:
        raise OutcomeHTTPException(409, "Action changed concurrently", oc.CONFLICT)
    if operation == "execute" and mock_mode():
        stamp = network_service.now()
        action.status = "mock_succeeded"
        action.snapshot = {"mock": True, "verification": {
            "verification_method": "mock", "method": "mock", "observed_at": stamp.isoformat(),
            "expected_result": "No effect: RESPONSE_MOCK_MODE", "actual_result": "Simulated; nothing was executed",
            "evidence_refs": [], "verification_status": "mock", "status": "mock", "failure_reason": None}}
        await ActionAuditLogService(db).record_event(action.id, "mock_succeeded", actor, metadata={"mock": True})
        return view(action)
    if operation == "execute" and action.action_type in (*WAF_TYPES, WATCH):
        stamp = network_service.now().timestamp()
        action.snapshot = {"start": stamp, "deadline": stamp + (current.proposed_ttl_seconds or 180)}
    elif operation == "execute" and action.action_type == COLLECT:
        if not is_enrolled(action.agent_id) or action.agent_id not in connection_manager.authenticated_connections:
            raise OutcomeHTTPException(409, "Authenticated Agent is offline", oc.AGENT_OFFLINE)
        start = monotonic()
        records = await related_records(db, incident, investigation)
        queued = await network_service.queue_command(db, action.agent_id, actor)
        cmd = await db.get(Command, queued["command_id"])
        cmd.payload = {**cmd.payload, "assist_id": action.id}
        action.snapshot = {"command_id": cmd.id, "related_records": records,
                           "dispatch_ms": round((monotonic() - start) * 1000)}
    action.status = target
    await ActionAuditLogService(db).record_event(action.id, target, actor)
    if operation == "execute" and action.action_type == GUIDE:
        await record_guidance(db, action, actor, investigation)
    if operation == "execute" and action.action_type == WATCH:
        await reconcile_watch(db, action)
    if operation == "execute" and action.action_type in WAF_TYPES:
        await db.commit()  # Record the intent and absolute expiry before changing the external store.
        await reconcile(db, action)
    return view(action)
