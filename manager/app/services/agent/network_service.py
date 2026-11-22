"""Persist endpoint state and dispatch authenticated, expiring network actions."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
import uuid

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from app.models.agent import Agent
from app.models.command import Command
from app.models.incident import Incident
from app.models.threat_indicator import ThreatIndicator
from app.models.network_snapshot import NetworkSnapshot
from app.models.response_action import ResponseAction
from app.schemas.enums import CommandStatus
from app.schemas.network import NetworkAck, NetworkSnapshotIn
from app.services.common.audit_log_service import ActionAuditLogService
from app.services.detection.network_reputation_service import KNOWN_PREFIXES

REFRESH = "network_refresh"
FIREWALL = "network_firewall"
FIREWALL_SAFETY_VERSION = 2
ACTIONS = (REFRESH, FIREWALL)
COMMAND_TTL = 45
RESULT_TTL = 180


def now():
    return datetime.now(timezone.utc)


def utc(stamp):
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


async def store_snapshot(session, agent_id, payload):
    if len(json.dumps(payload, ensure_ascii=False).encode()) > 1_750_000:
        raise ValueError("Network snapshot exceeds size limit")
    dto = NetworkSnapshotIn.model_validate(payload)
    if dto.agent_id != agent_id or not dto.collected_at.tzinfo or not dto.timestamp.tzinfo:
        raise ValueError("Invalid network snapshot identity or timestamp")
    if await session.get(Agent, agent_id) is None:
        raise ValueError("Network snapshot requires a registered Agent")
    snapshot = await session.get(NetworkSnapshot, agent_id)
    previous = snapshot.payload if snapshot else {}
    if snapshot and previous.get("snapshot_id") == dto.snapshot_id:
        return
    stamp = now()
    if not snapshot:
        snapshot = NetworkSnapshot(agent_id=agent_id, received_at=stamp)
        session.add(snapshot)
    snapshot.received_at = stamp
    snapshot.payload = dto.model_dump(mode="json")


async def mark_unsupported(session, agent_id, platform):
    snapshot = await session.get(NetworkSnapshot, agent_id)
    if snapshot:
        return
    stamp = now()
    session.add(NetworkSnapshot(agent_id=agent_id, received_at=stamp, payload={
        "agent_id": agent_id, "platform": platform, "status": "unsupported",
        "sections": {}, "collected_at": stamp.isoformat(),
    }))


async def _update_action(session, command, status, transaction=None, error=None):
    action_id = (command.payload or {}).get("action_id")
    if not action_id:
        return
    action = await session.get(ResponseAction, action_id)
    if not action or action.agent_id != command.agent_id or action.action_type != FIREWALL:
        return
    action.status = status
    action.snapshot = {**(action.snapshot or {}), "agent_result": transaction, "error": error,
                       "ack": command.status.value, "executed_at": command.executed_at.isoformat() if command.executed_at else None}
    if status in {"applied", "rollback_scheduled"}:
        action.applied_at = now()
    await ActionAuditLogService(session).record_event(
        action.id, status, "agent" if status != "timeout" else "manager",
        error, {"command_id": command.id, "transaction": transaction},
    )


async def expire_commands(session, agent_id):
    current = now()
    rows = (await session.scalars(select(Command).where(
        Command.agent_id == agent_id, Command.action.in_(ACTIONS),
        Command.status.in_([CommandStatus.PENDING, CommandStatus.SENT]),
        Command.issued_at <= current - timedelta(seconds=COMMAND_TTL),
    ).with_for_update())).all()
    for cmd in rows:
        deadline = RESULT_TTL if cmd.status == CommandStatus.SENT else COMMAND_TTL
        if (current - utc(cmd.issued_at)).total_seconds() < deadline:
            continue
        cmd.status = CommandStatus.TIMEOUT
        cmd.error_message = "Agent acknowledgement timed out"
        await _update_action(session, cmd, "timeout", error=cmd.error_message)
    await session.flush()


async def queue_command(session, agent_id, operator, operation=None):
    # PostgreSQL serializes requests per Agent. Pending commands are deliberately never retried.
    agent = await session.scalar(select(Agent).where(Agent.id == agent_id).with_for_update())
    if not agent:
        raise HTTPException(404, "Agent not found")
    await expire_commands(session, agent_id)
    if operation and operation["operation"] not in {"commit", "rollback"}:
        if agent.is_isolated:
            raise HTTPException(409, "Agent is isolated")
        snapshot = await session.get(NetworkSnapshot, agent_id)
        if not snapshot or snapshot.payload.get("platform") != "linux":
            raise HTTPException(409, "A Linux network snapshot is required")
        firewall = snapshot.payload.get("sections", {}).get("firewall", {})
        controls_ok = bool((firewall.get("controls_configured") or firewall.get("provider") == "ufw")
                           and firewall.get("safety_version") == FIREWALL_SAFETY_VERSION)
        if not controls_ok or now() - utc(snapshot.received_at) > timedelta(seconds=90):
            raise HTTPException(409, "UFW controls require a current snapshot with the upgraded local safety policy")
    elif operation:
        origin = await session.get(Command, operation["transaction_id"])
        if not origin or origin.agent_id != agent_id or origin.action != FIREWALL or not origin.payload.get("action_id"):
            raise HTTPException(404, "Firewall transaction not found")
        action = await session.get(ResponseAction, origin.payload["action_id"])
        if (not action or action.status != "rollback_scheduled" or origin.status != CommandStatus.SUCCESS
                or origin.payload.get("firewall_safety_version") != FIREWALL_SAFETY_VERSION):
            raise HTTPException(409, "Firewall transaction is not awaiting confirmation")

    latest = await session.scalar(select(Command).where(
        Command.agent_id == agent_id, Command.action.in_(ACTIONS),
        Command.issued_at >= now() - timedelta(seconds=5),
    ).limit(1))
    if latest:
        raise HTTPException(429, "Wait five seconds before requesting another network command")
    pending = await session.scalar(select(Command.id).where(
        Command.agent_id == agent_id, Command.action.in_(ACTIONS),
        Command.status.in_([CommandStatus.PENDING, CommandStatus.SENT]),
    ).limit(1))
    if pending:
        raise HTTPException(409, "A network command is already pending")

    if operation is None:
        await session.execute(delete(Command).where(
            Command.agent_id == agent_id, Command.action == REFRESH,
            Command.issued_at < now() - timedelta(days=7),
        ))
    command_id = uuid.uuid4().hex
    action_id = uuid.uuid4().hex if operation else None
    stamp = now()
    payload = {"expires_at": (stamp + timedelta(seconds=COMMAND_TTL)).isoformat(), "params": operation or {}}
    if operation:
        payload.update(action_id=action_id, firewall_safety_version=FIREWALL_SAFETY_VERSION)
        action = ResponseAction(id=action_id, agent_id=agent_id, action_type=FIREWALL, status="pending",
                                action_params=dict(operation, command_id=command_id, operator=operator))
        session.add(action)
        await session.flush()
        await ActionAuditLogService(session).record_event(
            action_id, "created", operator, operation["reason"], {"command_id": command_id, "parameters": operation},
        )
    session.add(Command(id=command_id, agent_id=agent_id, action=FIREWALL if operation else REFRESH,
                        payload=payload, issued_at=stamp, max_retries=0))
    await session.flush()
    return {"command_id": command_id, "action_id": action_id, "status": "pending"}


async def pull_network_command(session, agent_id, *, reported_safety=None):
    await expire_commands(session, agent_id)
    query = select(Command).where(Command.agent_id == agent_id, Command.action.in_(ACTIONS),
                                  Command.status == CommandStatus.PENDING).order_by(Command.issued_at).limit(1)
    cmd = await session.scalar(query.with_for_update(skip_locked=True))
    if not cmd:
        return None
    version = cmd.payload.get("firewall_safety_version")
    if cmd.action == FIREWALL:
        snapshot = await session.get(NetworkSnapshot, agent_id)
        safety = (snapshot.payload.get("sections", {}).get("firewall", {}) if snapshot else {}).get("safety_version")
        if (version != FIREWALL_SAFETY_VERSION or safety != FIREWALL_SAFETY_VERSION
                or reported_safety != FIREWALL_SAFETY_VERSION):
            cmd.status = CommandStatus.FAILED
            cmd.error_message = "Command uses an obsolete firewall safety policy"
            await _update_action(session, cmd, "failed", error=cmd.error_message)
            return None
    cmd.send_to_agent()
    return {"agent_id": agent_id, "schema_version": 1, "command_id": cmd.id, "action": cmd.action,
            "expires_at": cmd.payload["expires_at"], "params": cmd.payload["params"], "firewall_safety_version": version}


async def acknowledge(session, agent_id, payload):
    dto = NetworkAck.model_validate(payload)
    if dto.agent_id != agent_id or not dto.timestamp.tzinfo:
        raise ValueError("Network acknowledgement identity or timestamp mismatch")
    cmd = await session.scalar(select(Command).where(Command.id == dto.command_id).with_for_update())
    if not cmd or cmd.agent_id != agent_id or cmd.action not in ACTIONS:
        raise ValueError("Unknown network command")
    if cmd.status not in {CommandStatus.SENT, CommandStatus.TIMEOUT}:
        return
    snapshot = await session.get(NetworkSnapshot, agent_id)
    result = dto.transaction or {}
    verified = bool(snapshot and dto.snapshot_id and snapshot.payload.get("snapshot_id") == dto.snapshot_id
                    and snapshot.payload.get("command_id") == cmd.id and snapshot.payload.get("status") in {"ok", "partial"})
    if cmd.action == FIREWALL and verified:
        firewall = snapshot.payload["sections"].get("firewall", {})
        params = cmd.payload["params"]
        operation = params["operation"]
        expected = {"commit": "committed", "rollback": "rolled_back"}.get(operation, "awaiting_commit")
        after = result.get("after") or {}
        verified = (firewall.get("provider") == "ufw" and firewall.get("status") in {"active", "inactive"}
                    and result.get("status") == expected and result.get("id") == params.get("transaction_id", cmd.id)
                    and all(firewall.get(field) == after.get(field) for field in ("status", "defaults", "logging")))
        if operation in {"enable", "disable"}:
            requested_status = "active" if operation == "enable" else "inactive"
            verified = verified and firewall.get("status") == requested_status
    if dto.status == "success" and not verified:
        raise ValueError("Network command requires a correlated verification snapshot")
    cmd.acknowledge(CommandStatus.SUCCESS if dto.status == "success" else CommandStatus.FAILED, dto.error)
    cmd.executed_at = dto.timestamp
    state = {"awaiting_commit": "rollback_scheduled", "committed": "applied", "rolled_back": "reverted",
             "rollback_failed": "failed", "applying": "rollback_scheduled"}.get(result.get("status"),
                                                                              "applied" if verified else "failed")
    if dto.status == "failed" and not result:
        state = "failed"
    await _update_action(session, cmd, state, dto.transaction, dto.error)
    if result.get("id") and result["id"] != cmd.id:
        await record_transaction(session, agent_id, result)


async def record_transaction(session, agent_id, result):
    transaction_id = result.get("id")
    if not isinstance(transaction_id, str) or len(transaction_id) != 32:
        return
    cmd = await session.scalar(select(Command).where(Command.id == transaction_id).with_for_update())
    if not cmd or cmd.action != FIREWALL or cmd.agent_id != agent_id:
        return
    action_id = cmd.payload.get("action_id")
    action = await session.get(ResponseAction, action_id) if action_id else None
    state = {"awaiting_commit": "rollback_scheduled", "rolled_back": "reverted",
             "rollback_failed": "failed", "committed": "applied"}.get(result.get("status"))
    if state and action and action.status != state:
        # A command ACK establishes apply success. Recovery is accepted even when the original ACK was lost.
        if state in {"rollback_scheduled", "applied"} and cmd.status != CommandStatus.SUCCESS:
            return
        await _update_action(session, cmd, state, result, result.get("error"))


async def audit_history(session, agent_id, offset, limit):
    statement = select(ResponseAction).where(ResponseAction.agent_id == agent_id, ResponseAction.action_type == FIREWALL)
    rows = (await session.scalars(statement.options(selectinload(ResponseAction.audit_logs))
                                  .order_by(ResponseAction.created_at.desc()).offset(offset).limit(limit + 1))).all()
    return {"rows": [
        {"id": action.id, "agent_id": action.agent_id, "status": action.status, "requested_at": action.created_at,
         "parameters": action.action_params, "result": action.snapshot,
         "events": [{"timestamp": event.created_at, "event": event.event, "actor": event.actor, "reason": event.reason}
                    for event in action.audit_logs]}
        for action in rows[:limit]
    ], "has_more": len(rows) > limit}


async def add_context(session, agent_id, rows, *, groups):
    ip_key = "remote_ip" if groups else "dst_ip"
    ips = {row[ip_key] for row in rows if row.get(ip_key)}
    if not ips:
        return rows
    context = {}
    for value in ips:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        prefix = next(((asn, org) for network, asn, org, _ in KNOWN_PREFIXES if address in network), None)
        if prefix:
            context[value] = {"asn": prefix[0], "organization": f"{prefix[1]} (local prefix estimate)"}
    indicator_rows = (await session.scalars(
        select(ThreatIndicator).where(ThreatIndicator.indicator_type == "ip", ThreatIndicator.value.in_(ips))
        .order_by(ThreatIndicator.confidence.desc()).limit(500)
    )).all()
    for indicator in indicator_rows:
        context.setdefault(indicator.value, {}).setdefault("risk_context",
            f"{indicator.threat_type} · {indicator.source} · confidence {indicator.confidence:g}")
    if groups:
        cutoff = now() - timedelta(days=7)
        incidents = (await session.scalars(select(Incident).where(Incident.agent_id == agent_id, Incident.created_at >= cutoff)
                                          .order_by(Incident.created_at.desc()).limit(250))).all()
        for value in ips:
            exact = re.compile(r"(?<![0-9A-Fa-f.])" + re.escape(value) + r"(?![0-9A-Fa-f.])")
            matches = [{"id": item.id, "title": item.title} for item in incidents
                       if exact.search(f"{item.description or ''} {item.notes or ''}")]
            context.setdefault(value, {})["incidents"] = matches[:10]
    return [{**row, **context.get(row.get(ip_key), {})} for row in rows]
