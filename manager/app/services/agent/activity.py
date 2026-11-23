"""Current socket/process observations, independent of SOC incident status."""
from datetime import datetime, timedelta, timezone
import ipaddress

from sqlalchemy import select

from app.models.agent import Agent
from app.models.agent_activity import AgentActivity
from app.core.agent_health import ACTIVITY_FRESHNESS, STALE_AFTER, agent_health, as_utc
from app.services.detection.network_shell import RULE_ID, detect_network_shell

PROCESS_LIMIT = 8192
SOCKET_LIMIT = 200


def process_identity(process):
    pid = process.get("pid")
    started = process.get("process_start_time")
    if type(pid) is int and 0 < pid < 2**31 and type(started) in (float, int) and 0 < started < 2**53:
        return (pid, started)
    return None


def socket_key(event):
    try:
        local, remote = (ipaddress.ip_address(event[field]) for field in ("src_ip", "dst_ip"))
        local, remote = (getattr(ip, "ipv4_mapped", None) or ip for ip in (local, remote))
        return [event["protocol"], str(local), int(event["src_port"]), str(remote), int(event["dst_port"])]
    except (KeyError, ValueError, TypeError, OverflowError):
        return None


async def record_sample(session, agent_id, stream, payload, events):
    """Save a newer observation under the same per-Agent lock used for incident writes."""
    metadata = payload.get("activity_sample")
    if not isinstance(metadata, dict) or metadata.get("version") != 1:
        return None
    now = datetime.now(timezone.utc)
    captured = as_utc(metadata.get("captured_at"))
    if captured is None or not now - timedelta(minutes=5) <= captured <= now + timedelta(seconds=30):
        return False
    agent = (await session.execute(select(Agent).where(Agent.id == agent_id).with_for_update())).scalar_one_or_none()
    if agent is None or agent.decommissioned_at is not None:
        return False
    row = await session.get(AgentActivity, agent_id)
    samples = dict(row.samples) if row else {}
    previous = as_utc(samples.get(stream, {}).get("captured_at"))
    if previous and captured <= previous:
        return False
    limit = SOCKET_LIMIT if stream == "socket" else PROCESS_LIMIT
    if not isinstance(events, list):
        return False
    rows = [item for item in events[:limit] if isinstance(item, dict)]
    if stream == "socket":
        rows = [item for item in rows if as_utc(item.get("observed_at")) == captured]
    complete = metadata.get("complete") is True and len(rows) == len(events)
    sample = {"captured_at": captured.isoformat(), "received_at": now.isoformat(), "complete": complete}
    if stream == "socket":
        session.info["previous_socket_sample"] = samples.get("socket", {})
        keys = [socket_key(item) for item in rows]
        sample["complete"] = complete and None not in keys
        sample["tuples"] = [key for key in keys if key is not None]
        sample["detections"] = sorted({match["entity"] for item in rows
                                     if (match := detect_network_shell(item)) and match["severity"] == "high"})
    else:
        identities = {str(item["pid"]): process_identity(item) for item in rows if type(item.get("pid")) is int}
        sample["processes"] = {pid: identity[1] if identity else None for pid, identity in identities.items()}
        sample["complete"] = complete and len(identities) == len(rows)
    samples[stream] = sample
    if row:
        row.samples = samples
    else:
        session.add(AgentActivity(agent_id=agent_id, samples=samples))
    await session.flush()
    return True


def observation_time(sample):
    return as_utc(sample.get("captured_at")) if sample else None


def observation_expiry(sample):
    captured = observation_time(sample)
    received = as_utc(sample.get("received_at")) if sample else None
    if captured is None or received is None:
        return None
    return min(captured, received) + ACTIVITY_FRESHNESS


def process_observation(agent, sample, now):
    expires = observation_expiry(sample)
    if expires and agent and as_utc(agent.last_seen):
        expires = min(expires, as_utc(agent.last_seen) + STALE_AFTER)
    return {
        "status": "running" if agent_health(agent, now) == "online" and expires and expires > now else "unknown",
        "last_seen": observation_time(sample),
        "expires_at": expires,
    }


def incident_activity(incident, agent, samples, now):
    evidence = incident.detection_evidence or {}
    process = evidence.get("process") or {}
    identity = process_identity(process)
    socket = evidence.get("network")
    socket_sample = samples.get("socket", {})
    process_sample = samples.get("process", {})
    socket_at = observation_time(socket_sample)
    process_at = observation_time(process_sample)
    expires = observation_expiry(socket_sample)
    if expires and agent and as_utc(agent.last_seen):
        expires = min(expires, as_utc(agent.last_seen) + STALE_AFTER)
    last_seen = (as_utc(evidence.get("last_observed_at")) or as_utc(evidence.get("last_received_at"))
                 or as_utc(incident.created_at))
    health = agent_health(agent, now)
    status = incident.status.value
    disposition = "false_positive" if status == "false_positive" or incident.label == "false_positive" else incident.label
    if status == "false_positive":  # Older API represented disposition as a lifecycle status.
        status = "closed"

    state = "historical"
    reason = "historical_evidence"
    last_verified = as_utc(evidence.get("last_observed_at"))
    process_state = "unknown" if identity else None
    process_seen = last_verified if identity else None
    containment = evidence.get("containment") or {}
    verified_exit = as_utc(containment.get("verified_at"))
    if identity and process_at:
        observed = process_sample.get("processes", {})
        pid = str(identity[0])
        if observed.get(pid) == identity[1]:
            process_seen = process_at
            if observation_expiry(process_sample) > now:
                process_state = "running"
        elif observation_expiry(process_sample) > now and (
            (pid not in observed and process_sample.get("complete")) or observed.get(pid) is not None
        ):
            process_state = "exited"

    if evidence.get("rule_id") == RULE_ID and socket and socket_at and socket_at >= last_seen:
        if evidence.get("entity") in socket_sample.get("detections", []):
            state, reason, last_verified = "active", "socket_behavior_observed", socket_at
            if identity and (process_at is None or socket_at >= process_at):
                process_state, process_seen = "running", socket_at
            if (verified_exit and verified_exit >= socket_at) or process_state == "exited":
                state, reason = "unknown", "awaiting_socket_verification"
        elif socket_sample.get("complete") and socket_key(socket) not in socket_sample.get("tuples", []):
            state, reason, last_verified = "inactive", "socket_absent", socket_at
        else:
            state, reason = "unknown", "inconclusive_socket_sample"
    elif evidence.get("rule_id") == RULE_ID:
        state, reason = "unknown", "awaiting_socket_sample"

    if verified_exit and identity and (process_at is None or verified_exit >= process_at):
        process_state = "exited"
    if state in {"active", "inactive"} and (expires is None or expires <= now):
        state, reason = "stale", "socket_sample_expired"
    if health != "online":
        state, reason = "stale", f"agent_{health}"
        if process_state == "running":
            process_state = "unknown"

    return {
        "incident_status": status, "disposition": disposition, "detection_activity": state, "activity_reason": reason,
        "process_activity": process_state, "process_last_seen": process_seen,
        "first_seen": as_utc(evidence.get("first_seen")) or as_utc(evidence.get("first_received_at")) or as_utc(incident.created_at),
        "last_seen": last_seen, "last_verified": last_verified, "activity_expires_at": expires,
        "occurrence_count": evidence.get("observations", 1),
        "risk_calculated_at": as_utc(evidence.get("risk_calculated_at")) or as_utc(incident.created_at),
        "rule_version": evidence.get("rule_version"), "confidence": evidence.get("confidence"),
    }


async def attach_incident_activity(session, incidents, now=None):
    agent_ids = {incident.agent_id for incident in incidents if incident.agent_id}
    rows = {}
    if agent_ids:
        stmt = select(Agent, AgentActivity).outerjoin(AgentActivity).where(Agent.id.in_(agent_ids))
        rows = {agent.id: (agent, activity.samples if activity else {})
                for agent, activity in (await session.execute(stmt)).all()}
    now = now or datetime.now(timezone.utc)
    for incident in incidents:
        agent, samples = rows.get(incident.agent_id, (None, {}))
        for field, value in incident_activity(incident, agent, samples, now).items():
            setattr(incident, field, value)
    return incidents
