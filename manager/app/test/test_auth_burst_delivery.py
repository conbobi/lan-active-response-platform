"""Hydra against the lab login (2026-11-27 07:22–07:55): bursts must be detected, not lost or merged away.

Fixture data only; documentation addresses.
"""
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.incident import Incident
from app.websocket import agent_ws
from test_http_response_assist import lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

HYDRA = "198.51.100.31"


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


async def hydra_run(factory, start, tries=16):
    """16 hydra tasks: GET + POST /login each, then the application's failure records in one batch."""
    failures = []
    for index in range(tries):
        for method in ("GET", "POST"):
            request_id = uuid.uuid4().hex
            async with factory() as db:
                await agent_ws._handle_web_access_log(AGENT, {"wait_ack": False, "payload": {
                    "agent_id": AGENT, "client_ip": HYDRA, "method": method, "path": "/login", "status_code": 200,
                    "user_agent": "Mozilla/5.0 (Hydra)", "request_id": request_id, "service": "flask_web",
                    "timestamp": iso(start + index * 0.05)}}, db)
                await db.commit()
            if method == "POST":
                failures.append({"service": "flask_web", "source_ip": HYDRA, "status": "failed", "username": "admin",
                                 "count": 1, "event_id": request_id, "request_id": request_id, "method": "POST",
                                 "path": "/login", "http_status": 200, "timestamp": iso(start + index * 0.05)})
    return failures


async def send_auth(factory, events):
    async with factory() as db:
        await agent_ws._handle_auth_event(AGENT, {"wait_ack": False, "payload": {"agent_id": AGENT, "events": events}}, db)
        await db.commit()


async def brute_force_incidents(factory):
    async with factory() as db:
        rows = (await db.scalars(select(Incident))).all()
    behaviors = [((i.detection_evidence or {}).get("behavior") or {}, i) for i in rows]
    return [i for b, i in behaviors if b.get("source_ip") == HYDRA and b.get("evidence_type") == "authentication"
            and b.get("classification") in ("repeated_auth_failures", "authentication_brute_force")]


@pytest.mark.asyncio
async def test_hydra_burst_is_detected_without_per_request_chain_correlation(lab, monkeypatch):
    _, factory = lab
    calls = []
    original = agent_ws._correlate_web_chain

    async def counted(session, agent_id):
        calls.append(agent_id)
        return await original(session, agent_id)

    monkeypatch.setattr(agent_ws, "_correlate_web_chain", counted)
    failures = await hydra_run(factory, time.time() - 20)
    await send_auth(factory, failures)
    assert calls == []  # 32 requests + 16 failures: none can add a web-compromise stage
    incident, = await brute_force_incidents(factory)
    assert incident.detection_evidence["behavior"]["failed_attempts"] == 16


@pytest.mark.asyncio
async def test_resent_batch_after_reconnect_is_not_double_counted(lab):
    _, factory = lab
    failures = await hydra_run(factory, time.time() - 20)
    await send_auth(factory, failures)
    await send_auth(factory, failures)  # Agent outbox resends what it handed to the dead socket
    incident, = await brute_force_incidents(factory)
    assert incident.detection_evidence["behavior"]["failed_attempts"] == 16


@pytest.mark.asyncio
async def test_a_later_hydra_run_is_a_new_incident_even_if_the_old_one_was_touched(lab):
    _, factory = lab
    await send_auth(factory, await hydra_run(factory, time.time() - 20))
    first, = await brute_force_incidents(factory)
    async with factory() as db:  # an observation 17 minutes ago; another detector linked it just now
        row = await db.get(Incident, first.id)
        evidence = dict(row.detection_evidence)
        evidence["last_received_at"] = (datetime.now(timezone.utc) - timedelta(minutes=17)).isoformat()
        evidence["correlated_chain"] = {"incident_id": "inc_chain", "link": "CORRELATED", "basis": "test"}
        row.detection_evidence = evidence
        row.updated_at = datetime.now(timezone.utc)
        await db.commit()
    await send_auth(factory, await hydra_run(factory, time.time() - 5))
    assert len(await brute_force_incidents(factory)) == 2
