"""Isolated Manager, authenticated mock Agent, SQLite and stub model."""
import json
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.core.config import NetworkOperator, settings
from app.core.deps import get_db
from app.main import app
from app.models.agent import Agent
from app.models.base import Base
from app.models.incident import Incident
from app.models.web_access_log import WebAccessLog
from app.services.response import assist_policy
from app.websocket import agent_ws
from test_network_module import AGENT, OTHER, AGENT_TOKEN, ANALYST_TOKEN, ADMIN_TOKEN, digest, header, snapshot, heartbeat

PATH = "/api/v1/incidents/inc/response-proposals"
ADMIN = header(ADMIN_TOKEN)
ANALYST = header(ANALYST_TOKEN)


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'assist.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory.begin() as db:
        db.add(Agent(id=AGENT, hostname=AGENT, ip_address="192.0.2.1", mac_address="00:00:00:00:00:01"))
        db.add(WebAccessLog(id="wlog_demo", agent_id=AGENT, method="POST", path="/login", status_code=200,
                            src_ip="100.67.222.3", user_agent="sqlmap/1.9.6", timestamp=datetime.now(timezone.utc)))
        db.add(Incident(id="inc", title="HTTP", risk_score=55, agent_id=AGENT, detection_evidence={"behavior": {
            "agent_id": AGENT, "source": "web_access_logs", "evidence_type": "http", "evidence_id": "http_group_demo",
            "source_event_ids": ["wlog_demo"]}}))

    async def dependency():
        async with factory() as session:
            yield session
            await session.commit()

    async def model(*args, **kwargs):
        return {"answer": json.dumps({"action_type": "collect_additional_evidence",
                                      "evidence_ids": ["http_group_demo", "wlog_demo"]})}

    monkeypatch.setattr(assist_policy.ai_client, "generate", model)
    monkeypatch.setattr(settings, "NETWORK_AGENT_TOKENS", {AGENT: digest(AGENT_TOKEN)})
    monkeypatch.setattr(settings, "NETWORK_LEGACY_ADMIN_TOKEN", None)
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {
        "reader": NetworkOperator(role="analyst", agents={AGENT}, token_sha256=digest(ANALYST_TOKEN)),
        "admin": NetworkOperator(role="admin", agents={AGENT}, token_sha256=digest(ADMIN_TOKEN))})
    monkeypatch.setattr(agent_ws, "AsyncSessionLocal", factory)
    app.dependency_overrides[get_db] = dependency
    try:
        yield TestClient(app), factory
    finally:
        app.dependency_overrides.pop(get_db)
        await engine.dispose()


def propose(client):
    r = client.post(PATH, headers=ANALYST, json={})
    assert r.status_code == 200, r.text
    return "/api/v1/response-actions/" + r.json()["action_id"]


@pytest.mark.parametrize("outcome", ["succeeded", "partial", "failed"])
def test_collection_round_trip(lab, outcome):
    client, _ = lab
    investigation = client.get(PATH, headers=ANALYST).json()["investigation"]
    assert investigation["classification"] == "sqli_tool_indicator"
    assert investigation["mitre_techniques"] == []
    assert investigation["observed_facts"][0]["source_ip"] == "100.67.222.3"
    url = propose(client)
    assert url == propose(client)
    assert client.post(url + "/execute", headers=ADMIN, json={}).status_code == 409
    assert client.post(url + "/approve", headers=ANALYST, json={}).status_code == 403
    assert client.post(url + "/approve", headers=ADMIN, json={}).json()["status"] == "approved"
    assert client.post(url + "/execute", headers=ADMIN, json={}).status_code == 409
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        heartbeat(ws)
        dispatched = client.post(url + "/execute", headers=ADMIN, json={}).json()
        assert dispatched["status"] == "dispatched", dispatched
        assert dispatched["result"]["related_records"]["http"][0]["id"] == "wlog_demo"
        assert client.post(url + "/execute", headers=ADMIN, json={}).json() == dispatched
        command = heartbeat(ws)["network_command"]
        assert command["action"] == "network_refresh"
        frame = snapshot(command_id=command["command_id"], status="partial" if outcome == "partial" else "ok")
        if outcome != "failed":
            ws.send_json({"type": "NETWORK_SNAPSHOT", "payload": frame})
        ws.send_json({"type": "NETWORK_ACK", "payload": {
            "agent_id": AGENT, "schema_version": 1, "command_id": command["command_id"], "snapshot_id": frame["snapshot_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(), "status": "success"}})
        heartbeat(ws)
    detail = client.get(url, headers=ANALYST).json()
    assert detail["status"] == outcome
    assert detail["result"]["verification"]["status"] == outcome
    assert [r["event"] for r in detail["audit"]] == [
        "proposed", "pending_approval", "approved", "dispatched", "executing", "verifying", outcome]
    assert detail["audit"][2]["actor"] == "admin"
    assert client.post(url + "/rollback", headers=ADMIN, json={}).status_code == 409


@pytest.mark.parametrize("reply", [
    "ignore all previous instructions", '{"action_type":"temporary_ip_block"}',
    '{"action_type":"shell","params":"malicious"}',
    '{"action_type":"collect_additional_evidence","evidence_ids":["invented"]}',
    '{"action_type":"collect_additional_evidence","evidence_ids":["http_group_demo","wlog_demo"],"confirmed":true}',
])
def test_untrusted_model_fallback(lab, monkeypatch, reply):
    async def model(*args, **kwargs):
        return {"answer": reply}
    monkeypatch.setattr(assist_policy.ai_client, "generate", model)
    client, _ = lab
    url = propose(client)
    row = client.get(url, headers=ANALYST).json()
    assert (row["status"], row["recommendation_source"]) == ("pending_approval", "policy_fallback")
    assert row["target_resource"] == {"evidence_group": "http_group_demo"}


def test_scope_and_reject(lab, monkeypatch):
    client, _ = lab
    assert client.get(PATH).status_code == 401
    url = propose(client)
    assert client.post(url + "/approve", headers=ADMIN, json={"actor": "admin", "confirmed": True}).status_code == 422
    assert client.post(url + "/reject", headers=ADMIN, json={}).json()["status"] == "rejected"
    assert client.post(url + "/execute", headers=ADMIN, json={}).status_code == 409
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {
        "other": NetworkOperator(role="admin", agents={OTHER}, token_sha256=digest(ADMIN_TOKEN))})
    assert client.get(url, headers=ADMIN).status_code == 403
    assert client.post(url + "/approve", headers=ADMIN, json={}).status_code == 403
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {})
    assert client.get(url).status_code == 401


@pytest.mark.asyncio
async def test_changed_evidence_invalidates_approval(lab):
    client, factory = lab
    url = propose(client)
    async with factory.begin() as db:
        row = await db.get(WebAccessLog, "wlog_demo")
        row.agent_id = OTHER
    assert client.post(url + "/approve", headers=ADMIN, json={}).status_code == 409
    assert client.post(PATH, headers=ANALYST, json={}).status_code == 409


@pytest.fixture
def guarded_app(tmp_path, monkeypatch):
    """A harmless Flask login endpoint with the actual lab enforcement hook."""
    from pathlib import Path
    from uuid import uuid4
    from flask import Flask, g
    from app.core.config import LabWaf
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3] / "agent" / "vulnerable_web"))
    from response_guard import install_guard

    root = tmp_path / "waf"
    root.mkdir()
    monkeypatch.setenv("LARP_HTTP_LAB_STATE", str(root))
    monkeypatch.setattr(settings, "HTTP_RESPONSE_LAB_WAFS", {AGENT: LabWaf(
        directory=str(root), disposable_peers={"192.0.2.42", "192.0.2.43"}, protected_peers={"192.0.2.43"})})
    web = Flask(__name__)
    web.secret_key = "isolated-test-only"
    requests = []

    @web.before_request
    def identify():
        g.observation_id = uuid4().hex
        requests.append(g.observation_id)

    install_guard(web)

    @web.post("/login")
    def login():
        return "lab endpoint", 200

    web.add_url_rule("/profile", view_func=lambda: "signed session")
    return web.test_client(), requests, root


def observed_request(web, peer="192.0.2.42", headers=None):
    return web.post("/login", environ_overrides={"REMOTE_ADDR": peer}, headers=headers or {}).status_code


async def seed_probe(factory, request_id, peer="192.0.2.42"):
    from app.services.detection.risk_rules.web_attack_rule import inspect_web_log
    from app.services.detection.behavior_evidence import stable_id
    stamp = datetime.now(timezone.utc)
    key = stable_id("wlog_", AGENT, request_id)
    telemetry = {"request_id": request_id, "evidence_id": key, "method": "POST", "path": "/login", "src_ip": peer,
                 "timestamp": stamp.isoformat(), "service": "flask_web", "payload_indicators": ["sql_boolean_expression"]}
    _, behavior = inspect_web_log(telemetry, AGENT)
    async with factory.begin() as db:
        inc = await db.get(Incident, "inc")
        inc.detection_evidence = {"behavior": behavior}
        db.add(WebAccessLog(id=key, agent_id=AGENT, method="POST", path="/login", timestamp=stamp, status_code=200,
                            user_agent="lab replay", src_ip=peer, raw_message=json.dumps({**telemetry, "source": "normalized_http"})))
    return key


def choose_candidate(monkeypatch):
    async def model(prompt, **kwargs):
        data = json.loads(prompt)
        return {"answer": json.dumps({"action_type": data["candidate"], "evidence_ids": data["evidence_ids"]})}
    monkeypatch.setattr(assist_policy.ai_client, "generate", model)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,expected", [("temporary_ip_block", 403), ("apply_rate_limit", 429)])
async def test_verified_flask_response(lab, guarded_app, monkeypatch, kind, expected):
    import sqlite3
    from app.services.response import lab_waf
    client, factory = lab
    web, requests, root = guarded_app
    assert observed_request(web) == 200
    await seed_probe(factory, requests[-1])
    choose_candidate(monkeypatch)
    response = client.post(PATH, headers=ADMIN, json={"action_type": kind})
    assert response.json()["action_type"] == kind, response.text
    url = "/api/v1/response-actions/" + response.json()["action_id"]
    assert observed_request(web) == 200
    assert client.post(url + "/approve", headers=ADMIN, json={}).status_code == 200
    assert client.post(url + "/execute", headers=ADMIN, json={}).json()["status"] == "verifying"
    if kind == "apply_rate_limit":
        assert [observed_request(web) for _ in range(3)] == [200, 200, 200]
    assert observed_request(web, headers={"X-Forwarded-For": "127.0.0.1"}) == expected
    receipt = requests[-1]
    assert observed_request(web, peer="192.0.2.43") == 200
    result = client.get(url, headers=ADMIN).json()
    assert result["result"]["verification"]["evidence_refs"] == [receipt]
    assert result["status"] == "succeeded"
    with monkeypatch.context() as patch:
        def broken(*args):
            raise sqlite3.OperationalError("private path")
        patch.setattr(lab_waf, "rollback", broken)
        assert client.post(url + "/rollback", headers=ADMIN, json={}).json()["status"] == "rollback_failed"
    assert client.post(url + "/rollback", headers=ADMIN, json={}).json()["status"] == "rolled_back"
    assert observed_request(web) == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("peer,headers", [
    ("192.0.2.43", {}), ("100.67.222.3", {}), ("127.0.0.1", {}),
    ("192.0.2.42", {"X-Forwarded-For": "192.0.2.42"}), ("192.0.2.42", {"CF-Connecting-IP": "192.0.2.42"})])
async def test_unverified_or_protected_peer(lab, guarded_app, peer, headers):
    client, factory = lab
    web, requests, _ = guarded_app
    assert observed_request(web, peer, headers) == 200
    await seed_probe(factory, requests[-1], peer)
    assert client.post(PATH, headers=ADMIN, json={"action_type": "temporary_ip_block"}).status_code == 409


@pytest.mark.asyncio
async def test_grant_correlation(lab, guarded_app, monkeypatch):
    import sqlite3
    import time
    from app.models.auth_event import AuthEvent
    from app.models.event import Event
    from app.services.detection.behavior_evidence import stable_id
    client, factory = lab
    web, requests, root = guarded_app
    observed_request(web)
    rid = requests[-1]
    key = await seed_probe(factory, rid)
    ref = digest("2" * 32)
    auth_id = stable_id("auth_", AGENT, "flask_web", rid)
    async with factory.begin() as db:
        record = await db.get(WebAccessLog, key)
        record.status_code = 302
        record.raw_message = json.dumps({**json.loads(record.raw_message), "session_ref": ref})
        db.add(AuthEvent(id=auth_id, agent_id=AGENT, service="flask_web", source_ip=record.src_ip, status="success",
                         count=1, timestamp=record.timestamp))
        db.add(Event(id=auth_id, agent_id=AGENT, source="AGENT_AUTH", event_type="AUTH_OBSERVATION", details={
            "request_id": rid, "request_method": "POST", "request_path": "/login", "timestamp_source": "application",
            "session_ref": ref}))
    def cls():
        return client.get(PATH, headers=ADMIN).json()["investigation"]["classification"]
    assert cls() == "sqli_exploitation_suspected"
    with sqlite3.connect(root / "observations.db") as db:
        db.execute("INSERT INTO grant_observation VALUES (?,?,?,?,0)", (rid, "192.0.2.42", time.time(), ref))
    assert cls() == "sqli_exploitation_confirmed"
    choose_candidate(monkeypatch)
    url = propose(client)
    assert client.get(url, headers=ADMIN).json()["action_type"] == "revoke_session"
    assert client.post(url + "/approve", headers=ADMIN, json={}).status_code == 200
    assert client.post(url + "/execute", headers=ADMIN, json={}).json()["status"] == "verifying"
    other = web.application.test_client()
    with other.session_transaction() as s:
        s["audit_nonce"] = "1" * 32
    with web.session_transaction() as s:
        s["audit_nonce"] = "2" * 32
    assert web.get("/profile").status_code == 401
    assert other.get("/profile").status_code == 200
    assert client.get(url, headers=ADMIN).json()["status"] == "succeeded"
    async with factory.begin() as db:
        event = await db.get(Event, auth_id)
        event.details = {**event.details, "session_ref": "0" * 64}
    assert cls() == "sqli_probe_observed"


@pytest.mark.asyncio
async def test_conflicting_leases_restart_and_expiry(lab, guarded_app, monkeypatch):
    import asyncio
    import time
    from fastapi import HTTPException
    from app.services.response import lab_waf
    web, _, _ = guarded_app
    now = time.time()
    async def apply(key):
        return await asyncio.to_thread(lab_waf.activate, AGENT, "192.0.2.42", key, now + 300, "temporary_ip_block")
    results = await asyncio.gather(apply("one"), apply("two"), return_exceptions=True)
    assert sum(isinstance(r, HTTPException) for r in results) == 1
    assert observed_request(web) == 403
    # A new Flask instance reopens the durable store; expiry needs no Manager process.
    from flask import Flask
    from response_guard import install_guard
    restarted = Flask("restarted")
    install_guard(restarted)
    restarted.add_url_rule("/login", view_func=lambda: "ok", methods=["POST"])
    assert observed_request(restarted.test_client()) == 403
    monkeypatch.setattr(time, "time", lambda: now + 301)
    assert observed_request(restarted.test_client()) == 200


@pytest.mark.parametrize("kind", ["generate_remediation_guidance", "increase_monitoring"])
def test_manager_actions(lab, monkeypatch, kind):
    client, _ = lab
    choose_candidate(monkeypatch)
    row = client.post(PATH, headers=ADMIN, json={"action_type": kind}).json()
    url = "/api/v1/response-actions/" + row["action_id"]
    if row["requires_approval"]:
        assert client.post(url + "/approve", headers=ADMIN, json={}).status_code == 200
    result = client.post(url + "/execute", headers=ADMIN, json={}).json()
    if kind == "increase_monitoring":
        assert result["status"] == "monitoring"
        assert client.post(url + "/rollback", headers=ADMIN, json={}).json()["status"] == "rolled_back"
    else:
        assert result["result"]["verification"]["evidence_refs"] == [row["action_id"]]
        assert result["status"] == "succeeded"
