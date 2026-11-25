"""Phase 2 comprehensive automated test suite for LARP EDR response execution, verification & RBAC."""
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
from app.models.process_info import ProcessInfo
from app.models.web_access_log import WebAccessLog
from app.services.response import assist_policy
from app.websocket import agent_ws
from test_network_module import AGENT, OTHER, AGENT_TOKEN, ANALYST_TOKEN, ADMIN_TOKEN, digest, header, snapshot, heartbeat

PATH = "/api/v1/incidents/inc/response-proposals"
ADMIN = header(ADMIN_TOKEN)
ANALYST = header(ANALYST_TOKEN)


@pytest.fixture
async def phase2_lab(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'phase2.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory.begin() as db:
        db.add(Agent(id=AGENT, hostname=AGENT, ip_address="192.0.2.1", mac_address="00:00:00:00:00:01"))
        db.add(ProcessInfo(
            id="proc_1234", agent_id=AGENT, pid=1234, parent_pid=1,
            name="suspicious_tool", exe_path="/usr/bin/suspicious_tool",
            process_start_time=1000.0, cmdline="/usr/bin/suspicious_tool --attack",
            is_suspicious=True
        ))
        db.add(WebAccessLog(
            id="wlog_sqli", agent_id=AGENT, method="POST", path="/login", status_code=200,
            src_ip="192.0.2.42", user_agent="sqlmap/1.9.6", timestamp=datetime.now(timezone.utc),
            raw_message=json.dumps({
                "source": "normalized_http", "service": "flask_web", "request_id": "req_123",
                "payload_indicators": ["sql_boolean_expression"]
            })
        ))
        db.add(Incident(
            id="inc", title="HTTP SQLi Incident", risk_score=75, agent_id=AGENT,
            detection_evidence={"behavior": {
                "agent_id": AGENT, "source": "web_access_logs", "evidence_type": "http",
                "evidence_id": "http_group_sqli", "source_event_ids": ["wlog_sqli"]
            }}
        ))

    async def dependency():
        async with factory() as session:
            yield session
            await session.commit()

    async def model(*args, **kwargs):
        return {"answer": json.dumps({"action_type": "collect_additional_evidence",
                                      "evidence_ids": ["http_group_sqli", "wlog_sqli"]})}

    monkeypatch.setattr(assist_policy.ai_client, "generate", model)
    monkeypatch.setattr(settings, "NETWORK_AGENT_TOKENS", {AGENT: digest(AGENT_TOKEN)})
    monkeypatch.setattr(settings, "NETWORK_LEGACY_ADMIN_TOKEN", None)
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {
        "reader": NetworkOperator(role="analyst", agents={AGENT}, token_sha256=digest(ANALYST_TOKEN)),
        "admin": NetworkOperator(role="admin", agents={AGENT}, token_sha256=digest(ADMIN_TOKEN))
    })
    monkeypatch.setattr(agent_ws, "AsyncSessionLocal", factory)
    app.dependency_overrides[get_db] = dependency
    try:
        yield TestClient(app), factory
    finally:
        app.dependency_overrides.pop(get_db)
        await engine.dispose()


def test_legacy_actions_api_authorization_and_actor(phase2_lab):
    """Test that legacy /api/v1/actions requires operator token and binds actor identity."""
    client, _ = phase2_lab

    # 1. Anonymous request is rejected with 401
    r_unauth = client.post("/api/v1/actions", json={
        "agent_id": AGENT, "action_type": "isolate", "action_params": {"confirmed": True}
    })
    assert r_unauth.status_code == 401
    assert "operator" in r_unauth.json()["detail"].lower()

    # 2. Analyst role (read-only) cannot perform write action
    r_analyst = client.post("/api/v1/actions", headers=ANALYST, json={
        "agent_id": AGENT, "action_type": "isolate", "action_params": {"confirmed": True}
    })
    assert r_analyst.status_code == 403

    # 3. Admin operator succeeds and actor identity is derived from token
    r_admin = client.post("/api/v1/actions", headers=ADMIN, json={
        "agent_id": AGENT, "action_type": "isolate", "action_params": {"confirmed": True}
    })
    assert r_admin.status_code == 201
    action_data = r_admin.json()
    action_id = action_data["id"]

    # 4. Undo also requires admin operator authorization
    r_undo_unauth = client.post(f"/api/v1/actions/{action_id}/undo", json={})
    assert r_undo_unauth.status_code == 401

    # Simulate that action reached 'applied' status
    from app.models.response_action import ResponseAction
    _, factory = phase2_lab
    import asyncio
    async def set_applied():
        async with factory.begin() as db:
            act = await db.get(ResponseAction, action_id)
            act.status = "applied"
    asyncio.run(set_applied())

    r_undo_admin = client.post(f"/api/v1/actions/{action_id}/undo", headers=ADMIN, json={})
    assert r_undo_admin.status_code == 200
    assert r_undo_admin.json()["undone_by"] == "admin"


def test_process_kill_authorization_and_safety(phase2_lab):
    """Test that process kill endpoints require operator authorization and verify PID / start time."""
    client, _ = phase2_lab

    # 1. Unauthenticated kill is rejected
    r_unauth = client.post(f"/api/v1/process/{AGENT}/process/1234/kill", json={
        "process_start_time": 1000.0, "exe_path": "/usr/bin/suspicious_tool", "confirmed": True
    })
    assert r_unauth.status_code == 401

    # 2. Start time mismatch (possible PID reuse) is rejected with 409
    r_mismatch = client.post(f"/api/v1/process/{AGENT}/process/1234/kill", headers=ADMIN, json={
        "process_start_time": 900.0, "exe_path": "/usr/bin/suspicious_tool", "confirmed": True
    })
    assert r_mismatch.status_code == 409
    assert "start time mismatch" in r_mismatch.json()["detail"].lower()

    # 3. Verified kill succeeds with admin operator
    r_ok = client.post(f"/api/v1/process/{AGENT}/process/1234/kill", headers=ADMIN, json={
        "process_start_time": 1000.0, "exe_path": "/usr/bin/suspicious_tool", "confirmed": True
    })
    assert r_ok.status_code == 200
    assert r_ok.json()["action_type"] == "kill_process"
    assert r_ok.json()["pid"] == 1234


def test_duplicate_approval_and_duplicate_dispatch(phase2_lab):
    """Test that approving or executing an action multiple times is idempotent and safe."""
    client, _ = phase2_lab
    r_prop = client.post(PATH, headers=ANALYST, json={})
    assert r_prop.status_code == 200
    action_url = f"/api/v1/response-actions/{r_prop.json()['action_id']}"

    # 1. First approval -> approved
    r_app1 = client.post(f"{action_url}/approve", headers=ADMIN, json={})
    assert r_app1.status_code == 200
    assert r_app1.json()["status"] == "approved"

    # 2. Duplicate approval -> idempotent 200 with approved
    r_app2 = client.post(f"{action_url}/approve", headers=ADMIN, json={})
    assert r_app2.status_code == 200
    assert r_app2.json()["status"] == "approved"

    # 3. Execute with connected agent -> dispatched
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        heartbeat(ws)
        r_exec1 = client.post(f"{action_url}/execute", headers=ADMIN, json={})
        assert r_exec1.status_code == 200
        assert r_exec1.json()["status"] == "dispatched"

        # 4. Duplicate execution -> idempotent 200 with dispatched
        r_exec2 = client.post(f"{action_url}/execute", headers=ADMIN, json={})
        assert r_exec2.status_code == 200
        assert r_exec2.json()["status"] == "dispatched"


def test_offline_agent_execution_rejected(phase2_lab):
    """Test that executing network_refresh when Agent is offline returns 409."""
    client, _ = phase2_lab
    r_prop = client.post(PATH, headers=ANALYST, json={})
    action_url = f"/api/v1/response-actions/{r_prop.json()['action_id']}"
    client.post(f"{action_url}/approve", headers=ADMIN, json={})

    # Agent is not connected over websocket
    r_exec = client.post(f"{action_url}/execute", headers=ADMIN, json={})
    assert r_exec.status_code == 409
    assert "agent is offline" in r_exec.json()["detail"].lower()


def test_ack_before_snapshot_reconciliation(phase2_lab):
    """Test out-of-order delivery where ACK arrives before snapshot and reconciles upon snapshot arrival."""
    client, _ = phase2_lab
    r_prop = client.post(PATH, headers=ANALYST, json={})
    action_url = f"/api/v1/response-actions/{r_prop.json()['action_id']}"
    client.post(f"{action_url}/approve", headers=ADMIN, json={})

    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        heartbeat(ws)
        client.post(f"{action_url}/execute", headers=ADMIN, json={})
        command = heartbeat(ws)["network_command"]
        frame = snapshot(command_id=command["command_id"], status="ok")

        # Send ACK FIRST (before snapshot!)
        ws.send_json({"type": "NETWORK_ACK", "payload": {
            "agent_id": AGENT, "schema_version": 1, "command_id": command["command_id"],
            "snapshot_id": frame["snapshot_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(), "status": "success"
        }})
        heartbeat(ws)

        # Now send SNAPSHOT
        ws.send_json({"type": "NETWORK_SNAPSHOT", "payload": frame})
        heartbeat(ws)

    detail = client.get(action_url, headers=ANALYST).json()
    assert detail["status"] == "succeeded"
    verification = detail["result"]["verification"]
    assert verification["status"] == "succeeded"
    assert verification["evidence_refs"] == [frame["snapshot_id"]]
    assert verification["verification_method"] == "authenticated_network_snapshot"
    assert "verification_id" in verification
    assert "observed_at" in verification
    assert "expected_result" in verification
    assert "actual_result" in verification


def test_verification_metadata_schema_fields(phase2_lab):
    """Verify that action verification adheres to the complete Step 5 schema."""
    client, _ = phase2_lab
    r_prop = client.post(PATH, headers=ANALYST, json={})
    action_url = f"/api/v1/response-actions/{r_prop.json()['action_id']}"
    client.post(f"{action_url}/approve", headers=ADMIN, json={})

    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        heartbeat(ws)
        client.post(f"{action_url}/execute", headers=ADMIN, json={})
        command = heartbeat(ws)["network_command"]
        frame = snapshot(command_id=command["command_id"], status="ok")
        ws.send_json({"type": "NETWORK_SNAPSHOT", "payload": frame})
        ws.send_json({"type": "NETWORK_ACK", "payload": {
            "agent_id": AGENT, "schema_version": 1, "command_id": command["command_id"],
            "snapshot_id": frame["snapshot_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(), "status": "success"
        }})
        heartbeat(ws)

    detail = client.get(action_url, headers=ANALYST).json()
    v = detail["result"]["verification"]
    required_keys = [
        "verification_id", "action_id", "verification_method", "observed_at",
        "expected_result", "actual_result", "evidence_refs", "verification_status"
    ]
    for k in required_keys:
        assert k in v, f"Missing verification field: {k}"
    assert v["verification_status"] == "succeeded"
    assert v["action_id"] == r_prop.json()["action_id"]
