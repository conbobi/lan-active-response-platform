"""Network API/WebSocket tests with an isolated SQLite database."""
from datetime import datetime, timedelta, timezone
import hashlib

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.websockets import WebSocketDisconnect

from app.core.config import NetworkOperator, settings
from app.core.deps import get_session
from app.main import app
from app.models.agent import Agent
from app.models.base import Base
from app.models.command import Command
from app.models.network_snapshot import NetworkSnapshot
from app.schemas.enums import CommandStatus
from app.services.agent import network_service, ssh_probe
from app.websocket import agent_ws

AGENT = "aws-test"
OTHER = "other-test"
AGENT_TOKEN = "agent-token-" + "x" * 38
ANALYST_TOKEN = "reader-token-" + "x" * 38
ADMIN_TOKEN = "admin-token-" + "x" * 38
LEGACY_TOKEN = "legacy-token-" + "x" * 38
SNAPSHOT_ID = "e" * 32


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def header(token):
    return {"Authorization": f"Bearer {token}"}


def route(section, agent=AGENT):
    return f"/api/v1/network/agents/{agent}/{section}"


def snapshot(**kwargs):
    timestamp = datetime.now(timezone.utc).isoformat()
    return {"agent_id": AGENT, "schema_version": 1, "timestamp": timestamp, "collected_at": timestamp,
            "snapshot_id": SNAPSHOT_ID, "platform": "linux", "status": "ok", "sections": {
                "firewall": {"provider": "ufw", "status": "active", "controls_configured": True, "safety_version": 2, "rules": []},
                "ports": {"rows": [{"src_ip": "0.0.0.0", "src_port": 22, "protocol": "TCP"}], "total": 1},
                "overview": {"firewall_status": "active", "external_reachability": "unverified",
                             "aws_security_group": "Unknown / Not integrated"},
            }, **kwargs}


@pytest.fixture
async def network_client(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'integration.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory.begin() as session:
        for agent_id in (AGENT, OTHER):
            session.add(Agent(id=agent_id, hostname=agent_id, ip_address="192.0.2.1", mac_address="00:00:00:00:00:00"))

    async def session_dependency():
        async with factory.begin() as session:
            yield session

    app.dependency_overrides[get_session] = session_dependency
    monkeypatch.setattr(agent_ws, "AsyncSessionLocal", factory)
    monkeypatch.setattr(settings, "NETWORK_AGENT_TOKENS", {AGENT: digest(AGENT_TOKEN), OTHER: digest("a" * 40)})
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {
        "analyst-a": NetworkOperator(role="analyst", agents={AGENT}, token_sha256=digest(ANALYST_TOKEN)),
        "admin-a": NetworkOperator(role="admin", agents={AGENT}, token_sha256=digest(ADMIN_TOKEN)),
    })
    monkeypatch.setattr(settings, "NETWORK_LEGACY_ADMIN_TOKEN", digest(LEGACY_TOKEN))
    monkeypatch.setattr(ssh_probe, "configured", lambda agent_id: agent_id == AGENT)
    try:
        yield TestClient(app), factory
    finally:
        app.dependency_overrides.pop(get_session, None)
        await engine.dispose()


def heartbeat(ws):
    ws.send_json({"type": "HEARTBEAT", "payload": {"agent_id": AGENT, "hostname": AGENT, "platform": "linux",
                                                    "firewall_safety_version": 2}})
    response = ws.receive_json()
    assert response["status"] == "ack", response
    return response


def test_unauthorized_operator_and_legacy_bypass(network_client):
    client, _ = network_client
    assert client.get(route("overview")).status_code == 401
    assert client.get(route("overview", OTHER), headers=header(ADMIN_TOKEN)).status_code == 403
    operation = {"operation": "disable", "reason": "Maintenance", "confirmed": True}
    assert client.post(route("firewall/actions"), headers=header(ANALYST_TOKEN), json=operation).status_code == 403
    assert client.post(route("firewall/actions", OTHER), headers=header(ADMIN_TOKEN), json=operation).status_code == 403
    assert client.post("/api/v1/commands/", json={"action": "network_firewall"}).status_code == 401
    assert client.post("/api/v1/commands/", headers=header(ADMIN_TOKEN),
                       json={"action": "unisolate", "agent_id": OTHER}).status_code == 401
    result = client.post("/api/v1/commands/", headers=header(LEGACY_TOKEN),
                         json={"id": "injection-test", "agent_id": AGENT, "action": "network_firewall", "payload": {}})
    assert result.status_code == 400


@pytest.mark.parametrize("params", [
    {"operation": "add_rule", "protocol": "tcp", "port": 0, "action": "allow"},
    {"operation": "add_rule", "protocol": "tcp", "port": 65536, "action": "allow"},
    {"operation": "add_rule", "protocol": "tcp", "port": 22, "action": "allow", "source": "192.0.2.1;whoami"},
    {"operation": "add_rule", "protocol": "tcp", "port": 22, "action": "allow", "interface": "ens5&&id"},
    {"operation": "enable", "command": "ufw enable"},
    {"operation": "enable", "confirmed": 1},
])
def test_invalid_operation_is_rejected_before_dispatch(network_client, params):
    client, _ = network_client
    assert client.post(route("firewall/actions"), headers=header(ADMIN_TOKEN),
                       json={"confirmed": True, "reason": "Test", **params}).status_code == 422


async def test_offline_stale_and_platform(network_client):
    client, factory = network_client
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    async with factory.begin() as session:
        session.add(NetworkSnapshot(agent_id=AGENT, received_at=old, payload=snapshot()))
    response = client.get(route("overview"), headers=header(ANALYST_TOKEN)).json()
    assert response["online"] is False and response["stale"] is True
    assert response["data"]["external_reachability"] == "unverified"
    assert response["data"]["aws_security_group"] == "Unknown / Not integrated"
    assert client.post(route("refresh"), headers=header(ANALYST_TOKEN)).status_code == 409
    async with factory.begin() as session:
        row = await session.get(NetworkSnapshot, AGENT)
        row.payload = snapshot(platform="windows", status="unsupported", sections={})
    result = client.get(route("overview"), headers=header(ANALYST_TOKEN)).json()
    assert result["status"] == "unsupported"
    assert result["data"] == {}


def test_agent_identity_binding(network_client):
    client, _ = network_client
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/agent?agent_id={AGENT}"):
            pytest.fail("Agent without a token was admitted")
    with client.websocket_connect("/ws/agent?agent_id=not-enrolled") as ws:
        ws.send_json({"type": "HEARTBEAT", "payload": {"agent_id": AGENT}})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    assert client.get(route("probe"), headers={"x-larp-agent-token": AGENT_TOKEN}).status_code == 204
    assert client.get(route("probe", OTHER), headers={"x-larp-agent-token": AGENT_TOKEN}).status_code == 401


def test_websocket_inventory_and_verified_control_audit(network_client):
    client, _ = network_client
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        heartbeat(ws)
        ws.send_json({"type": "NETWORK_SNAPSHOT", "payload": snapshot()})
        heartbeat(ws)
        port_response = client.get(route("ports"), params={"port": 22}, headers=header(ANALYST_TOKEN)).json()
        assert port_response["online"] and port_response["data"]["rows"][0]["src_ip"] == "0.0.0.0"
        queued = client.post(route("firewall/actions"), headers=header(ADMIN_TOKEN),
                             json={"operation": "disable", "confirmed": True, "reason": "Maintenance"})
        assert queued.status_code == 202, queued.text
        command_id = queued.json()["command_id"]
        commands = heartbeat(ws)
        assert commands["pending_commands"] == []
        assert commands["network_command"]["command_id"] == command_id
        assert heartbeat(ws)["network_command"] is None
        ack = {"agent_id": AGENT, "schema_version": 1, "command_id": command_id,
               "snapshot_id": "c" * 32, "timestamp": datetime.now(timezone.utc).isoformat(),
               "status": "success", "transaction": {"id": command_id, "status": "awaiting_commit",
                                                       "before": {"status": "active"}, "after": {"status": "inactive"}}}
        ws.send_json({"type": "NETWORK_ACK", "payload": ack})
        heartbeat(ws)
        assert client.get(route(f"commands/{command_id}"), headers=header(ANALYST_TOKEN)).json()["status"] == "sent"
        frame = snapshot(command_id=command_id, snapshot_id="c" * 32)
        frame["sections"]["firewall"]["status"] = "inactive"
        ws.send_json({"type": "NETWORK_SNAPSHOT", "payload": frame})
        ws.send_json({"type": "NETWORK_ACK", "payload": ack})
        heartbeat(ws)
        assert client.get(route(f"commands/{command_id}"), headers=header(ANALYST_TOKEN)).json()["status"] == "success"
        audit = client.get(route("audit"), headers=header(ANALYST_TOKEN)).json()["data"]["rows"][0]
        assert audit["parameters"]["operator"] == "admin-a"
        assert audit["parameters"]["reason"] == "Maintenance"
        assert audit["status"] == "rollback_scheduled"
        assert audit["result"]["agent_result"]["before"]["status"] == "active"
        ws.send_json({"type": "NETWORK_TRANSACTION", "payload": {
            "agent_id": AGENT, "schema_version": 1, "timestamp": datetime.now(timezone.utc).isoformat(),
            "transaction": {**ack["transaction"], "status": "rolled_back", "after": {"status": "active"}},
        }})
        heartbeat(ws)
        assert client.get(route("audit"), headers=header(ANALYST_TOKEN)).json()["data"]["rows"][0]["status"] == "reverted"


async def test_expired_command_is_never_delivered(network_client):
    client, factory = network_client
    stale = "a" * 32
    async with factory.begin() as session:
        session.add(Command(id=stale, agent_id=AGENT, action=network_service.REFRESH,
                            issued_at=datetime.now(timezone.utc) - timedelta(minutes=3), max_retries=0))
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        assert heartbeat(ws)["network_command"] is None
    async with factory() as session:
        command = await session.scalar(select(Command).where(Command.id == stale))
        assert command.status == CommandStatus.TIMEOUT


def test_ssh_probe_requires_enrolled_live_agent_and_checks_recovery(network_client, monkeypatch):
    client, _ = network_client
    assert client.get(route("ssh-probe"), headers=header(ADMIN_TOKEN)).status_code == 401
    identity = {"x-larp-agent-token": AGENT_TOKEN}
    assert client.get(route("ssh-probe"), headers=identity).status_code == 503

    async def fresh_probe(agent_id):
        assert agent_id == AGENT
        return {"source": "192.0.2.9", "endpoint": "192.0.2.10", "port": 2222}

    monkeypatch.setattr(ssh_probe, "verify", fresh_probe)
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers=identity) as ws:
        heartbeat(ws)
        assert client.get(route("ssh-probe"), headers=identity).json()["port"] == 2222
        monkeypatch.setattr(ssh_probe, "configured", lambda _: False)
        result = client.post(route("firewall/actions"), headers=header(ADMIN_TOKEN),
                             json={"operation": "enable", "confirmed": True, "reason": "Maintenance"})
        assert result.status_code == 503
        for direction in ("incoming", "outgoing"):
            result = client.post(route("firewall/actions"), headers=header(ADMIN_TOKEN), json={
                "operation": "set_policy", "direction": direction, "action": "deny",
                "confirmed": True, "reason": "Maintenance",
            })
            assert result.status_code == 409


async def test_old_firewall_commands_are_never_replayed(network_client):
    client, factory = network_client
    async with factory.begin() as session:
        session.add(Command(id="b" * 32, agent_id=AGENT, action=network_service.FIREWALL,
                            issued_at=datetime.now(timezone.utc), max_retries=0, payload={
                                "params": {"operation": "enable"},
                            }))
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        assert heartbeat(ws)["network_command"] is None
    async with factory() as session:
        cmd = await session.get(Command, "b" * 32)
        assert cmd.status == CommandStatus.FAILED
        assert "obsolete" in cmd.error_message
