"""
Comprehensive regression tests for:
1. Process Kill Authorization (Unified Operator & Legacy Admin Token).
2. Process Protection (SSH, systemd, Agent, PID <= 2, PID reuse, offline agent).
3. Status verification (Queued action must remain 'pending' until Agent ACK).
4. DB Connection Pool metrics instrumentation and session release during AI triage.
"""
import hashlib
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import NetworkOperator, settings
from app.core.database import get_db, get_pool_status
from app.core.deps import get_session
from app.main import app
from app.models.agent import Agent, AgentStatus
from app.models.base import Base
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.response_action import ResponseAction
from app.services.ai.ai_triage_service import AITriageService

AGENT_ID = "ip-test-agent"
ADMIN_TOKEN = "admin-secret-token-" + "x" * 30
ANALYST_TOKEN = "analyst-secret-token-" + "x" * 28
LEGACY_TOKEN = "legacy-admin-token-" + "x" * 30


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def setup_test_env(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test_edr.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_session] = override_get_db

    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {
        "soc-admin": NetworkOperator(role="admin", agents={AGENT_ID}, token_sha256=digest(ADMIN_TOKEN)),
        "soc-reader": NetworkOperator(role="analyst", agents={AGENT_ID}, token_sha256=digest(ANALYST_TOKEN)),
    })
    monkeypatch.setattr(settings, "NETWORK_LEGACY_ADMIN_TOKEN", digest(LEGACY_TOKEN))

    # Seed test agent
    async with factory() as session:
        agent = Agent(
            id=AGENT_ID,
            hostname="test-host",
            ip_address="192.168.1.100",
            mac_address="00:11:22:33:44:55",
            status=AgentStatus.ACTIVE,
            last_seen=datetime.now(timezone.utc),
        )
        session.add(agent)

        # Seed standard target process
        target_proc = ProcessInfo(
            id="proc-target-1234",
            agent_id=AGENT_ID,
            pid=1234,
            parent_pid=1,
            name="malware.bin",
            exe_path="/tmp/malware.bin",
            cmdline="/tmp/malware.bin --listen 4444",
            process_start_time=1700000000.0,
            is_suspicious=True,
            created_at=datetime.now(timezone.utc),
        )
        session.add(target_proc)

        # Seed critical system processes (sshd and agent)
        sshd_proc = ProcessInfo(
            id="proc-sshd-600",
            agent_id=AGENT_ID,
            pid=600,
            parent_pid=1,
            name="sshd",
            exe_path="/usr/sbin/sshd",
            cmdline="/usr/sbin/sshd -D",
            process_start_time=1690000000.0,
            is_suspicious=False,
            created_at=datetime.now(timezone.utc),
        )
        session.add(sshd_proc)

        agent_proc = ProcessInfo(
            id="proc-agent-800",
            agent_id=AGENT_ID,
            pid=800,
            parent_pid=1,
            name="python3",
            exe_path="/usr/bin/python3",
            cmdline="python3 /opt/larp/agent.py",
            process_start_time=1690000000.0,
            is_suspicious=False,
            created_at=datetime.now(timezone.utc),
        )
        session.add(agent_proc)

        await session.commit()

    try:
        yield TestClient(app), factory
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_session, None)
        await engine.dispose()


def test_kill_process_authentication_and_authorization(setup_test_env):
    """Test unified auth allows soc-admin and legacy admin, rejects analyst and unauthenticated."""
    client, _ = setup_test_env
    kill_url = f"/api/v1/process/{AGENT_ID}/process/1234/kill"

    # 1. Missing Authorization header -> 401
    resp = client.post(kill_url, json={"confirmed": True})
    assert resp.status_code == 401
    assert "required" in resp.json().get("detail", "").lower()

    # 2. Invalid Bearer Token -> 401
    resp = client.post(kill_url, headers=auth_header("invalid-token-12345678901234567890"), json={"confirmed": True})
    assert resp.status_code == 401

    # 3. Analyst operator (read-only) -> 403 Forbidden
    resp = client.post(kill_url, headers=auth_header(ANALYST_TOKEN), json={"confirmed": True})
    assert resp.status_code == 403
    assert "admin" in resp.json().get("detail", "").lower()

    # 4. Legacy Admin Token -> 200 OK (accepted)
    resp = client.post(kill_url, headers=auth_header(LEGACY_TOKEN), json={"confirmed": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["pid"] == 1234
    assert data["status"] == "pending"  # Crucial: never applied immediately

    # 5. Operator Admin Token (soc-admin) -> 200 OK (accepted)
    resp = client.post(kill_url, headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["pid"] == 1234
    assert data["status"] == "pending"


def test_kill_process_validation_rules(setup_test_env):
    """Test process validation: PID <= 2, offline agent, not found, PID reuse."""
    client, factory = setup_test_env

    # 1. PID <= 2 rejection (PID 1 systemd or PID 2 kthreadd)
    resp = client.post(f"/api/v1/process/{AGENT_ID}/process/1/kill", headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code == 400
    assert "greater than 2" in resp.json().get("detail", "")

    resp = client.post(f"/api/v1/process/{AGENT_ID}/process/2/kill", headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code == 400

    # 2. Process not found on agent -> 404
    resp = client.post(f"/api/v1/process/{AGENT_ID}/process/9999/kill", headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code == 404
    assert "not found" in resp.json().get("detail", "").lower()

    # 3. PID reuse check (start time mismatch) -> 409
    resp = client.post(
        f"/api/v1/process/{AGENT_ID}/process/1234/kill",
        headers=auth_header(ADMIN_TOKEN),
        json={"confirmed": True, "process_start_time": 1800000000.0}  # ground truth in DB is 1700000000.0
    )
    assert resp.status_code == 409
    assert "start time mismatch" in resp.json().get("detail", "").lower()


def test_kill_process_critical_protection(setup_test_env):
    """Test protection against killing SSH daemon and Agent binary."""
    client, _ = setup_test_env

    # 1. Attempting to kill sshd (PID 600) -> rejected by agent_protection
    resp = client.post(f"/api/v1/process/{AGENT_ID}/process/600/kill", headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code in (400, 403)
    error_msg = resp.json().get("detail", "") or resp.json().get("error", "")
    assert "critical system service" in error_msg.lower() or "protected" in error_msg.lower()

    # 2. Attempting to kill agent process (PID 800) -> rejected
    resp = client.post(f"/api/v1/process/{AGENT_ID}/process/800/kill", headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code in (400, 403)
    error_msg = resp.json().get("detail", "") or resp.json().get("error", "")
    assert "larp agent" in error_msg.lower() or "protected" in error_msg.lower()


@pytest.mark.asyncio
async def test_kill_process_offline_agent(setup_test_env):
    """Test rejection when agent is marked DEAD / offline."""
    client, factory = setup_test_env
    # Mark agent as DEAD
    async with factory() as session:
        agent = await session.get(Agent, AGENT_ID)
        agent.status = AgentStatus.DEAD
        await session.commit()

    resp = client.post(f"/api/v1/process/{AGENT_ID}/process/1234/kill", headers=auth_header(ADMIN_TOKEN), json={"confirmed": True})
    assert resp.status_code == 409
    assert "offline" in resp.json().get("detail", "").lower()


def test_db_pool_metrics_and_health(setup_test_env):
    """Test database pool metrics endpoint and health check."""
    client, _ = setup_test_env

    # 1. Direct function call
    metrics = get_pool_status()
    assert "pool_size" in metrics
    assert "checked_out_connections" in metrics
    assert "overflow" in metrics
    assert "total_active_connections" in metrics

    # 2. Health check endpoint
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "database_pool" in data
    assert "checked_out_connections" in data["database_pool"]

    # 3. Dedicated system pool endpoint
    resp = client.get("/api/v1/system/db-pool")
    assert resp.status_code == 200
    data = resp.json()
    assert "pool_size" in data
    assert "checked_in_connections" in data


@pytest.mark.asyncio
async def test_ai_triage_decoupled_db_session(tmp_path, monkeypatch):
    """Test that AI triage decouples DB read and write and does not leak DB sessions during LLM calls."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ai_triage.db'}", pool_size=5, max_overflow=0)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed incident
    inc_id = "inc-test-101"
    async with factory() as session:
        session.add(Agent(id="agent-01", hostname="agent-01", ip_address="10.0.0.1", mac_address="00:00:00:00:00:01"))
        session.add(Incident(
            id=inc_id,
            agent_id="agent-01",
            title="Suspicious Netcat Outbound",
            description="Process nc opened outbound connection to external IP",
            risk_score=75,
            status="open",
            created_at=datetime.now(timezone.utc),
        ))
        await session.commit()

    # Monkeypatch AsyncSessionLocal for AITriageService
    from app.services.ai import ai_triage_service
    monkeypatch.setattr(ai_triage_service, "AsyncSessionLocal", factory)

    # Mock ai_client.generate to simulate latency while checking checked-out pool connections
    async def mock_generate(*args, **kwargs):
        # Verify that during the LLM call, checked out connections from the engine pool is 0!
        checked_out = engine.pool.checkedout()
        assert checked_out == 0, f"Expected 0 checked-out connections during LLM call, got {checked_out}!"
        return {
            "answer": '{"classification": "likely_malicious", "summary": "Phát hiện netcat đáng ngờ", "mitre_techniques": [], "root_cause": "Reverse shell", "confidence": 0.85}'
        }

    monkeypatch.setattr(ai_triage_service.ai_client, "generate", mock_generate)

    # Run AI triage with session=None (short sessions mode)
    service = AITriageService()
    analysis = await service.analyze_incident(inc_id)

    assert analysis is not None
    assert analysis.incident_id == inc_id
    assert "Phát hiện netcat đáng ngờ" in analysis.summary
    assert analysis.confidence == 0.85

    # Verify all pool connections returned to pool
    assert engine.pool.checkedout() == 0

    await engine.dispose()
