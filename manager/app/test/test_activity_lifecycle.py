from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.deps import get_db
from app.models.action_audit_log import ActionAuditLog
from app.models.agent import Agent
from app.models.agent_activity import AgentActivity
from app.models.command import Command
from app.models.event import Event
from app.models.flow import Flow
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.response_action import ResponseAction
from app.routers.v1.dashboard_router import router as dashboard_router
from app.schemas.enums import CommandStatus, IncidentStatus
from app.services.agent.activity import attach_incident_activity, record_sample
from app.services.dashboard.dashboard_service import DashboardService
from app.services.process.process_tree_service import ProcessTreeService
from app.services.rule_engine import RuleEngine
from app.websocket import agent_ws


@pytest.fixture
async def activity_db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'activity.db'}")
    async with engine.begin() as conn:
        for model in (Agent, Incident, AgentActivity, Event, Flow, ProcessInfo, ResponseAction, Command, ActionAuditLog):
            await conn.run_sync(model.__table__.create)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(Agent(id="one", hostname="lab", ip_address="192.0.2.1", mac_address="00:00:00:00:00:00"))
        await session.commit()
    yield factory
    await engine.dispose()


def holder(pid=40, started=100.0, name="bash"):
    return {"pid": pid, "parent_pid": 10, "process_start_time": started, "process_name": name,
            "exe_path": f"/usr/bin/{name}", "socket_fds": [0, 1], "stdio_fds": [0, 1],
            "interactive": True}


def connection(stamp, process=None, src_port=32000):
    return {"src_ip": "100.65.0.1", "src_port": src_port, "dst_ip": "100.65.0.2", "dst_port": 4444,
            "protocol": "TCP", "status": "ESTABLISHED", "direction": "outbound", "inode": "42",
            "holders": [process or holder()], "attribution": "inode_verified", "observed_at": stamp.isoformat(),
            "interfaces": ["tailscale0"], "overlay": "tailscale"}


def sample(stamp, complete=True):
    return {"version": 1, "captured_at": stamp.isoformat(), "complete": complete}


async def report(session, rules, stamp, events, complete=True):
    payload = {"agent_id": "one", "network_connections": events, "activity_sample": sample(stamp, complete)}
    if await record_sample(session, "one", "socket", payload, events):
        await rules.evaluate(payload, session)
    await session.commit()


@pytest.fixture
def rules():
    engine = RuleEngine()
    engine._get_active_rules = AsyncMock(return_value=[])
    return engine


async def test_observed_socket_disappears_and_reordered_reports_are_ignored(activity_db, rules):
    now = datetime.now(timezone.utc) - timedelta(seconds=5)
    async with activity_db() as session:
        event = connection(now)
        await report(session, rules, now, [event])
        incident = (await session.scalars(select(Incident))).one()
        assert (await DashboardService(session).get_summary())["active_behavior"]["id"] == incident.id

        later = now + timedelta(seconds=1)
        await report(session, rules, later, [], complete=False)
        assert (await DashboardService(session).get_summary())["active_behavior"] is None
        await attach_incident_activity(session, [incident])
        assert incident.detection_activity == "unknown"

        later += timedelta(seconds=1)
        await report(session, rules, later, [])
        await report(session, rules, now, [event])
        await attach_incident_activity(session, [incident])
        assert incident.detection_activity == "inactive"
        assert incident.last_seen == now
        assert incident.last_verified == later
        assert incident.status == IncidentStatus.OPEN
        assert (await DashboardService(session).get_summary())["incident_queue"] == 1


async def test_offline_historical_risk_and_canonical_agent_counts(activity_db):
    async with activity_db() as session:
        now = datetime.now(timezone.utc)
        session.add_all([
            Agent(id="old", hostname="lab", ip_address="192.0.2.2", mac_address="00:00:00:00:00:01",
                  last_seen=now - timedelta(minutes=6)),
            Agent(id="retired", hostname="lab", ip_address="192.0.2.3", mac_address="00:00:00:00:00:02",
                  decommissioned_at=now),
            Incident(id="legacy", agent_id="one", title="High Risk Threat Spike",
                     description="Direct connection to C2 port", risk_score=67.1),
            Incident(id="older", agent_id="old", title="Old finding", risk_score=90),
        ])
        await session.commit()
        result = await DashboardService(session).get_summary()
        assert result["health_counts"] == {"online": 1, "offline": 1, "decommissioned": 1}
        assert result["active_behavior"] is None
        assert result["incident_queue"] == 2
        assert result["network_findings"][0]["risk_score"] == 67.1
        assert result["network_findings"][0]["culprit_process"] is None
        history = {item["id"]: item for item in result["incidents"]}
        assert history["legacy"]["detection_activity"] == "historical"
        assert history["older"]["detection_activity"] == "stale"
        assert history["older"]["incident_status"] == "open"
        tree = await ProcessTreeService(session).snapshot("one")
        assert tree["flagged_processes"] == []


async def test_occurrences_dedupe_and_pid_reuse_remains_historical_evidence(activity_db, rules):
    start = datetime.now(timezone.utc) - timedelta(seconds=5)
    async with activity_db() as session:
        for index in range(100):
            stamp = start + timedelta(milliseconds=10 * index)
            await report(session, rules, stamp, [connection(stamp)])
        old = (await session.scalars(select(Incident))).one()
        assert old.detection_evidence["observations"] == 100

        later = start + timedelta(seconds=2)
        new = holder(started=105.0)
        await report(session, rules, later, [connection(later, new), connection(later, holder(pid=41), src_port=32001)])
        assert await session.scalar(select(func.count()).select_from(Incident)) == 3

        sample_time = later + timedelta(milliseconds=250)
        payload = {"activity_sample": sample(sample_time)}
        await record_sample(session, "one", "process", payload, [new])
        session.add(ProcessInfo(id="new-proc", agent_id="one", pid=40, parent_pid=10, name="bash",
                                process_start_time=105.0, is_suspicious=True))
        await session.commit()
        await attach_incident_activity(session, [old])
        assert old.process_activity == "exited"
        assert old.detection_evidence["process"]["process_start_time"] == 100.0
        tree = await ProcessTreeService(session).snapshot("one")
        assert [item["process_start_time"] for item in tree["flagged_processes"]] == [105.0]


async def test_http_refresh_is_read_only_and_snapshots_resync(activity_db, rules):
    app = FastAPI()
    app.include_router(dashboard_router)

    async def database():
        async with activity_db() as session:
            yield session

    app.dependency_overrides[get_db] = database
    now = datetime.now(timezone.utc) - timedelta(seconds=3)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        async with activity_db() as session:
            await report(session, rules, now, [connection(now, holder(name="tailscaled"))])
        snapshot = (await client.get("/summary")).json()
        assert snapshot["incident_queue"] == 0
        async with activity_db() as session:
            later = now + timedelta(seconds=1)
            await report(session, rules, later, [connection(later)])
        for _ in range(3):
            refreshed = (await client.get("/summary")).json()
            assert refreshed["incident_queue"] == 1
            assert refreshed["active_behavior"]["detection_activity"] == "active"


async def test_transient_database_failure_keeps_last_committed_observation(activity_db, rules, monkeypatch):
    now = datetime.now(timezone.utc) - timedelta(seconds=3)
    async with activity_db() as session:
        await report(session, rules, now, [connection(now)])
    scorer = MagicMock()
    scorer.process_risk = AsyncMock(side_effect=RuntimeError("database unavailable"))
    monkeypatch.setattr(agent_ws, "RiskAssessmentService", lambda _: scorer)
    monkeypatch.setattr(agent_ws, "rule_engine", rules)
    async with activity_db() as session:
        session.info["defer_incident_events"] = True
        with pytest.raises(RuntimeError, match="database unavailable"):
            await agent_ws._handle_telemetry_risk("one", {"payload": {
                "activity_sample": sample(now + timedelta(seconds=1)), "network_connections": [],
            }}, session)
        await session.rollback()
    async with activity_db() as session:
        result = await DashboardService(session).get_summary()
        assert result["active_behavior"]["detection_activity"] == "active"
        assert result["incident_queue"] == 1


async def test_verified_kill_marks_contained_only_for_matching_process(activity_db, rules):
    now = datetime.now(timezone.utc) - timedelta(seconds=3)
    async with activity_db() as session:
        await report(session, rules, now, [connection(now)])
        incident = (await session.scalars(select(Incident))).one()
        action = ResponseAction(id="a", agent_id="one", incident_id=incident.id, action_type="kill_process_tree",
                                status="pending", action_params={"command_id": "cmd"})
        command = Command(id="cmd", agent_id="one", action="kill_process_tree_verified", status=CommandStatus.SENT,
                          payload={"action_id": "a", **holder()})
        session.add_all([action, command])
        await session.commit()
        await agent_ws._handle_command_ack("one", {"payload": {
            "command_id": "cmd", "status": "success", "validation": "validated", "killed_pids": [40],
        }}, session)
        await session.commit()
        await attach_incident_activity(session, [incident])
        assert action.status == "applied"
        assert incident.status == IncidentStatus.CONTAINED
        assert incident.resolved_at is None
        assert incident.process_activity == "exited"
        assert incident.detection_activity == "unknown"


async def test_reappearance_creates_a_new_episode_in_the_same_window(activity_db, rules):
    start = datetime.now(timezone.utc) - timedelta(seconds=4)
    async with activity_db() as session:
        await report(session, rules, start, [connection(start)])
        await report(session, rules, start + timedelta(seconds=1), [])
        latest = start + timedelta(seconds=2)
        await report(session, rules, latest, [connection(latest)])
        incident = (await session.scalars(select(Incident))).one()
        assert incident.detection_evidence["episodes"] == 2
        assert incident.detection_evidence["observations"] == 2
        assert (await DashboardService(session).get_summary())["active_incidents"] == 1


def test_additive_migration_is_repeatable_and_preserves_legacy_rows():
    from sqlalchemy import create_engine, inspect, text
    from app.initializers.init_db import ensure_activity_schema

    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE agents (id VARCHAR(64) PRIMARY KEY)"))
        connection.execute(text(
            "CREATE TABLE incidents (id VARCHAR(64) PRIMARY KEY, agent_id VARCHAR(64), status TEXT, "
            "created_at DATETIME, updated_at DATETIME, risk_score FLOAT)"
        ))
        connection.execute(text("INSERT INTO agents VALUES ('legacy')"))
        connection.execute(text("INSERT INTO incidents (id, agent_id, status, risk_score) VALUES ('old', 'legacy', 'OPEN', 67.1)"))
        ensure_activity_schema(connection)
        ensure_activity_schema(connection)
        assert connection.execute(text("SELECT status, risk_score, fingerprint FROM incidents")).one() == ("OPEN", 67.1, None)
        assert inspect(connection).has_table("agent_activity")
