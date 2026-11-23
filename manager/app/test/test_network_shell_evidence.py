from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.initializers.init_db import ensure_network_evidence_columns
from app.models.agent import Agent
from app.models.flow import Flow
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.incident import IncidentOut
from app.services.detection.network_reputation_service import NetworkReputationService
from app.services.detection.network_shell import RULE_ID, detect_network_shell
from app.services.detection.risk_assessment_service import RiskAssessmentService
from app.services.detection.risk_rules.c2_communication_rule import C2CommunicationRule
from app.services.detection.risk_rules.network_connection_rule import NetworkConnectionRule
from app.services.detection.risk_rules.registry import RiskRuleRegistry
from app.services.incident.incident_service import IncidentService
from app.services.incident.incident_timeline_service import IncidentTimelineService
from app.services.rule_engine import RuleEngine
from app.websocket import agent_ws


def process(pid=809, parent=808, name="bash", **fields):
    return {"pid": pid, "parent_pid": parent, "process_name": name, "exe_path": f"/usr/bin/{name}",
            "process_start_time": float(pid), "uid": 1000, **fields}


def event(*holders, **fields):
    return {
        "src_ip": "100.96.0.18", "src_port": 52919, "dst_ip": "100.96.0.19", "dst_port": 4444,
        "protocol": "TCP", "status": "ESTABLISHED", "direction": "unknown", "inode": "1023",
        "attribution": "inode_verified", "holders": list(holders), "overlay": "tailscale",
        "interfaces": ["tailscale0"], "originator_pid": None, "observed_at": "2026-01-01T10:00:00+00:00", **fields,
    }


@pytest.mark.parametrize("observation", [
    event(process(name="tailscaled"), overlay=None, interfaces=["eth0"], dst_port=443),
    event(process(name="tailscaled"), protocol="UDP", dst_port=3478),
    event(process(name="sshd"), direction="inbound", dst_port=53129),
    event(process(name="python3"), direction="inbound", src_port=5000),
    event(process(name="cloudflared"), overlay=None, dst_port=443),
    event(process(name="curl"), direction="outbound"),
    event(process(pty_requested=True), attribution="unverified_socket"),
    event(process(interactive=True, socket_fds=[7], stdio_fds=[])),
    event(),
])
def test_baselines_and_unverified_connections_do_not_match(observation):
    assert detect_network_shell(observation) is None


def test_stdio_confidence_is_independent_of_port_and_keeps_related_processes():
    parent = process(808, 807, "bash")
    python = process(810, 809, "python3", pty_requested=True)
    child = process(811, 810, "bash")
    shell = process(socket_fds=[0, 1, 2], stdio_fds=[0, 1, 2], interactive=True,
                    ancestry=[parent], descendants=[python, child])
    helper = process(810, 809, "python3", socket_fds=[7])
    result = detect_network_shell(event(shell, helper, dst_port=29090))
    assert result["classification"] == "High-Confidence Reverse Shell"
    assert result["process"]["pid"] == 809
    assert result["process"]["parent_pid"] == 808
    assert [p["pid"] for p in result["descendants"]] == [810, 811]
    assert result["network"]["pid"] == 809
    assert result["network"]["originator_pid"] is None
    assert result["network"]["overlay"] == "tailscale"
    assert [p["pid"] for p in result["network"]["holders"]] == [809, 810]
    assert NetworkReputationService.get_reputation("100.96.0.19")["category"] == "shared_cgnat"


def test_shared_evidence_never_implies_initiator_or_unique_culprit():
    shell = process(socket_fds=[0, 1], stdio_fds=[0, 1], interactive=True)
    peer = process(810, 809, socket_fds=[0, 1], stdio_fds=[0, 1], interactive=True)
    result = detect_network_shell(event(shell, peer))
    assert result["process"] is None
    assert result["network"]["pid"] is None
    assert result["network"]["originator_pid"] is None
    assert len(result["network"]["holders"]) == 2


def test_partial_evidence_is_suspected_and_inbound_is_excluded():
    shell = process(socket_fds=[0, 1], stdio_fds=[0, 1])
    match = detect_network_shell(event(shell))
    assert match["classification"] == "Suspected Reverse Shell"
    assert match["risk_score"] == 66
    assert match["confidence"] < 0.7
    assert detect_network_shell(event(shell, direction="inbound")) is None


@pytest.mark.asyncio
async def test_port_score_is_weak_and_correlation_counts_the_socket_once():
    registry = RiskRuleRegistry()
    registry.register(NetworkConnectionRule())
    registry.register(C2CommunicationRule())
    service = RiskAssessmentService(MagicMock(), registry)
    service.detection_rule_service.sync_registry = AsyncMock()
    service.threat_intel_service.check_ip = AsyncMock()
    common = event(process(name="curl"))
    score, factors = await service.evaluate("a", {"network_connections": [common, common]})
    assert score == 6
    assert set(factors["_scores"]) == {"network_connection"}
    service.threat_intel_service.check_ip.assert_not_awaited()

    strong = event(process(stdio_fds=[0, 1], socket_fds=[0, 1], interactive=True))
    score, factors = await service.evaluate("a", {"network_connections": [strong, strong]})
    assert score == detect_network_shell(strong)["risk_score"]
    assert set(factors["_scores"]) == {RULE_ID}


class DatabaseSession:
    def __init__(self, session):
        self.session = session
        self.add = session.add
        self.add_all = session.add_all

    async def execute(self, stmt):
        return self.session.execute(stmt)

    async def commit(self):
        self.session.commit()

    async def flush(self):
        self.session.flush()

    async def refresh(self, entity):
        self.session.refresh(entity)

    async def get(self, model, key):
        return self.session.get(model, key)


@pytest.mark.asyncio
async def test_websocket_incident_round_trip_and_sliding_aggregation(monkeypatch):
    engine = create_engine("sqlite://")
    for model in (Agent, Incident, Flow, ResponseAction):
        model.__table__.create(engine)
    with Session(engine) as database:
        database.add(Agent(id="a", hostname="victim", ip_address="192.0.2.1", mac_address="00:00:00:00:00:00"))
        database.commit()
        session = DatabaseSession(database)
        rules = RuleEngine()
        monkeypatch.setattr(rules, "_get_active_rules", AsyncMock(return_value=[]))
        monkeypatch.setattr(agent_ws, "rule_engine", rules)
        monkeypatch.setattr(agent_ws, "_run_ai_triage", AsyncMock())
        monkeypatch.setattr(agent_ws.dashboard_manager, "broadcast", AsyncMock())
        scorer = MagicMock()
        scorer.process_risk = AsyncMock(return_value=MagicMock(incident=None, score=73))
        monkeypatch.setattr(agent_ws, "RiskAssessmentService", lambda _: scorer)

        shell = process(socket_fds=[0, 1], stdio_fds=[0, 1])
        first = event(shell)
        await agent_ws._handle_telemetry_risk("a", {"payload": {"network_connections": [first]}}, session)
        original = database.scalars(select(Incident)).one()
        assert original.detection_evidence["classification"] == "Suspected Reverse Shell"
        original.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        database.commit()

        verified = event({**shell, "interactive": True}, observed_at="2026-01-01T10:00:15+00:00")
        for _ in range(2):
            await agent_ws._handle_telemetry_risk("a", {"payload": {"network_connections": [verified]}}, session)
        database.expire_all()
        stored = database.scalars(select(Incident)).one()
        assert stored.detection_evidence["observations"] == 2
        incident = IncidentOut.model_validate(await IncidentService(session)._enrich_incident(stored))
        assert incident.risk_score == 73
        assert incident.culprit_process["pid"] == 809
        assert incident.network_indicators[0]["src_port"] == 52919
        flow = database.scalars(select(Flow)).first()
        assert flow.socket_evidence["holders"][0]["parent_pid"] == 808
        assert flow.socket_evidence["originator_pid"] is None
        assert incident.detection_evidence["classification"] == "High-Confidence Reverse Shell"
        timeline = await IncidentTimelineService(session).build_timeline(stored.id)
        assert any(item["type"] == "network_connection" and item["details"]["inode"] == "1023"
                   for item in timeline["timeline"])
        agent_ws.dashboard_manager.broadcast.assert_awaited_once()

        different = event({**shell, "process_start_time": 900.0}, src_port=53000)
        await agent_ws._handle_telemetry_risk("a", {"payload": {"network_connections": [different]}}, session)
        assert len(database.scalars(select(Incident)).all()) == 2


def test_evidence_column_migration_preserves_existing_rows():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE incidents (id TEXT PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE flows (id TEXT PRIMARY KEY)"))
        connection.execute(text("INSERT INTO incidents (id) VALUES ('old')"))
        ensure_network_evidence_columns(connection)
        ensure_network_evidence_columns(connection)
        assert connection.execute(text("SELECT id, detection_evidence FROM incidents")).one() == ("old", None)


@pytest.mark.asyncio
async def test_response_rejects_auto_isolation_and_missing_target():
    from app.core.exceptions import BadRequestError
    from app.services.response.response_action_service import ResponseActionService

    service = ResponseActionService(MagicMock())
    service.agent_repo.get = AsyncMock(return_value=MagicMock())
    with pytest.raises(BadRequestError, match="confirmation"):
        await service.create_and_apply_action("a", "isolate", {"confirmed": True}, actor="policy_engine")
    with pytest.raises(BadRequestError, match="PID, start time"):
        await service.create_and_apply_action("a", "kill_process_tree", {"confirmed": True})


@pytest.mark.asyncio
async def test_failed_kill_ack_requires_verified_pid_exit_and_is_audited():
    from app.models.action_audit_log import ActionAuditLog
    from app.models.command import Command
    from app.schemas.enums import CommandStatus

    engine = create_engine("sqlite://")
    for model in (Agent, Incident, ResponseAction, Command, ActionAuditLog):
        model.__table__.create(engine)
    with Session(engine) as database:
        database.add(Agent(id="a", hostname="victim", ip_address="192.0.2.1", mac_address="00:00:00:00:00:00"))
        action = ResponseAction(id="action", agent_id="a", action_type="kill_process_tree", status="pending",
                                action_params={"command_id": "cmd"})
        database.add(action)
        cmd = Command(id="cmd", agent_id="a", action="kill_process_tree_verified",
                      status=CommandStatus.SENT, payload={"action_id": action.id, "pid": 809, "confirmed": True})
        database.add(cmd)
        database.commit()
        await agent_ws._handle_command_ack("a", {"payload": {"command_id": "cmd", "status": "success"}},
                                           DatabaseSession(database))
        assert action.status == "failed"
        assert cmd.status == CommandStatus.FAILED
        audit = database.scalars(select(ActionAuditLog)).one()
        assert audit.event == "failed"
        assert audit.metadata_["target_pid"] == 809
        assert audit.metadata_["result"] == "failed"
