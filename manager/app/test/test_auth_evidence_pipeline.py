import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models.agent import Agent
from app.models.auth_event import AuthEvent
from app.models.base import Base
from app.models.event import Event
from app.models.flow import Flow
from app.models.incident import Incident
from app.models.web_access_log import WebAccessLog
from app.schemas.incident import AIAnalysisOut
from app.services.ai.ai_triage_service import _analysis_fields, fallback_verdict
from app.services.ai.alert_context_projector import build_alert_context
from app.services.ai.triage_schema import TriageVerdict, parse_output, validate_verdict
from app.services.common.notification_service import NotificationService
from app.services.detection.behavior_evidence import BRUTE_FORCE, REPEATED, SCAN, SQLI, technique_for
from app.services.detection.risk_rules.network_scan_rule import scan_findings
from app.websocket import agent_ws


def incident_context(group):
    return build_alert_context(Incident(
        agent_id="agent-a", title="Authentication observation", created_at=datetime.now(timezone.utc),
        detection_evidence=group, risk_score=55,
    ))


def test_legacy_factor_is_partial_without_mitre_or_invented_event_ids():
    context = incident_context({
        "rule_id": "brute_force", "rule_version": "risk:1",
        "factors": [{"rule": "brute_force", "reason": "Brute force on flask_web from 192.0.2.4: 15 failed logins"}],
    })
    verdict = fallback_verdict(context)
    assert verdict.classification == REPEATED
    assert verdict.evidence_completeness == "partial"
    assert verdict.techniques == []
    assert context.facts[0]["reported_failed_attempts"] == 15
    assert "source_event_ids" not in context.facts[0]


def test_ai_can_only_map_technique_for_its_observed_behavior():
    fact = {
        "classification": REPEATED, "evidence_type": "authentication", "source": "auth_events",
        "source_event_ids": ["auth_1"], "failed_attempts": 5, "successful_attempts": 0,
    }
    context = incident_context({"rule_id": REPEATED, "behavior": fact})
    bogus = ["T1218", "T1218.007", "T1110"]
    answer = json.dumps({
        "classification": "confirmed_malicious", "confidence": 1.0,
        "evidence_ids": ["F1"], "mitre_techniques": [{"id": key, "evidence_ids": ["F1"]} for key in bogus],
    })
    output = parse_output({"answer": answer}, TriageVerdict, {"F1"})
    verdict = validate_verdict(output, context)
    assert verdict.classification == REPEATED and not verdict.techniques
    assert not context.flows and not context.processes
    record = _analysis_fields(context, verdict, "ok", "revision")
    assert record["root_cause"] is None and "5 thất bại" in record["summary"]
    assert AIAnalysisOut.model_validate({
        **record, "id": "ai_1", "incident_id": "inc_1", "analysis_type": "triage",
        "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc),
    }).mitre_techniques == []

    fact["classification"] = BRUTE_FORCE
    assert technique_for(fact) is None
    fact["brute_force_criteria"] = "password_burst_same_account_source"
    assert technique_for(fact) == "T1110"
    fact["classification"] = SQLI
    assert technique_for(fact) is None


def test_scan_requires_inbound_distinct_local_ports_within_window():
    now = datetime.now(timezone.utc)

    def flow(port, index, observed=now, direction="inbound", agent="agent-a"):
        return Flow(
            id=f"flow_{index}", agent_id=agent, src_ip="192.0.2.2", src_port=port,
            dst_ip="198.51.100.7", dst_port=43000 + index, protocol="TCP", start_time=now,
            socket_evidence={"direction": direction, "observed_at": observed.isoformat(),
                             "status": "SYN-RECV", "socket_id": f"socket_{index}"},
        )

    scope = {("198.51.100.7", "192.0.2.2", "TCP"): now}
    rows = [flow(5000 + n, n) for n in range(7)]
    stale = flow(6000, 8, now - timedelta(seconds=61))
    assert not list(scan_findings([*rows, stale, flow(6001, 9, direction="outbound"),
                                   flow(6002, 10, agent="agent-b")], scope, "agent-a"))
    assert not list(scan_findings([flow(5000, n) for n in range(30)], scope, "agent-a"))
    matches = list(scan_findings([*rows, flow(6000, 8), rows[0]], scope, "agent-a"))
    assert len(matches) == 1 and matches[0]["connection_count"] == 8
    assert matches[0]["source_ip"] == "198.51.100.7"
    assert matches[0]["destination_ip"] == "192.0.2.2"
    verdict = fallback_verdict(incident_context({"rule_id": SCAN, "behavior": matches[0]}))
    assert [tech["id"] for tech in verdict.techniques] == ["T1046"]


@pytest.mark.asyncio
async def test_auth_ws_persists_event_identity_reuses_http_request_and_deduplicates(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}")
    sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(NotificationService, "send_alert", AsyncMock())
    now = datetime.now(timezone.utc)
    request_id = "a" * 32
    web = {
        "request_id": request_id, "path": "/login?token=private-test-value", "method": "POST",
        "status_code": 302, "src_ip": "192.0.2.4", "service": "flask_web",
        "timestamp": now.isoformat(), "raw_message": "secret=private-test-value",
        "payload_indicators": ["sql_query_operator"],
        "headers": {"Authorization": "private-test-value"},
    }
    attack = {
        "service": "flask_web", "request_id": request_id, "username": "operator",
        "source_ip": web["src_ip"], "status": "failed", "method": "POST", "path": "/login",
        "timestamp": now.isoformat(), "timestamp_source": "application", "auth_method": "password",
        "payload_indicators": ["sql_query_operator"], "password": "private-test-value",
    }
    try:
        async with sessions() as db:
            db.info["defer_incident_events"] = True
            db.add(Agent(id="agent-a", hostname="local-fixture", ip_address="192.0.2.2", mac_address="00:00:00:00:00:01"))
            await db.flush()
            await agent_ws._handle_web_access_log("agent-a", {"payload": web}, db)
            envelope = {"payload": {"events": [attack, attack]}}
            await agent_ws._handle_auth_event("agent-a", envelope, db)
            await agent_ws._handle_auth_event("agent-a", envelope, db)
            await db.commit()
        async with sessions() as db:
            auth, = (await db.scalars(select(AuthEvent))).all()
            web_row, = (await db.scalars(select(WebAccessLog))).all()
            observation, = (await db.scalars(select(Event).where(Event.event_type == "AUTH_OBSERVATION"))).all()
            incident, = (await db.scalars(select(Incident))).all()
            evidence = incident.detection_evidence["behavior"]
            assert evidence["source_event_ids"] == [auth.id] and observation.id == auth.id
            assert auth.timestamp.replace(tzinfo=timezone.utc) == now
            assert evidence["http_event_id"] == web_row.id and evidence["http_status"] == 302
            assert evidence["classification"] == SQLI and evidence["exploitation_outcome"] == "undetermined"
            assert incident.detection_evidence["observations"] == 1
            assert "private-test-value" not in json.dumps([web_row.raw_message, observation.details, incident.detection_evidence])
            assert build_alert_context(incident).facts[0]["verified_technique"] == "T1190"
    finally:
        await engine.dispose()
