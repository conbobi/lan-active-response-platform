"""Threat Memory API: RBAC, SOC verify/revoke, mark-incorrect, analysis source view, re-triage on escalation."""
import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import NetworkOperator, settings
from app.models.ai_analysis import AIAnalysis
from app.models.ai_cache import ThreatMemory
from app.services.ai import threat_memory as tm
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT, digest, header

OPERATOR_TOKEN = "operator-token-for-threat-memory-tests"
OPERATOR = header(OPERATOR_TOKEN)


@pytest.fixture
def env(lab, monkeypatch):
    client, factory = lab
    operators = dict(settings.NETWORK_OPERATORS)
    operators["op"] = NetworkOperator(role="operator", agents={AGENT}, token_sha256=digest(OPERATOR_TOKEN))
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", operators)
    return client, factory


async def memory_row(factory, **extra):
    row = ThreatMemory(
        fingerprint="f" * 64, fingerprint_version=tm.FINGERPRINT_VERSION, attack_pattern="Reverse shell (linux)",
        platform="linux", detection_rule_ids=["network_shell"], mitre_techniques=["T1059.004"],
        behavioral_features={}, analysis_template={"classification": "likely_malicious", "confidence": 0.85,
                                                   "evidence_roles": ["network:outbound:verified_shell"], "techniques": []},
        response_playbook_reference={"actions": ["collect_additional_evidence", "block_ip"]},
        evidence_requirements=["network:outbound:verified_shell"], model_name="m@unpinned", prompt_version="p",
        telemetry_schema_version=tm.TELEMETRY_SCHEMA_VERSION, source_incident_id="inc",
        expires_at=tm.now() + timedelta(days=1), **extra)
    async with factory.begin() as db:
        db.add(row)
    return row.id


@pytest.mark.asyncio
async def test_memory_management_roles(env):
    client, factory = env
    memory_id = await memory_row(factory)
    assert client.get("/api/v1/ai/threat-memory").status_code == 401
    items = client.get("/api/v1/ai/threat-memory", headers=ANALYST).json()["items"]
    assert items[0]["attack_pattern"] == "Reverse shell (linux)" and len(items[0]["fingerprint_short"]) == 12
    assert "behavioral_features" not in items[0]  # no raw features / long hashes in the list
    path = f"/api/v1/ai/threat-memory/{memory_id}"
    assert client.post(path + "/revoke", headers=ANALYST, json={}).status_code == 403
    assert client.post(path + "/verify", headers=OPERATOR, json={}).status_code == 403
    verified = client.post(path + "/verify", headers=ADMIN, json={"reason": "Đã đối chiếu"}).json()
    assert verified["validation_status"] == "soc_verified" and verified["reviewer"] == "admin"
    revoked = client.post(path + "/revoke", headers=OPERATOR, json={"reason": "Sai ngữ cảnh"}).json()
    assert revoked["validation_status"] == "revoked" and revoked["reviewer"] == "op"
    assert tm.usable(await _get(factory, memory_id), model_name="m@unpinned", prompt_version="p") == "status_revoked"


async def _get(factory, memory_id):
    async with factory() as db:
        return await db.get(ThreatMemory, memory_id)


@pytest.mark.asyncio
async def test_analysis_source_view_and_mark_incorrect_revokes_the_entry(env):
    client, factory = env
    memory_id = await memory_row(factory)
    async with factory.begin() as db:
        db.add(AIAnalysis(incident_id="inc", analysis_type="triage", summary="s", confidence=0.85,
                          model_name="threat-memory", raw_response=json.dumps({
                              "analysis_source": tm.EXACT, "model_called": False, "status": "ok",
                              "memory": {"id": memory_id, "attack_pattern": "Reverse shell (linux)",
                                         "validation_status": "auto_validated"},
                              "similar_cases": [{"id": memory_id, "attack_pattern": "Reverse shell (linux)",
                                                 "similarity": 0.8}],
                              "latency_ms": {"lookup": 3.1, "llm": None, "total": 40.0}})))
    view = client.get("/api/v1/ai/incidents/inc/analysis-source", headers=ANALYST).json()
    assert view["analysis_source"] == tm.EXACT and view["model_called"] is False and view["model_name"] is None
    assert view["memory"]["usage_count"] == 0 and view["similar_cases"][0]["source_incident_id"] == "inc"
    assert client.post("/api/v1/ai/incidents/inc/analysis/incorrect", headers=ANALYST, json={}).status_code == 403
    marked = client.post("/api/v1/ai/incidents/inc/analysis/incorrect", headers=OPERATOR,
                         json={"reason": "Sai phân loại"}).json()
    assert marked["memory_invalidated"] == [memory_id]
    assert (await _get(factory, memory_id)).validation_status == "incorrect"
    async with factory() as db:
        analysis = (await db.scalars(select(AIAnalysis))).one()
        assert analysis.analyst_rating == "wrong"


@pytest.mark.asyncio
async def test_learning_never_overrides_a_soc_rejection(env, monkeypatch):
    client, factory = env
    await memory_row(factory, validation_status="incorrect")
    fp = tm.Fingerprint("f" * 64, {}, "linux", ["network_shell"], {})
    stored = await tm.store(factory, fp, {"classification": "likely_malicious", "confidence": 0.8,
                                          "evidence_roles": [], "techniques": []},
                            model_name="m@unpinned", prompt_version="p", incident_id="inc")
    assert stored is None and (await _get(factory, (await _all(factory))[0].id)).validation_status == "incorrect"


async def _all(factory):
    async with factory() as db:
        return (await db.scalars(select(ThreatMemory))).all()


@pytest.mark.asyncio
async def test_rule_change_invalidates_entries(env):
    client, factory = env
    memory_id = await memory_row(factory)
    async with factory.begin() as db:
        assert await tm.invalidate_rule(db, "network_shell", "Logic rule thay đổi") == 1
    row = await _get(factory, memory_id)
    assert row.validation_status == "invalidated" and row.status_reason == "Logic rule thay đổi"


@pytest.mark.asyncio
async def test_metrics_come_from_recorded_decisions_only(env):
    client, factory = env
    empty = client.get("/api/v1/ai/threat-memory/metrics", headers=ANALYST).json()
    assert empty["analyses"] == 0 and empty["exact_hit_rate"] is None and empty["avg_llm_ms"] is None
    decision = tm.Decision(tm.EXACT, lookup_ms=2.0)
    await tm.record_event(factory, decision, incident_id="inc", final_source=tm.EXACT, total_ms=30.0)
    await tm.record_event(factory, tm.Decision(tm.FRESH, lookup_ms=4.0), incident_id="inc", final_source=tm.FRESH,
                          llm_ms=60000.0, total_ms=60100.0)
    stats = client.get("/api/v1/ai/threat-memory/metrics", headers=ANALYST).json()
    assert stats["analyses"] == 2 and stats["exact_hit_rate"] == 0.5 and stats["miss_rate"] == 0.5
    assert stats["avg_lookup_ms"] == 3.0 and stats["avg_llm_ms"] == 60000.0 and stats["avg_total_ms_exact"] == 30.0


@pytest.mark.asyncio
async def test_run_analysis_requires_scope(env, monkeypatch):
    client, factory = env
    assert client.post("/api/v1/ai/incidents/inc/analysis/run", json={"mode": "fresh"}).status_code == 401
    calls = []

    class Fake:
        async def analyze_incident(self, incident_id, **kwargs):
            calls.append((incident_id, kwargs))
    monkeypatch.setattr("app.services.ai.ai_triage_service.AITriageService", Fake)
    response = client.post("/api/v1/ai/incidents/inc/analysis/run", headers=ANALYST, json={"mode": "fresh"})
    assert response.status_code == 202 and calls == [("inc", {"manual": True, "use_memory": False})]


@pytest.mark.asyncio
async def test_chain_escalation_queues_a_new_analysis(env):
    """Severity MEDIUM → HIGH re-triages the same incident so the fingerprint is evaluated again."""
    from test_web_compromise_chain import PING, SH, WEB, UPLOAD, bypass, chain_incidents, send
    from app.services.detection import web_compromise
    from app.websocket import agent_ws
    client, factory = env
    await bypass(factory)
    await send(factory, agent_ws._handle_web_access_log, UPLOAD)
    await send(factory, agent_ws._handle_web_access_log, PING)
    incident, = await chain_incidents(factory)
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": SH["process_start_time"], **SH, "parent": WEB}]})
    async with factory() as db:
        db.info["defer_incident_events"] = True
        await web_compromise.correlate(db, AGENT)
        assert db.info.get("new_incident_ids", []) == []  # nothing new since the last evaluation
    async with factory() as db:
        row = await db.get(type(incident), incident.id)
        row.severity, row.risk_score = "medium", 50.0
        row.detection_evidence = {**row.detection_evidence, "chain_digest": "older"}
        await db.commit()
    async with factory() as db:
        db.info["defer_incident_events"] = True
        await web_compromise.correlate(db, AGENT)
        assert incident.id in db.info.get("new_incident_ids", [])
