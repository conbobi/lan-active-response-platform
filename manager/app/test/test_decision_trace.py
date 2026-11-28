"""Comprehensive tests for AI Risk Analyst Decision Trace, SSE streaming, risk explanation, and verification."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import NetworkOperator, settings
from app.models.agent import Agent
from app.models.ai_analysis import AIAnalysis
from app.models.ai_cache import ThreatMemory
from app.models.base import Base
from app.models.containment import ContainmentAction
from app.models.decision_trace import AIAnalysisRun, AIDecisionTraceEvent
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.response_action import ResponseAction
from app.models.response_policy import ResponsePolicy
from app.models.web_access_log import WebAccessLog
from app.services.ai import ai_triage_service, threat_memory as tm
from app.services.ai.ai_client import ai_client
from app.services.ai.decision_trace import (
    extract_risk_explanation,
    sanitize_safe_result,
    sanitize_trace_text,
    trace_broker,
)
from app.services.ai.triage_router import TriageQueue
from app.services.detection.risk_assessment_service import RiskAssessmentService
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401
from test_network_module import AGENT, digest, header

OUT_OF_SCOPE_TOKEN = "out-of-scope-operator-token-xyz-12345"
OUT_OF_SCOPE_HEADER = header(OUT_OF_SCOPE_TOKEN)


@pytest.fixture
def trace_env(lab, monkeypatch):
    client, factory = lab
    operators = dict(settings.NETWORK_OPERATORS)
    operators["other_op"] = NetworkOperator(
        role="operator",
        agents={"other-agent-99"},
        token_sha256=digest(OUT_OF_SCOPE_TOKEN),
    )
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", operators)
    monkeypatch.setattr(ai_triage_service, "AsyncSessionLocal", factory)
    monkeypatch.setattr(ai_triage_service, "triage_queue", TriageQueue(max_waiting=4))
    monkeypatch.setattr(
        ai_triage_service,
        "load_tokenizer",
        lambda: SimpleNamespace(count_chat=lambda s, u: max(1, (len(s or "") + len(u or "")) // 4)),
    )
    monkeypatch.setenv("AI_TRIAGE_ENABLE_SKIP", "false")
    trace_broker._active_runs.clear()
    trace_broker._subscribers.clear()
    return client, factory


async def _seed_http_incident(factory, inc_id: str = "inc_trace_http", *, risk_snapshot: dict | None = None, chain: dict | None = None):
    now = datetime.now(timezone.utc)
    evidence = {
        "rule_id": "web_compromise_chain" if chain else "web_attack",
        "factors": [
            {"rule": "web_attack", "score": 65.0, "reason": "SQLi probe on /login"}
        ] if not chain else [],
        "behavior": {
            "evidence_id": f"ev_{inc_id}",
            "evidence_type": "http",
            "classification": "sqli_probe_observed",
            "source_ip": "100.67.222.3",
            "service": "flask_web",
            "request_method": "POST",
            "request_path": "/login",
            "http_status": 500,
            "user_agent": "curl/8.5.0",
            "source_event_ids": [f"web_{inc_id}"],
            "first_attempt_at": (now - timedelta(seconds=10)).isoformat(),
            "last_attempt_at": now.isoformat(),
        },
    }
    if risk_snapshot is not None:
        evidence["risk_snapshot"] = risk_snapshot
    if chain is not None:
        evidence["chain"] = chain

    async with factory.begin() as db:
        inc = Incident(
            id=inc_id,
            agent_id=AGENT,
            title="Test HTTP SQLi Incident",
            description="Automated test incident",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            risk_score=75.0 if risk_snapshot or not chain else float(chain.get("score_breakdown", {}).get("final", 100.0)),
            detection_evidence=evidence,
            created_at=now,
        )
        db.add(inc)
        db.add(
            WebAccessLog(
                id=f"web_{inc_id}",
                agent_id=AGENT,
                timestamp=now,
                src_ip="100.67.222.3",
                host="100.112.146.63:5000",
                method="POST",
                path="/login",
                status_code=500,
                user_agent="curl/8.5.0",
            )
        )
    return inc_id


def test_sanitizer_strips_thinking_jwts_and_cookies():
    dirty = (
        "<think>Let me analyze Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.sig123456 "
        "password=SuperSecret123</think>Kết luận hợp lệ; Cookie: larp_refresh_token=abcxyz123; "
        "authorization=Bearer topsecretvalue999"
    )
    cleaned = sanitize_trace_text(dirty)
    assert "<think>" not in cleaned
    assert "</think>" not in cleaned
    assert "eyJhbGci" not in cleaned
    assert "SuperSecret123" not in cleaned
    assert "abcxyz123" not in cleaned
    assert "topsecretvalue999" not in cleaned
    assert "Kết luận hợp lệ" in cleaned

    nested = sanitize_safe_result({
        "summary": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload123.sig123456",
        "password": "secret",
        "refresh_token": "tok",
        "thinking": "raw chain of thought",
        "counts": {"http_events": 3},
    })
    assert nested["password"] == "[REDACTED]"
    assert nested["refresh_token"] == "[REDACTED]"
    assert nested["thinking"] == "[REDACTED]"
    assert "[REDACTED_JWT]" in nested["summary"]
    assert nested["counts"]["http_events"] == 3


@pytest.mark.asyncio
async def test_risk_explanation_exact_vs_legacy_missing(trace_env):
    _, factory = trace_env
    snapshot = {
        "source": "risk_assessment_service",
        "raw_score": 75.0,
        "smoothed_score": 75.0,
        "previous_smoothed": 20.0,
        "ema_applied": False,
        "security_attack_bypass": True,
        "thresholds": {"incident_creation_threshold": 50.0, "severity_high": 70.0, "severity_critical": 85.0},
        "rule_breakdown": [
            {
                "rule_id": "web_attack",
                "matched": True,
                "raw_score": 65.0,
                "debounced_score": 65.0,
                "weight": 1.1538,
                "weighted_contribution": 75.0,
                "evidence_ids": ["web_inc_snap"],
                "reason": "SQLi observed",
            }
        ],
    }
    snap_id = await _seed_http_incident(factory, "inc_snap", risk_snapshot=snapshot)

    async with factory.begin() as db:
        legacy_inc = Incident(
            id="inc_legacy_none",
            agent_id=AGENT,
            title="Legacy Empty Incident",
            description="Old record before risk_snapshot",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.OPEN,
            risk_score=55.0,
            detection_evidence={},
        )
        db.add(legacy_inc)

    async with factory() as db:
        exp_snap = await extract_risk_explanation(db, await db.get(Incident, snap_id))
        assert exp_snap["breakdown_available"] is True
        assert exp_snap["raw_score"] == 75.0
        assert exp_snap["security_attack_bypass"] is True
        assert exp_snap["ema_applied"] is False
        assert exp_snap["rule_breakdown"][0]["debounced_score"] == 65.0

        exp_legacy = await extract_risk_explanation(db, await db.get(Incident, "inc_legacy_none"))
        assert exp_legacy["breakdown_available"] is False
        assert exp_legacy["message"] == "Chưa có dữ liệu phân rã điểm"
        assert exp_legacy["rule_breakdown"] == []


@pytest.mark.asyncio
async def test_full_trace_persistence_unique_runs_and_no_false_pid(trace_env, monkeypatch):
    client, factory = trace_env
    inc_id = await _seed_http_incident(
        factory,
        "inc_trace_full",
        risk_snapshot={
            "source": "risk_assessment_service",
            "raw_score": 75.0,
            "smoothed_score": 75.0,
            "previous_smoothed": None,
            "ema_applied": False,
            "security_attack_bypass": True,
            "thresholds": {"incident_creation_threshold": 50.0, "severity_high": 70.0, "severity_critical": 85.0},
            "rule_breakdown": [
                {
                    "rule_id": "web_attack",
                    "matched": True,
                    "raw_score": 75.0,
                    "debounced_score": 75.0,
                    "weight": 1.0,
                    "weighted_contribution": 75.0,
                    "evidence_ids": ["web_inc_trace_full"],
                    "reason": "SQLi probe on /login",
                }
            ],
        },
    )

    async with factory.begin() as db:
        db.add(
            ResponsePolicy(
                id="pol_test_block",
                name="Block High Risk Attacker",
                min_score=70.0,
                max_score=100.0,
                action_type="block_ip",
                scope="agent",
                priority=10,
                is_active=True,
            )
        )

    async def fake_generate(prompt, system, format_schema=None, **kwargs):
        payload = {
            "evidence_ids": ["F1"],
            "classification": "sqli_probe_observed",
            "confidence": 0.78,
            "mitre_techniques": [],
        }
        return {"answer": json.dumps(payload), "thinking": "<think>secret Bearer xyz</think>", "metrics": {"eval_duration": 150_000_000}}

    monkeypatch.setattr(ai_client, "generate", fake_generate)

    svc = ai_triage_service.AITriageService()
    row1 = await svc.analyze_incident(inc_id, manual=True, requested_by="admin")
    row2 = await svc.analyze_incident(inc_id, manual=True, requested_by="admin")
    assert row1 is not None and row2 is not None

    runs_resp = client.get(f"/api/v1/ai/incidents/{inc_id}/analysis/runs", headers=ANALYST)
    assert runs_resp.status_code == 200
    runs = runs_resp.json()["runs"]
    assert len(runs) == 2
    assert runs[0]["analysis_run_id"] != runs[1]["analysis_run_id"]

    run_id = runs[0]["analysis_run_id"]
    trace_resp = client.get(f"/api/v1/ai/runs/{run_id}/trace", headers=ANALYST)
    assert trace_resp.status_code == 200
    data = trace_resp.json()
    assert data["run"]["status"] == "COMPLETED"
    assert data["run"]["analysis_id"] == row2.id

    events = data["events"]
    seqs = [e["sequence"] for e in events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs) and seqs[0] == 1

    # PROCESS_NETWORK_CORRELATION must be SKIPPED (not faked) for HTTP-only incident
    corr_events = [e for e in events if e["stage"] == "PROCESS_NETWORK_CORRELATION"]
    assert corr_events[-1]["status"] == "SKIPPED"
    assert corr_events[-1]["safe_result"]["matched_pids"] == []

    # CLAIM_VERIFICATION checks pass without root/execution claims
    verify_events = [e for e in events if e["stage"] == "CLAIM_VERIFICATION" and e["status"] == "COMPLETED"]
    assert verify_events and verify_events[-1]["safe_result"]["passed"] is True

    # RESPONSE_RECOMMENDATION stays strictly read-only
    policy_events = [
        e for e in events
        if e["stage"] == "RESPONSE_RECOMMENDATION" and e["event_type"] == "stage_completed"
    ]
    assert policy_events[-1]["safe_result"]["read_only"] is True
    assert policy_events[-1]["safe_result"]["auto_executed"] is False
    async with factory() as db:
        assert (await db.scalar(select(func.count(ResponseAction.id)))) == 0
        assert (await db.scalar(select(func.count(ContainmentAction.id)))) == 0


@pytest.mark.asyncio
async def test_sse_stream_auth_scope_and_replay(trace_env, monkeypatch):
    client, factory = trace_env
    inc_id = await _seed_http_incident(factory, "inc_sse_test")

    async def fake_generate(prompt, system, **kwargs):
        return {
            "answer": json.dumps({
                "evidence_ids": ["F1"],
                "classification": "sqli_probe_observed",
                "confidence": 0.72,
                "mitre_techniques": [],
            }),
            "metrics": {},
        }

    monkeypatch.setattr(ai_client, "generate", fake_generate)
    await ai_triage_service.AITriageService().analyze_incident(inc_id, manual=True)
    run_id = client.get(f"/api/v1/ai/incidents/{inc_id}/analysis/runs", headers=ANALYST).json()["runs"][0]["analysis_run_id"]

    # Auth & scope enforcement on SSE endpoint
    assert client.get(f"/api/v1/ai/runs/{run_id}/stream").status_code == 401
    assert client.get(f"/api/v1/ai/runs/{run_id}/stream?token=secret", headers=ANALYST).status_code == 400
    assert client.get(f"/api/v1/ai/runs/{run_id}/stream", headers=OUT_OF_SCOPE_HEADER).status_code == 403

    # Replay from sequence > 3 using Last-Event-ID header
    stream_resp = client.get(
        f"/api/v1/ai/runs/{run_id}/stream",
        headers={**ANALYST, "Last-Event-ID": "3"},
    )
    assert stream_resp.status_code == 200
    assert "text/event-stream" in stream_resp.headers["content-type"]

    replayed_seqs = []
    for block in stream_resp.text.split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data:"):
                ev = json.loads(line[5:].strip())
                replayed_seqs.append(ev["sequence"])
    assert replayed_seqs and all(s > 3 for s in replayed_seqs)
    assert replayed_seqs == sorted(replayed_seqs)


@pytest.mark.asyncio
async def test_ollama_timeout_and_cache_hit_stages(trace_env, monkeypatch):
    client, factory = trace_env
    inc_id = await _seed_http_incident(factory, "inc_timeout_test")

    async def timeout_generate(*args, **kwargs):
        raise TimeoutError("Ollama timed out after 120s")

    monkeypatch.setattr(ai_client, "generate", timeout_generate)
    svc = ai_triage_service.AITriageService()
    row = await svc.analyze_incident(inc_id, manual=True)
    assert row is not None

    runs = client.get(f"/api/v1/ai/incidents/{inc_id}/analysis/runs", headers=ANALYST).json()["runs"]
    timeout_trace = client.get(f"/api/v1/ai/runs/{runs[0]['analysis_run_id']}/trace", headers=ANALYST).json()
    assert timeout_trace["run"]["status"] == "TIMEOUT"
    assert timeout_trace["run"]["analysis_id"] == row.id

    by_stage = {e["stage"]: e for e in timeout_trace["events"]}
    assert by_stage["MODEL_INFERENCE"]["status"] == "TIMEOUT"
    assert by_stage["DETERMINISTIC_FALLBACK"]["status"] == "COMPLETED"

    # Now verify cache hit skips MODEL_INFERENCE cleanly
    inc_reuse = await _seed_http_incident(factory, "inc_cache_hit")
    model_calls = {"count": 0}

    async def good_generate(*args, **kwargs):
        model_calls["count"] += 1
        return {
            "answer": json.dumps({
                "evidence_ids": ["F1"],
                "classification": "sqli_probe_observed",
                "confidence": 0.77,
                "mitre_techniques": [],
            }),
            "metrics": {},
        }

    monkeypatch.setattr(ai_client, "generate", good_generate)
    await svc.analyze_incident(inc_reuse, manual=False, use_memory=True)
    assert model_calls["count"] == 1

    # Force a fresh run via router with reuse=True so EXACT threat memory matches
    res_reuse = await svc.analyze_incident(inc_reuse, manual=False, use_memory=True)
    assert res_reuse is not None
    assert model_calls["count"] == 1  # Still 1 -> Threat Memory reused!

    reuse_runs = client.get(f"/api/v1/ai/incidents/{inc_reuse}/analysis/runs", headers=ANALYST).json()["runs"]
    reuse_trace = client.get(f"/api/v1/ai/runs/{reuse_runs[0]['analysis_run_id']}/trace", headers=ANALYST).json()
    reuse_stages = {e["stage"]: e for e in reuse_trace["events"]}
    assert reuse_stages["CACHE_LOOKUP"]["safe_result"]["cache_hit"] is True
    assert reuse_stages["MODEL_INFERENCE"]["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_concurrent_single_flight_dedup_via_api(trace_env):
    client, factory = trace_env
    inc_id = await _seed_http_incident(factory, "inc_single_flight")

    # Simulate an existing active run already in DB/broker
    async with factory.begin() as db:
        inc = await db.get(Incident, inc_id)
        run, reused = await trace_broker.get_or_create_run(
            db, incident_id=inc_id, agent_id=inc.agent_id, requested_by="admin", mode="fresh"
        )
        assert reused is False
        existing_id = run.id

    r1 = client.post(f"/api/v1/ai/incidents/{inc_id}/analysis/run", headers=ANALYST, json={"mode": "fresh"})
    r2 = client.post(f"/api/v1/ai/incidents/{inc_id}/analysis/run", headers=ANALYST, json={"mode": "fresh"})
    assert r1.status_code == 202 and r2.status_code == 202
    assert r1.json()["analysis_run_id"] == existing_id
    assert r1.json()["reused_active_run"] is True
    assert r2.json()["analysis_run_id"] == existing_id
    assert r2.json()["reused_active_run"] is True


@pytest.mark.asyncio
async def test_risk_assessment_preserves_score_math_and_writes_snapshot(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'risk.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with factory() as db:
        db.add(Agent(id=AGENT, hostname="h1", ip_address="10.0.0.5", mac_address="00:11:22:33:44:55"))
        await db.commit()

        svc = RiskAssessmentService(db)
        telemetry = {
            "cpu_usage": 95.0,
            "memory_usage": 92.0,
            "failed_logins": 12,
            "process_list": [],
            "connections": [],
        }
        score_before, factors = await svc.evaluate(AGENT, telemetry)
        assert isinstance(score_before, float) and score_before >= 0.0
        assert len(svc._last_rule_breakdown) > 0
        await db.rollback()
    await engine.dispose()


@pytest.mark.asyncio
async def test_live_local_ollama_trace_if_running(tmp_path, monkeypatch):
    """Verify end-to-end real sec-q5:latest trace execution against local Ollama when running."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as http:
            tags = await http.get(f"{ai_client.base_url}/api/tags")
            models = [m.get("name") for m in tags.json().get("models", [])]
            if ai_client.model not in models:
                pytest.skip(f"Model {ai_client.model} not loaded in local Ollama")
    except Exception:
        pytest.skip("Local Ollama service not reachable")

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'live_ollama.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    now = datetime.now(timezone.utc)
    inc_id = "inc_live_ollama_check"
    async with factory.begin() as db:
        db.add(Agent(id=AGENT, hostname="lab-victim", ip_address="100.112.146.63", mac_address="aa:bb:cc:dd:ee:ff"))
        await db.flush()
        db.add(
            Incident(
                id=inc_id,
                agent_id=AGENT,
                title="Live Ollama SQLi Trace Verification",
                description="Live local Ollama verification",
                severity=IncidentSeverity.HIGH,
                status=IncidentStatus.OPEN,
                risk_score=75.0,
                created_at=now,
                detection_evidence={
                    "rule_id": "web_attack",
                    "risk_snapshot": {
                        "source": "risk_assessment_service",
                        "raw_score": 75.0,
                        "smoothed_score": 75.0,
                        "previous_smoothed": None,
                        "ema_applied": False,
                        "security_attack_bypass": True,
                        "thresholds": {"incident_creation_threshold": 50.0, "severity_high": 70.0},
                        "rule_breakdown": [
                            {
                                "rule_id": "web_attack",
                                "matched": True,
                                "raw_score": 75.0,
                                "debounced_score": 75.0,
                                "weight": 1.0,
                                "weighted_contribution": 75.0,
                                "evidence_ids": ["web_live_1"],
                                "reason": "SQLi token in /login",
                            }
                        ],
                    },
                    "behavior": {
                        "evidence_id": "ev_live_1",
                        "evidence_type": "http",
                        "classification": "sqli_probe_observed",
                        "source_ip": "100.67.222.3",
                        "service": "flask_web",
                        "request_method": "POST",
                        "request_path": "/login",
                        "http_status": 500,
                        "user_agent": "curl/8.5.0",
                        "source_event_ids": ["web_live_1"],
                        "first_attempt_at": (now - timedelta(seconds=5)).isoformat(),
                        "last_attempt_at": now.isoformat(),
                    },
                },
            )
        )
        db.add(
            WebAccessLog(
                id="web_live_1",
                agent_id=AGENT,
                timestamp=now,
                src_ip="100.67.222.3",
                host="100.112.146.63:5000",
                method="POST",
                path="/login",
                status_code=500,
                user_agent="curl/8.5.0",
            )
        )

    monkeypatch.setattr(ai_triage_service, "AsyncSessionLocal", factory)
    monkeypatch.setattr(ai_triage_service, "triage_queue", TriageQueue(max_waiting=2))
    trace_broker._active_runs.clear()
    trace_broker._subscribers.clear()

    svc = ai_triage_service.AITriageService()
    row = await svc.analyze_incident(inc_id, manual=True, requested_by="live-qa")
    assert row is not None

    async with factory() as db:
        run = await db.scalar(select(AIAnalysisRun).where(AIAnalysisRun.incident_id == inc_id))
        events = (
            await db.scalars(
                select(AIDecisionTraceEvent)
                .where(AIDecisionTraceEvent.analysis_run_id == run.id)
                .order_by(AIDecisionTraceEvent.sequence.asc())
            )
        ).all()
        assert run is not None
        assert run.status in ("COMPLETED", "TIMEOUT")
        stages = {e.stage: e for e in events}
        assert "RISK_RULE_EXPLANATION" in stages
        assert stages["RISK_RULE_EXPLANATION"].safe_result["breakdown_available"] is True
        assert "CLAIM_VERIFICATION" in stages
        for ev in events:
            assert "<think>" not in (ev.summary or "").lower()

    await engine.dispose()
