"""AI Threat Memory: fingerprint, exact/semantic/miss tiers, validation, invalidation, RBAC.

Runs the real AITriageService; only the model call is stubbed (call count = Ollama calls).
"""
import asyncio
import json
from datetime import timedelta
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select

from app.models.ai_cache import ThreatMemory, ThreatMemoryEvent
from app.models.ip_block import IpBlock
from app.models.response_action import ResponseAction
from app.services.ai import ai_triage_service, threat_memory as tm
from app.services.ai.alert_context_projector import build_alert_context
from app.services.ai.triage_router import TriageQueue
from app.test.test_ai_agent_pipeline import local_triage_db, triage_output, triage_tokenizer  # noqa: F401
from app.test.test_alert_context_projector import holder, incident_with, socket_observation
from app.services.detection.network_shell import detect_network_shell

SHELL_VERDICT = dict(classification="likely_malicious", confidence=0.85, ids=["N1"],
                     techniques=[{"id": "T1059.004", "evidence_ids": ["N1"]}])


def shell_incident(identifier, *, pid=801, start=10.0, ip="198.51.100.1", port=4444, name="bash", fds=(0, 1),
                   exe=None, agent="agent-a"):
    h = holder(pid=pid, start=start, name=name, fds=fds)
    evidence = detect_network_shell(socket_observation(h, port=port, dst_ip=ip))
    assert evidence, "fixture must be a verified network shell"
    if exe:  # same behaviour reported by an Agent on another platform
        evidence = json.loads(json.dumps(evidence).replace(f"/usr/bin/{name}", exe.replace("\\", "\\\\")))
    inc = incident_with({**evidence, "rule_version": "builtin:1"}, identifier=identifier)
    inc.agent_id = agent
    return inc


def fingerprint(incident):
    return tm.build_fingerprint(incident, build_alert_context(incident))


@pytest.fixture
def runtime(monkeypatch, triage_tokenizer):  # noqa: F811
    monkeypatch.setattr(ai_triage_service, "load_tokenizer", lambda: triage_tokenizer)
    monkeypatch.setattr(ai_triage_service, "triage_queue", TriageQueue(max_waiting=8))
    monkeypatch.setenv("AI_TRIAGE_ENABLE_SKIP", "false")
    return ai_triage_service.AITriageService()


def source(row):
    return json.loads(row.raw_response)


async def count(factory, model, *where):
    async with factory() as db:
        return await db.scalar(select(func.count()).select_from(model).where(*where))


# ── fingerprint ─────────────────────────────────────────────────────────────────────────────
def test_fingerprint_ignores_instance_values_and_is_deterministic():
    a = fingerprint(shell_incident("inc-a", pid=801, start=10.0, ip="198.51.100.1", port=4444))
    b = fingerprint(shell_incident("inc-b", pid=4242, start=99.0, ip="203.0.113.77", port=5555))
    assert a.value == b.value and a.value == fingerprint(shell_incident("inc-a")).value
    assert a.features["fingerprint_version"] == tm.FINGERPRINT_VERSION and a.platform == "linux"
    for volatile in ("801", "4242", "198.51.100.1", "203.0.113.77", "inc-a", "agent-a"):
        assert volatile not in json.dumps(a.features)


def test_near_matches_and_other_platforms_get_different_fingerprints():
    base = fingerprint(shell_incident("x"))
    variants = {
        "other_shell": fingerprint(shell_incident("y", name="sh")),
        "windows": fingerprint(shell_incident("z", exe="C:\\Windows\\System32\\bash.exe")),
        "well_known_port": fingerprint(shell_incident("w", port=443)),
    }
    assert variants["windows"].platform == "windows"
    values = [base.value, *(v.value for v in variants.values())]
    assert len(set(values)) == len(values)  # no collision among technically different cases


# ── tiers through the real triage service ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_miss_calls_model_then_same_technique_with_other_ip_pid_is_an_exact_hit(tmp_path, monkeypatch, runtime):
    first, second = shell_incident("inc-1"), shell_incident("inc-2", pid=4242, start=99.0, ip="203.0.113.77")
    engine, factory = await local_triage_db(tmp_path, monkeypatch, first, second)
    generate = AsyncMock(return_value=triage_output(**SHELL_VERDICT))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        miss = await runtime.analyze_incident("inc-1")
        assert generate.await_count == 1 and source(miss)["analysis_source"] == tm.FRESH
        assert source(miss)["learned_memory_id"] and await count(factory, ThreatMemory) == 1
        hit = await runtime.analyze_incident("inc-2")
        assert generate.await_count == 1  # no Ollama call
        raw = source(hit)
        assert raw["analysis_source"] == tm.EXACT and raw["model_called"] is False and hit.model_name == "threat-memory"
        assert raw["memory"]["validation_status"] == "auto_validated"
        assert raw["evidence_ids"] == ["N1"] and raw["classification"] == "likely_malicious"
        # Rendered from *this* incident: its PID/peer appear, the old incident's do not.
        assert "4242" in hit.summary and "203.0.113.77" in hit.summary
        assert "801" not in hit.summary and "198.51.100.1" not in hit.summary
        assert "inc-1" not in hit.raw_response
        await asyncio.sleep(0.05)
        async with factory() as db:
            entry = (await db.scalars(select(ThreatMemory))).one()
            assert entry.usage_count == 1 and entry.source_incident_id == "inc-1"
            assert {e.decision for e in (await db.scalars(select(ThreatMemoryEvent))).all()} == {tm.FRESH, tm.EXACT}
        # Cached analysis never creates or reuses response actions.
        assert await count(factory, ResponseAction) == 0 and await count(factory, IpBlock) == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_semantic_match_is_context_only(tmp_path, monkeypatch, runtime):
    shell, near = shell_incident("inc-sh"), shell_incident("inc-py", name="sh", pid=900)
    engine, factory = await local_triage_db(tmp_path, monkeypatch, shell, near)
    prompts = []

    async def generate(prompt, *args, **kwargs):
        prompts.append(prompt)
        if len(prompts) == 1:
            return triage_output(**SHELL_VERDICT)
        return triage_output("suspicious_unconfirmed", 0.4, ids=["N1"])  # model judges current evidence
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        await runtime.analyze_incident("inc-sh")
        result = await runtime.analyze_incident("inc-py")
        raw = source(result)
        assert len(prompts) == 2  # the model was still called
        assert raw["analysis_source"] == tm.SEMANTIC and raw["similar_cases"][0]["similarity"] > 0
        # The verdict is the model's on current evidence (verified-shell policy keeps likely_malicious),
        # with the model's own confidence 0.4 — not the similar case's 0.85.
        assert raw["confidence"] == 0.4 and raw["memory"] is None
        assert "Reference only (not evidence)" in prompts[1]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_other_platform_never_matches(tmp_path, monkeypatch, runtime):
    linux = shell_incident("inc-l")
    windows = shell_incident("inc-w", exe="C:\\Windows\\System32\\bash.exe")
    engine, factory = await local_triage_db(tmp_path, monkeypatch, linux, windows)
    generate = AsyncMock(return_value=triage_output(**SHELL_VERDICT))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        await runtime.analyze_incident("inc-l")
        result = await runtime.analyze_incident("inc-w")
        assert generate.await_count == 2 and source(result)["similar_cases"] == []
        assert source(result)["analysis_source"] == tm.FRESH
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("change,reason", [
    ({"expires_at": "past"}, "expired"),
    ({"validation_status": "revoked"}, "status_revoked"),
    ({"prompt_version": "old"}, "model_or_prompt_version"),
    ({"response_playbook_reference": {"actions": ["format_disk"]}}, "playbook_unsupported"),
])
async def test_unusable_entries_are_not_reused(tmp_path, monkeypatch, runtime, change, reason):
    engine, factory = await local_triage_db(tmp_path, monkeypatch, shell_incident("inc-1"), shell_incident("inc-2", pid=5))
    generate = AsyncMock(return_value=triage_output(**SHELL_VERDICT))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        await runtime.analyze_incident("inc-1")
        async with factory() as db:
            row = (await db.scalars(select(ThreatMemory))).one()
            for key, value in change.items():
                setattr(row, key, tm.now() - timedelta(seconds=1) if value == "past" else value)
            await db.commit()
        result = await runtime.analyze_incident("inc-2")
        assert generate.await_count == 2 and source(result)["analysis_source"] != tm.EXACT
        assert source(result)["cache_reason"] == reason
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_timeout_and_invalid_output_are_not_stored(tmp_path, monkeypatch, runtime):
    engine, factory = await local_triage_db(tmp_path, monkeypatch, shell_incident("inc-1"), shell_incident("inc-2", pid=7))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", AsyncMock(side_effect=TimeoutError))
    try:
        timed_out = await runtime.analyze_incident("inc-1")
        assert source(timed_out)["analysis_source"] == tm.FALLBACK and source(timed_out)["status"] == "timeout"
        monkeypatch.setattr(ai_triage_service.ai_client, "generate", AsyncMock(return_value={"answer": "not json"}))
        await runtime.analyze_incident("inc-2")
        assert await count(factory, ThreatMemory) == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_memory_failure_does_not_lose_the_analysis(tmp_path, monkeypatch, runtime):
    engine, factory = await local_triage_db(tmp_path, monkeypatch, shell_incident("inc-1"))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", AsyncMock(return_value=triage_output(**SHELL_VERDICT)))

    def broken(*args, **kwargs):
        raise RuntimeError("memory database down")
    monkeypatch.setattr(tm, "ThreatMemory", None)  # every lookup/store query now fails
    monkeypatch.setattr(tm, "similarity", broken)
    try:
        result = await runtime.analyze_incident("inc-1")
        raw = source(result)
        assert result is not None and raw["classification"] == "likely_malicious"
        assert raw["analysis_source"] == tm.FRESH and raw["cache_reason"] == "lookup_error"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_same_pattern_calls_model_once_and_stores_one_entry(tmp_path, monkeypatch, runtime):
    incidents = [shell_incident(f"inc-{n}", pid=1000 + n, ip=f"203.0.113.{n}") for n in range(1, 5)]
    engine, factory = await local_triage_db(tmp_path, monkeypatch, *incidents)

    async def slow(*args, **kwargs):
        await asyncio.sleep(0.2)
        return triage_output(**SHELL_VERDICT)
    generate = AsyncMock(side_effect=slow)
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        results = await asyncio.gather(*(runtime.analyze_incident(i.id) for i in incidents))
        assert generate.await_count == 1 and await count(factory, ThreatMemory) == 1
        assert sorted(source(r)["analysis_source"] for r in results) == [tm.EXACT] * 3 + [tm.FRESH]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_fresh_refresh_bypasses_memory_but_not_validation(tmp_path, monkeypatch, runtime):
    engine, factory = await local_triage_db(tmp_path, monkeypatch, shell_incident("inc-1"), shell_incident("inc-2", pid=8))
    generate = AsyncMock(return_value=triage_output(**SHELL_VERDICT))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        await runtime.analyze_incident("inc-1")
        generate.return_value = triage_output("likely_malicious", 0.8, ids=["N9"])  # cites evidence that does not exist
        fresh = await runtime.analyze_incident("inc-2", manual=True, use_memory=False)
        assert generate.await_count == 2
        raw = source(fresh)
        assert raw["analysis_source"] == tm.FALLBACK and raw["status"] == "schema_invalid"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_memory_survives_restart(tmp_path, monkeypatch, triage_tokenizer):  # noqa: F811
    engine, factory = await local_triage_db(tmp_path, monkeypatch, shell_incident("inc-1"), shell_incident("inc-2", pid=9))
    monkeypatch.setattr(ai_triage_service, "load_tokenizer", lambda: triage_tokenizer)
    monkeypatch.setenv("AI_TRIAGE_ENABLE_SKIP", "false")
    generate = AsyncMock(return_value=triage_output(**SHELL_VERDICT))
    monkeypatch.setattr(ai_triage_service.ai_client, "generate", generate)
    try:
        monkeypatch.setattr(ai_triage_service, "triage_queue", TriageQueue(max_waiting=2))
        await ai_triage_service.AITriageService().analyze_incident("inc-1")
        tm._locks.clear()  # a new process: no in-memory state
        monkeypatch.setattr(ai_triage_service, "triage_queue", TriageQueue(max_waiting=2))
        result = await ai_triage_service.AITriageService().analyze_incident("inc-2")
        assert generate.await_count == 1 and source(result)["analysis_source"] == tm.EXACT
    finally:
        await engine.dispose()


def test_rebinding_requires_every_role_in_the_current_incident():
    fp = fingerprint(shell_incident("x"))
    with pytest.raises(tm.Ineligible):
        tm.rebind({"classification": "likely_malicious", "confidence": 0.8,
                   "evidence_roles": ["process:bash", "behavior:sqli_probe_observed"], "techniques": []}, fp)


def test_escalating_chain_changes_the_fingerprint():
    from app.models.incident import Incident

    def chain_incident(stages):
        return Incident(id="c", agent_id="agent-a", title="chain", description="", risk_score=60, status="open",
                        detection_evidence={"rule_id": "web_compromise_chain", "rule_version": "chain:1", "chain": {
                            "conditions": [{"id": s, "status": "OBSERVED"} for s in stages],
                            "process_tree": [], "network": []}})
    medium = chain_incident(["auth_bypass", "suspicious_upload", "command_injection"])
    critical = chain_incident(["auth_bypass", "suspicious_upload", "command_injection", "web_spawned_shell",
                               "outbound_connection"])
    assert fingerprint(medium).value != fingerprint(critical).value
