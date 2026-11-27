"""Rule Assistant: natural language → grounded intent → questions → compiled rule → monitoring → promotion.

The model is stubbed (deterministic) except in the opt-in real test at the bottom.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from sqlalchemy import select

from app.models.incident import Incident
from app.models.rule_candidate import RuleCandidate
from app.models.rule_monitor_hit import RuleMonitorHit
from app.services.ai import rule_assistant as ra
from app.services.ai import validation_service as validation_module
from app.services.ai.ollama_json import GenerationError
from app.services.rule_engine import RuleEngine
from test_http_response_assist import ADMIN, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

RULES = "/api/v1/rules"
WEB = {"pid": 3691, "ppid": 1, "name": "python", "exe": "/usr/bin/python3.13",
       "cmdline": "/opt/larp-agent/venv/bin/python -u /opt/larp-agent/vulnerable_web/app.py"}


def model_answer(**fields):
    answer = {"platform": "unknown", "parent": [], "parent_hint": "", "child": [], "command": [], "chaining": False,
              "severity": "high", "mitre": [], "title": ""}
    answer.update(fields)
    return answer


@pytest.fixture(autouse=True)
def no_fp_explanation(monkeypatch):
    async def never(*args, **kwargs):
        raise AssertionError("Ollama must not be called")
    monkeypatch.setattr(validation_module.validation_service, "_generate_llm_fp_explanation", never)


def stub_model(monkeypatch, *answers):
    calls = []

    async def fake(url, model, system, user, schema, **kwargs):
        calls.append(user)
        answer = answers[min(len(calls), len(answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(ra, "generate_json", fake)
    return calls


@pytest.mark.asyncio
async def test_guessed_values_are_dropped_and_asked_back(monkeypatch):
    # The analyst only says "web server"; the model guesses nginx and bash.
    stub_model(monkeypatch, model_answer(platform="linux", parent=["nginx"], parent_hint="web server",
                                         child=["bash"], command=["whoami"], title="Web shell"))
    intent, notices = await ra.extract("Báo động khi web server trên linux sinh shell chạy whoami", ra.blank_intent())
    assert intent["parent"] == [] and intent["child"] == ["shell"] and intent["command"] == ["whoami"]
    assert any("nginx" in n for n in notices) and any("bash" in n for n in notices)
    asks = ra.questions(intent, {"parents": ["nginx", "app.py"], "scripts": ["app.py"]})
    assert asks[0]["slot"] == "parent" and asks[0]["options"] == ["nginx", "app.py"]


def test_narrative_words_and_bare_interpreters_never_become_observables():
    intent, notices = ra.sanitize({"platform": "linux", "parent": ["python3"], "child": ["sh"],
                                   "command": ["Adversaries", "exploit", "id"]})
    assert intent["command"] == ["id"] and len(notices) == 2
    ask = ra.questions(intent, {"scripts": ["/opt/larp-agent/vulnerable_web/app.py"]})[0]
    assert ask["slot"] == "parent" and ask["replace"] == ["python3"]
    with pytest.raises(ValueError):
        ra.compile_rule(intent)
    fixed = ra.apply_answer(intent, "parent", "vulnerable_web/app.py", ask["replace"])
    assert fixed["parent"] == ["vulnerable_web/app.py"] and ra.questions(fixed) == []


def test_broad_shell_alone_needs_more_evidence_and_compiles_deterministically():
    intent, _ = ra.sanitize({"platform": "linux", "child": ["shell"]})
    # The runtime ignores shells unless the parent is pinned: a parent-less shell rule would never fire.
    assert [a["slot"] for a in ra.questions(intent)] == ["parent"]
    intent = ra.apply_answer(intent, "command", ["whoami", "nối lệnh (; | && $())"])
    assert [a["slot"] for a in ra.questions(intent)] == ["parent"]
    intent = ra.apply_answer(intent, "parent", "vulnerable_web/app.py")
    assert intent["chaining"] and intent["command"] == ["whoami"]
    text, rule = ra.compile_rule(intent)
    selection = rule["detection"]["selection"]
    assert selection["Image|endswith"] == ["/sh", "/dash", "/bash", "/zsh"]
    assert rule["tags"] == ["attack.t1059.004"] and rule["logsource"]["product"] == "linux"
    assert yaml.safe_load(text) == rule and ra.compile_rule(intent)[0] == text


def lab_intent():
    intent, _ = ra.sanitize({"platform": "linux", "parent": ["vulnerable_web/app.py"], "child": ["shell"],
                             "chaining": True, "severity": "high"})
    return intent


@pytest.mark.asyncio
async def test_conversation_create_monitor_then_promote_and_detect(lab, monkeypatch):
    client, factory = lab
    monkeypatch.setattr(ra, "DEFAULT_MODEL", "stub-model")
    stub_model(monkeypatch, model_answer(platform="linux", parent=["python3"], child=["shell"], chaining=True,
                                         mitre=["T1059.004"], title="Web app spawning shell with injected command"))
    first = client.post(RULES + "/assistant", headers=ADMIN, json={
        "message": "Báo trên Linux khi python3 của web app sinh shell và có chèn lệnh (; hoặc &&)"}).json()
    assert first["model_used"] and not first["ready"]
    ask = first["questions"][0]
    assert ask["slot"] == "parent" and ask["replace"] == ["python3"]

    second = client.post(RULES + "/assistant", headers=ADMIN, json={
        "conversation_id": first["conversation_id"], "revision": first["revision"], "answer": {"slot": "parent", "value": "vulnerable_web/app.py",
                                              "replace": ask["replace"]}}).json()
    assert second["ready"] and not second["model_used"]
    assert "ParentCommandLine|contains" in second["sigma_yaml"]

    created = client.post(RULES + "/assistant/create", headers=ADMIN, json={
        "conversation_id": second["conversation_id"], "revision": second["revision"], "intent": {}, "description": "web app sinh shell có chèn lệnh", "model_used": True}).json()
    assert created["status"] == "monitoring", created
    assert created["validation_result"]["confusion"] == {"tp": 9, "fp": 0, "fn": 0, "tn": 36}
    assert created["recent_telemetry"]["labelled"] is False
    assert created["promotion"]["allowed"] is True
    rule_id = created["rule_id"]

    telemetry = {"agent_id": AGENT, "process_list": [
        {**WEB, "process_start_time": 1764126363.0},
        {"pid": 80001, "ppid": 3691, "name": "sh", "exe": "/usr/bin/dash",
         "cmdline": "/bin/sh -c ping -c 1 127.0.0.1;id", "process_start_time": 1764157200.5},
        {"pid": 80002, "ppid": 3691, "name": "sh", "exe": "/usr/bin/dash",
         "cmdline": "/bin/sh -c ping -c 1 8.8.8.8", "process_start_time": 1764157201.5},
    ]}
    for _ in range(2):  # the same process seen in two snapshots is one hit
        async with factory() as db:
            assert await RuleEngine().evaluate(telemetry, db) == []
            await db.commit()
    hits = client.get(f"{RULES}/{rule_id}/monitor-hits").json()
    assert hits["total"] == 1 and hits["items"][0]["process"]["pid"] == 80001
    assert hits["items"][0]["process"]["parent"]["pid"] == 3691
    async with factory() as db:
        sigma = [i for i in (await db.scalars(select(Incident))).all()
                 if (i.detection_evidence or {}).get("rule_id") == rule_id]
        assert sigma == []  # the lab fixture's seeded HTTP incident is unrelated

    activated = client.post(f"{RULES}/{rule_id}/activate", headers=ADMIN, json={}).json()
    assert activated["status"] == "active", activated
    async with factory() as db:
        incidents = await RuleEngine().evaluate(telemetry, db)
        await db.commit()
        stored = await db.get(RuleCandidate, uuid.UUID(rule_id))
    assert len(incidents) == 1 and stored.approved_by == "admin" and stored.source == "ai_assistant"
    assert stored.model_generated == "stub-model"


@pytest.mark.asyncio
async def test_rule_without_labelled_data_is_promotable_only_after_monitoring(lab):
    client, factory = lab
    intent, _ = ra.sanitize({"platform": "linux", "parent": ["postgres"], "child": ["sh"], "command": ["curl"]})
    created = client.post(RULES + "/assistant/create", headers=ADMIN, json={"intent": intent}).json()
    assert created["status"] == "monitoring" and created["validation_result"]["verdict"] == "INCONCLUSIVE"
    assert created["promotion"]["allowed"] is False and "24" in created["promotion"]["reason"]
    assert "error" in client.post(f"{RULES}/{created['rule_id']}/activate", headers=ADMIN, json={}).json()
    async with factory.begin() as db:
        rule = await db.get(RuleCandidate, uuid.UUID(created["rule_id"]))
        rule.validated_at = datetime.now(timezone.utc) - timedelta(hours=25)
    assert client.post(f"{RULES}/{created['rule_id']}/activate", headers=ADMIN, json={}).json()["status"] == "active"


@pytest.mark.asyncio
async def test_failed_rule_keeps_monitoring_but_cannot_be_promoted(lab):
    client, _ = lab
    # Any shell from the web app: the legitimate /ping use makes it fail on the labelled set.
    intent, _ = ra.sanitize({"platform": "linux", "parent": ["vulnerable_web/app.py"], "child": ["sh"],
                             "mitre": ["T1059.004"]})
    created = client.post(RULES + "/assistant/create", headers=ADMIN, json={"intent": intent}).json()
    assert created["validation_result"]["verdict"] == "FAILED"
    assert created["promotion"]["allowed"] is False
    assert "error" in client.post(f"{RULES}/{created['rule_id']}/activate", headers=ADMIN, json={}).json()


def test_model_failure_is_reported_not_faked(lab, monkeypatch):
    client, _ = lab
    stub_model(monkeypatch, GenerationError("Ollama generation timed out"))
    reply = client.post(RULES + "/assistant", headers=ADMIN, json={"message": "báo khi chạy mimikatz"}).json()
    assert reply["model_used"] is False and "timed out" in reply["error"]
    assert reply["intent"]["child"] == [] and not reply["ready"]


def test_assistant_requires_authentication(lab):
    client, _ = lab
    assert client.post(RULES + "/assistant", json={"message": "x"}).status_code == 401
    assert client.post(RULES + "/assistant/create", json={"intent": {}}).status_code == 401


@pytest.mark.skipif(os.getenv("LARP_REAL_HARVEST") != "1", reason="requires local Ollama")
@pytest.mark.asyncio
@pytest.mark.parametrize("message", [
    "Báo động khi web app vulnerable_web/app.py trên Linux sinh shell và có chèn lệnh như ; hoặc &&",
    "Alert when the web server spawns bash running whoami or curl",
])
async def test_real_model_extracts_grounded_intent(monkeypatch, message):
    monkeypatch.setattr(ra, "OLLAMA_URL", os.getenv("OLLAMA_URL", "http://localhost:11434"))
    intent, notices = await ra.extract(message, ra.blank_intent(), url=os.getenv("OLLAMA_URL", "http://localhost:11434"))
    print("\n", message, "\n", intent, "\n", notices, "\n", ra.questions(intent))
    for key in ("parent", "child", "command"):
        assert all(v.lower() in message.lower() or ra._base(v) in message.lower() for v in intent[key])
    if not ra.questions(intent):
        ra.compile_rule(intent)
