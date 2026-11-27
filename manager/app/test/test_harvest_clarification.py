"""AI Harvest clarification workflow (UAT tests A–E): classify → ask back → answer → compile.

Two kinds of tests live here:
* deterministic ones stub the model (MOCKED MODEL: they check the backend workflow, not model quality);
* ``test_real_model_uat`` (opt-in, LARP_REAL_HARVEST=1) sends the five UAT requests through the HTTP API
  of an isolated Manager (SQLite lab) to the real Ollama model and writes what it returned as evidence.
"""
import json
import os
import pathlib

import pytest
import yaml

from app.core.config import NetworkOperator, settings
from app.services.ai import rule_assistant as ra
from test_http_response_assist import ADMIN, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT, digest, header
from test_rule_assistant import model_answer, no_fp_explanation, stub_model  # noqa: F401

TURN = "/api/v1/rules/assistant"

A = "Phát hiện web server Linux sinh tiến trình shell sau khi nhận request HTTP đáng ngờ."
B = "Tạo luật phát hiện hacker vào server."
C = "Tôi không biết Sigma là gì. Tôi muốn phát hiện ai đó chiếm quyền web server."
D = "Phát hiện mọi hacker, kể cả khi không có log."
E = "Tạo luật Windows để phát hiện /bin/sh chạy trên Linux."


def turn(client, reply=None, headers=ADMIN, **body):
    if reply:
        body = {"conversation_id": reply["conversation_id"], "revision": reply["revision"], **body}
    response = client.post(TURN, headers=headers, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def slots(reply):
    return [q["slot"] for q in reply["questions"]]


def test_vague_request_is_asked_back_not_compiled(lab, monkeypatch):
    client, _ = lab
    # The model guesses a platform and processes the analyst never wrote.
    stub_model(monkeypatch, model_answer(platform="linux", child=["bash", "sh"], command=["whoami"],
                                         title="Detect hacker activity on server"))
    reply = turn(client, message=B)
    assert reply["classification"] == "NEEDS_CLARIFICATION" and reply["sigma_yaml"] is None
    assert reply["intent"]["platform"] is None and reply["intent"]["child"] == []
    assert slots(reply)[:2] == ["scenario", "platform"]
    assert set(reply["questions"][0]["options"]) == set(ra.SCENARIOS)


def test_admin_without_sigma_knowledge_gets_primer_and_picks_an_option(lab, monkeypatch):
    client, _ = lab
    calls = stub_model(monkeypatch, model_answer(platform="unknown", parent_hint="web server",
                                                 title="Web server compromise"))
    first = turn(client, message=C)
    assert ra.SIGMA_PRIMER in first["notices"] and slots(first)[0] == "scenario"

    picked = turn(client, first, answer={"slot": "scenario", "value": "Web process sinh shell"})
    assert picked["intent"]["child"] == ["shell"] and "platform" in slots(picked) and "parent" in slots(picked)
    linux = turn(client, picked, answer={"slot": "platform", "value": "linux"})
    done = turn(client, linux, answer={"slot": "parent", "value": "vulnerable_web/app.py"})
    assert done["classification"] == "READY_TO_GENERATE" and len(calls) == 1  # answers never call the model
    rule = yaml.safe_load(done["sigma_yaml"])
    assert rule["logsource"] == {"category": "process_creation", "product": "linux"}
    assert rule["detection"]["selection"] == {"ParentCommandLine|contains": ["vulnerable_web/app.py"],
                                              "Image|endswith": ["/sh", "/dash", "/bash", "/zsh"]}


def test_chain_only_behaviour_is_not_forced_into_sigma(lab, monkeypatch):
    client, _ = lab
    stub_model(monkeypatch, model_answer(parent_hint="web server"))
    first = turn(client, message=C)
    reply = turn(client, first, answer={"slot": "scenario", "value": "Upload được thực thi"})
    assert reply["classification"] == "UNSUPPORTED_REQUIREMENT" and reply["sigma_yaml"] is None
    assert reply["questions"] == [] and ra.CHAIN_ONLY in reply["notices"]


def test_no_telemetry_request_never_reaches_the_model(lab, monkeypatch):
    client, _ = lab
    calls = stub_model(monkeypatch, model_answer(platform="linux", child=["bash"]))
    reply = turn(client, message=D)
    assert calls == [] and reply["classification"] == "INSUFFICIENT_TELEMETRY"
    assert reply["questions"] == [] and reply["sigma_yaml"] is None and ra.NO_GUARANTEE in reply["notices"]


def test_platform_conflict_is_asked_and_a_linux_shell_is_never_a_windows_rule(lab, monkeypatch):
    client, _ = lab
    stub_model(monkeypatch, model_answer(platform="linux", child=["sh"], title="Detect /bin/sh"))
    first = turn(client, message=E)
    assert first["classification"] == "NEEDS_CLARIFICATION" and first["intent"]["platform"] is None
    assert first["intent"]["child"] == ["sh"] and slots(first)[0] == "platform"

    windows = turn(client, first, answer={"slot": "platform", "value": "windows"})
    assert windows["sigma_yaml"] is None and slots(windows)[0] == "child"
    assert windows["questions"][0]["replace"] == ["sh"]
    assert "platform" in slots(windows)  # the analyst can still switch the platform instead
    linux = turn(client, windows, answer={"slot": "platform", "value": "linux"})
    # A bare sh is ignored by the runtime safe-process policy unless its parent is named.
    assert linux["intent"]["platform"] == "linux" and slots(linux) == ["parent"]
    assert "safe-process" in linux["questions"][0]["text"]


def test_clear_request_asks_only_for_the_unnamed_parent(lab, monkeypatch):
    client, _ = lab
    stub_model(monkeypatch, model_answer(platform="linux", parent=["nginx"], parent_hint="web server",
                                         child=["shell"], mitre=["T1059.004"]))
    reply = turn(client, message=A)
    assert reply["intent"]["platform"] == "linux" and reply["intent"]["parent"] == []
    assert slots(reply) == ["parent"] and any("nginx" in n for n in reply["notices"])
    assert any("không thấy request HTTP" in n for n in reply["notices"])


def test_conversation_state_is_private_versioned_and_bound_to_creation(lab, monkeypatch):
    client, _ = lab
    other = "second-admin-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {**settings.NETWORK_OPERATORS, "admin2": NetworkOperator(
        role="admin", agents={AGENT}, token_sha256=digest(other))})
    stub_model(monkeypatch, model_answer(platform="linux", parent_hint="web server", child=["shell"]))
    first = turn(client, message=A)
    assert turn(client, first, resume=True) == first
    assert client.post(TURN, headers=header(other), json={"conversation_id": first["conversation_id"],
                                                    "revision": 1, "resume": True}).status_code == 404
    unasked = client.post(TURN, headers=ADMIN, json={"conversation_id": first["conversation_id"], "revision": 1,
                                                     "answer": {"slot": "command", "value": "id"}})
    assert unasked.status_code == 422
    second = turn(client, first, answer={"slot": "parent", "value": "vulnerable_web/app.py"})
    stale = client.post(TURN, headers=ADMIN, json={"conversation_id": first["conversation_id"], "revision": 1,
                                                   "answer": {"slot": "parent", "value": "x.py"}})
    assert stale.status_code == 409
    assert client.post(TURN + "/create", headers=ADMIN, json={
        "conversation_id": first["conversation_id"], "revision": 1, "intent": {}}).status_code == 409
    # The rule is built from the stored conversation, not from an intent the browser sends.
    created = client.post(TURN + "/create", headers=ADMIN, json={
        "conversation_id": second["conversation_id"], "revision": second["revision"],
        "intent": {"platform": "windows", "child": ["cmd.exe"]}}).json()
    assert "ParentCommandLine|contains" in created["rule_yaml"] and "product: linux" in created["rule_yaml"]


REAL_CASES = {"A": A, "B": B, "C": C, "D": D, "E": E}


@pytest.mark.skipif(os.getenv("LARP_REAL_HARVEST") != "1", reason="requires the real Ollama model")
@pytest.mark.parametrize("case", sorted(REAL_CASES))
def test_real_model_uat(lab, case):
    """REAL MODEL, isolated DB. Assertions are the UAT acceptance criteria; the reply is saved as evidence."""
    client, _ = lab
    reply = turn(client, message=REAL_CASES[case])
    out = pathlib.Path(os.getenv("LARP_UAT_EVIDENCE", "/tmp/uat-evidence"))
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{case}.json").write_text(json.dumps({"input": REAL_CASES[case], "response": reply},
                                                 ensure_ascii=False, indent=2))
    intent = reply["intent"]
    for key in ("parent", "child", "command"):  # nothing the analyst did not write
        assert all(ra._base(v) in REAL_CASES[case].lower() or v.lower() in REAL_CASES[case].lower()
                   or v == "shell" for v in intent[key]), (key, intent[key])
    if case == "A":
        assert intent["platform"] == "linux" and "shell" in intent["child"] and reply["sigma_yaml"] is None
        assert "parent" in slots(reply)
    if case in ("B", "C"):
        assert reply["classification"] == "NEEDS_CLARIFICATION" and "scenario" in slots(reply)
        assert intent["platform"] is None
    if case == "C":
        assert ra.SIGMA_PRIMER in reply["notices"]
    if case == "D":
        assert reply["classification"] == "INSUFFICIENT_TELEMETRY" and not reply["model_used"]
    if case == "E":
        assert reply["classification"] == "NEEDS_CLARIFICATION" and slots(reply)[0] == "platform"
