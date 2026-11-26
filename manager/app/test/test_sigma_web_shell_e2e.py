"""Use case "Web Server Spawning Shell": validator/runtime equivalence on the labelled Linux dataset
and the full Generate → Save → Validate → Approve/Activate → Evaluate → Detection flow.

Telemetry for the runtime step is built from dataset records (marked synthetic or lab snapshot);
the model is stubbed so the test is deterministic.
"""
import json
import os
import uuid

import pytest
import yaml
from sqlalchemy import select

from app.models.incident import Incident
from app.models.rule_candidate import RuleCandidate
from app.services.ai import harvest_service as harvest_module
from app.services.ai import validation_service as validation_module
from app.services.ai.validation_service import DATASET_DIR, LINUX_DATASET, labelled_dataset
from app.services.detection import sigma_runtime
from app.services.rule_engine import RuleEngine
from test_http_response_assist import ADMIN, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

RULES = "/api/v1/rules"

WEB_SHELL_RULE = """title: Web Server Spawning Shell With Injected Command
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentCommandLine|contains: vulnerable_web/app.py
    Image|endswith:
      - /dash
      - /sh
      - /bash
    CommandLine|re: '[;|&`]|\\$\\('
  condition: selection
level: high
tags:
  - attack.t1190
  - attack.t1059.004
"""
BROAD_RULE = """title: Web Server Spawning Any Shell
logsource: {category: process_creation, product: linux}
detection:
  selection:
    ParentCommandLine|contains: vulnerable_web/app.py
    Image|endswith: [/dash, /sh, /bash]
  condition: selection
level: medium
tags: [attack.t1059.004]
"""


def dataset_rows():
    return [json.loads(line) for line in (DATASET_DIR / LINUX_DATASET).read_text().splitlines()]


def runtime_snapshot(row, start=1764155000.0):
    """Agent-shaped process_list for one record: the parent and the child, linked only by PID."""
    child = {**row["process"], "process_start_time": start + 1}
    snapshot = [child]
    if row.get("parent"):
        parent = row["parent"]
        snapshot.append({"pid": parent["pid"], "ppid": 1, "name": parent["name"], "exe": parent["exe"],
                         "cmdline": parent["cmdline"], "process_start_time": start})
    return snapshot


def runtime_matches(rule_text, row):
    rule = yaml.safe_load(rule_text)
    mitre = [t.split(".", 1)[1].upper() for t in rule.get("tags", [])]
    events = sigma_runtime.candidates(rule, {"process_list": runtime_snapshot(row)})
    hits = sigma_runtime.matching_events(rule, events, mitre=mitre, name=rule["title"])
    return any(e.get("pid") == row["process"]["pid"] for e in hits)


@pytest.fixture(autouse=True)
def no_model(monkeypatch):
    async def never(*args, **kwargs):
        raise AssertionError("Ollama must not be called")
    monkeypatch.setattr(validation_module.validation_service, "_generate_llm_fp_explanation", never)


@pytest.mark.asyncio
@pytest.mark.parametrize("rule_text", [WEB_SHELL_RULE, BROAD_RULE])
async def test_validator_and_runtime_agree_on_every_labelled_event(rule_text):
    rule = yaml.safe_load(rule_text)
    records, _ = labelled_dataset(rule)
    mitre = [t.split(".", 1)[1].upper() for t in rule.get("tags", [])]
    validator_hits = {id(e) for e in sigma_runtime.matching_events(
        rule, [r["event"] for r in records], mitre=mitre, name=rule["title"])}
    by_id = {r["event_id"]: id(r["event"]) in validator_hits for r in records}
    rows = dataset_rows()
    assert len(rows) == len(records)
    for row in rows:
        assert runtime_matches(rule_text, row) == by_id[row["event_id"]], row["event_id"]


@pytest.mark.asyncio
async def test_labelled_metrics_separate_targeted_and_broad_rules():
    service = validation_module.ValidationService()
    targeted = await service.validate_rule(WEB_SHELL_RULE)
    assert targeted["verdict"] == "PASSED", targeted["reason"]
    assert targeted["confusion"] == {"tp": 9, "fp": 0, "fn": 0, "tn": 36}
    assert targeted["dataset"]["by_source"]["lab_vps_snapshot"] == {"attack": 0, "benign": 24}
    broad = await service.validate_rule(BROAD_RULE)
    assert broad["verdict"] == "FAILED"
    assert broad["confusion"]["fp"] == 3  # legitimate /ping use also spawns /bin/sh from the web app
    assert {s["scenario"] for s in broad["fp_samples"]} == {"web_ping_legitimate"}


@pytest.mark.asyncio
async def test_valid_rule_missing_every_relevant_attack_fails_with_recall_zero():
    # Shape of a real model answer: web servers that the lab does not run, so the 9 lab attacks are missed.
    rule = WEB_SHELL_RULE.replace("ParentCommandLine|contains: vulnerable_web/app.py",
                                  "ParentImage|endswith: [/nginx, /apache2, /httpd]")
    result = await validation_module.ValidationService().validate_rule(rule, cti_text="Web Server Spawning Shell (T1059.004)")
    assert result["verdict"] == "FAILED" and "Recall 0%" in result["reason"]
    assert result["confusion"] == {"tp": 0, "fp": 0, "fn": 9, "tn": 36}
    assert result["recall"] == 0.0 and result["precision"] is None and result["dataset"]["datasets"][0]["name"] == LINUX_DATASET


@pytest.mark.asyncio
async def test_too_little_labelled_data_is_inconclusive(monkeypatch):
    monkeypatch.setattr(validation_module, "MIN_ATTACK", 50)
    result = await validation_module.ValidationService().validate_rule(WEB_SHELL_RULE)
    assert result["verdict"] == "INCONCLUSIVE" and "Chưa đủ dữ liệu" in result["reason"]
    assert result["fpr"] is None and result["precision"] is None


@pytest.mark.asyncio
async def test_generate_save_validate_activate_detect(lab, monkeypatch):
    client, factory = lab

    async def model(text, feedback=None):  # Agent A output, stubbed: same shape the harvest model is asked for
        return WEB_SHELL_RULE
    monkeypatch.setattr(harvest_module.harvest_service, "_call_llm_for_sigma", model)
    monkeypatch.setattr(harvest_module, "AsyncSessionLocal", factory)

    created = client.post(RULES + "/harvest", headers=ADMIN, json={
        "cti_text": "Attackers abuse the /ping endpoint of a Flask app: shell metacharacters make the web "
                    "server spawn /bin/sh and run id, whoami and reverse shells."}).json()
    assert created["status"] == "pending" and created["source"] == "ai_harvest", created
    rule_id = created["rule_id"]
    listed = client.get(RULES + "?limit=100").json()["items"]
    assert [r["id"] for r in listed] == [rule_id]

    validated = client.post(f"{RULES}/{rule_id}/validate", headers=ADMIN, json={}).json()
    assert validated["status"] == "validated", validated
    assert validated["validation_result"]["confusion"] == {"tp": 9, "fp": 0, "fn": 0, "tn": 36}
    activated = client.post(f"{RULES}/{rule_id}/activate", headers=ADMIN, json={"analyst_id": "soc_lead"}).json()
    assert activated["status"] == "active" and activated["engine_supported"] is True
    metrics = client.get("/api/v1/dashboard/ai-metrics").json()
    assert metrics["rule_stats"]["active"] == 1 and metrics["accuracy_metrics"]["measured_rules"] == 1

    rows = {r["event_id"]: r for r in dataset_rows()}
    web = rows["vps-3691"]["process"]
    agent = rows["vps-49094"]["process"]
    telemetry = {"agent_id": AGENT, "timestamp": "2026-11-26T11:40:00+00:00", "process_list": [
        {**web, "process_start_time": 1764126363.0},
        {**agent, "process_start_time": 1764150775.0},
        {"pid": 80001, "ppid": web["pid"], "name": "sh", "exe": "/usr/bin/dash",
         "cmdline": "/bin/sh -c ping -c 1 127.0.0.1;id", "process_start_time": 1764157200.5},
        {"pid": 80002, "ppid": web["pid"], "name": "sh", "exe": "/usr/bin/dash",
         "cmdline": "/bin/sh -c ping -c 1 8.8.8.8", "process_start_time": 1764157201.5},
        {"pid": 80003, "ppid": agent["pid"], "name": "journalctl", "exe": "/usr/bin/journalctl",
         "cmdline": "journalctl -u cloudflared -u vulnerable_web -f -o json -n 0", "process_start_time": 1764157202.0},
    ]}
    async with factory() as db:
        incidents = await RuleEngine().evaluate(telemetry, db)
        await db.commit()
    assert len(incidents) == 1, [i.title for i in incidents]
    async with factory() as db:
        incident = (await db.scalars(select(Incident).where(Incident.id == incidents[0].id))).one()
        stored_rule = await db.get(RuleCandidate, uuid.UUID(rule_id))
    assert stored_rule.approved_by == "admin"
    evidence = incident.detection_evidence
    assert evidence["rule_id"] == rule_id and stored_rule.status == "active"
    assert evidence["process"]["pid"] == 80001 and evidence["process"]["cmdline"].endswith(";id")
    assert evidence["evidence_id"].startswith("proc_")
    assert evidence["parent"]["pid"] == web["pid"] and "vulnerable_web/app.py" in evidence["parent"]["cmdline"]
    assert "Web Server Spawning Shell" in incident.title

WEB_CTI = (
    "Adversaries exploit web application vulnerabilities (RCE, command injection) on web servers "
    "(python3 app.py, nginx, apache2, gunicorn, uwsgi) to spawn interactive shells "
    "(/bin/sh, /bin/bash, /bin/dash, zsh). The resulting child shell executes reconnaissance "
    "commands like whoami, id, or curl to retrieve second-stage payloads."
)


@pytest.mark.asyncio
@pytest.mark.parametrize("output", [
    "", "```yaml\n" + WEB_SHELL_RULE + "```", WEB_SHELL_RULE.replace("linux", "windows"),
    BROAD_RULE, WEB_SHELL_RULE.replace("vulnerable_web/app.py", "python3"),
    WEB_SHELL_RULE.replace("vulnerable_web/app.py", "Adversaries"),
    WEB_SHELL_RULE.replace("condition: selection", "condition: selection or filter"),
])
async def test_generation_failure_saves_nothing(lab, monkeypatch, output):
    client, factory = lab

    async def model(text, feedback=None):
        return output

    monkeypatch.setattr(harvest_module.harvest_service, "_call_llm_for_sigma", model)
    monkeypatch.setattr(harvest_module, "AsyncSessionLocal", factory)
    response = client.post(RULES + "/harvest", headers=ADMIN, json={"cti_text": WEB_CTI})
    assert response.status_code == 502 and "generation failed" in response.json()["detail"]
    assert client.get(RULES).json()["total"] == 0


@pytest.mark.asyncio
async def test_generation_retries_are_bounded_and_carry_the_rejection(lab, monkeypatch):
    client, factory = lab
    calls = []
    bad = WEB_SHELL_RULE.replace("ParentCommandLine|contains: vulnerable_web/app.py",
                                 "ParentImage|endswith: python3 app.py")

    async def model(text, feedback=None):
        calls.append(feedback)
        return bad if len(calls) == 1 else WEB_SHELL_RULE

    monkeypatch.setattr(harvest_module.harvest_service, "_call_llm_for_sigma", model)
    monkeypatch.setattr(harvest_module, "AsyncSessionLocal", factory)
    assert client.post(RULES + "/harvest", headers=ADMIN, json={"cti_text": WEB_CTI}).status_code == 200
    assert calls[0] is None and "ParentImage" in calls[1] and len(calls) == 2

    calls.clear()
    monkeypatch.setattr(harvest_module, "MAX_ATTEMPTS", 2)

    async def always_bad(text, feedback=None):
        calls.append(feedback)
        return bad
    monkeypatch.setattr(harvest_module.harvest_service, "_call_llm_for_sigma", always_bad)
    response = client.post(RULES + "/harvest", headers=ADMIN, json={"cti_text": WEB_CTI})
    assert response.status_code == 502 and "after 2 model attempt" in response.json()["detail"]
    assert len(calls) == 2 and client.get(RULES).json()["total"] == 1


@pytest.mark.skipif(os.getenv("LARP_REAL_HARVEST") != "1", reason="requires local Ollama")
@pytest.mark.parametrize("cti", [WEB_CTI, "Web Server Spawning Shell (T1059.004)"])
def test_real_ollama_generate_save_validate(lab, monkeypatch, cti):
    """Real model, no stub: LARP_REAL_HARVEST=1 OLLAMA_URL=http://localhost:11434 pytest -k real_ollama -s"""
    client, factory = lab
    monkeypatch.setattr(harvest_module, "AsyncSessionLocal", factory)
    response = client.post(RULES + "/harvest", headers=ADMIN, json={"cti_text": cti})
    assert response.status_code == 200, response.text
    candidate = response.json()
    assert candidate["status"] == "pending" and candidate["source"] == "ai_harvest", candidate
    path = f"{RULES}/{candidate['rule_id']}"
    stored = client.get(path).json()
    assert stored["rule_yaml"] == candidate["rule_yaml"] and stored["model_generated"]
    rule = yaml.safe_load(stored["rule_yaml"])
    assert rule["logsource"] == {"product": "linux", "category": "process_creation"}
    assert sigma_runtime.check_support(rule)[0]
    result = client.post(path + "/validate", headers=ADMIN, json={}).json()["validation_result"]
    print(stored["model_generated"], stored["rule_yaml"], result["verdict"], result["confusion"])
    assert result["dataset"]["datasets"][0]["name"] == LINUX_DATASET
    assert result["confusion"] is not None
    assert client.get(path).json()["status"] != "active"


@pytest.mark.asyncio
async def test_dataset_routes_only_relevant_independent_labels():
    from test_ai_soc_studio import SUPPORTED

    service = validation_module.ValidationService()
    windows = await service.validate_rule(SUPPORTED)
    assert windows["dataset"]["datasets"][0]["name"] == "windows_fixture_v1"
    assert windows["dataset"]["attack"] == 2 and windows["confusion"] is None
    assert not windows["passed"]  # fewer than five labelled target attacks
    mismatch = await service.validate_rule(SUPPORTED, cti_text=WEB_CTI)
    assert mismatch["confusion"] is None and "linux" in mismatch["reason"]
    network = await service.validate_rule(WEB_SHELL_RULE.replace("process_creation", "network_connection"))
    assert network["confusion"] is None and network["verdict"] == "INCONCLUSIVE"
