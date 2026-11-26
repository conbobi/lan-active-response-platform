"""AI SOC Studio: real KPIs, rule table and the Sigma pipeline Generate → Validate → Save → Approve →
Activate → Detect. Isolated SQLite Manager; the model is stubbed, never called."""
import uuid

import pytest
from sqlalchemy import select

from app.models.incident import Incident
from app.models.rule_candidate import RuleCandidate
from app.services.ai import harvest_service as harvest_module
from app.services.ai import validation_service as validation_module
from app.services.rule_engine import RuleEngine
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

RULES = "/api/v1/rules"
METRICS = "/api/v1/dashboard/ai-metrics?period=7d"

SUPPORTED = """title: Shadow copy deletion
logsource: {category: process_creation, product: windows}
detection:
  selection:
    CommandLine|contains: delete shadows
  condition: selection
level: high
tags: [attack.t1490]
"""
FILTERED = """title: Shadow copy deletion with exclusion
logsource: {category: process_creation}
detection:
  selection: {CommandLine|contains: vssadmin}
  filter: {CommandLine|contains: list}
  condition: selection and not filter
level: high
"""
NO_POSITIVE = """title: Linux tool never in the evaluation set
logsource: {category: process_creation, product: linux}
detection:
  selection: {CommandLine|contains: larp-test-unique-token}
  condition: selection
level: low
"""


@pytest.fixture(autouse=True)
def no_model(monkeypatch):
    async def never(*args, **kwargs):
        raise AssertionError("Ollama must not be called in these tests")
    monkeypatch.setattr(validation_module.validation_service, "_generate_llm_fp_explanation", never)


async def add_rule(factory, yaml_text, status="pending"):
    rule_id = uuid.uuid4()
    async with factory.begin() as db:
        db.add(RuleCandidate(id=rule_id, rule_yaml=yaml_text, rule_name=yaml_text.splitlines()[0][7:],
                             source="human", status=status, severity="high", mitre_techniques=["T1490"]))
    return str(rule_id)


def test_empty_database_shows_no_rules_and_no_invented_kpis(lab):
    client, _ = lab
    assert client.get(RULES + "?limit=100").json() == {"total": 0, "items": [], "limit": 100, "offset": 0}
    metrics = client.get(METRICS).json()
    assert metrics["rule_stats"]["total"] == 0 and metrics["rule_stats"]["active"] == 0
    assert metrics["accuracy_metrics"]["avg_fpr"] is None and metrics["accuracy_metrics"]["avg_precision"] is None
    assert metrics["accuracy_metrics"]["measured_rules"] == 0
    assert metrics["ai_triage_stats"]["avg_latency_sec"] is None
    assert metrics["top_mitre_techniques"] == []
    assert all(day["rules_generated"] == 0 and day["avg_fpr"] is None for day in metrics["trend_last_7_days"])


@pytest.mark.asyncio
@pytest.mark.parametrize("model_output,source", [(f"```yaml\n{SUPPORTED}```", "ai_harvest"),
                                                 ("not yaml at all", "template_fallback")])
async def test_harvest_saves_rule_visible_in_table_and_kpis(lab, monkeypatch, model_output, source):
    client, factory = lab

    async def model(text):
        return model_output
    monkeypatch.setattr(harvest_module.harvest_service, "_call_llm_for_sigma", model)
    monkeypatch.setattr(harvest_module, "AsyncSessionLocal", factory)  # harvest opens its own session
    created = client.post(RULES + "/harvest", headers=ADMIN, json={"cti_text": "Attackers ran vssadmin delete shadows"})
    assert created.status_code == 200 and "error" not in created.json(), created.text
    assert created.json()["source"] == source
    async with factory() as db:
        stored = (await db.scalars(select(RuleCandidate))).all()
    assert len(stored) == 1 and stored[0].status == "pending"
    for query in ("", "&status=all", "&status=pending"):
        listed = client.get(RULES + "?limit=100" + query).json()
        assert [item["id"] for item in listed["items"]] == [created.json()["rule_id"]], query
    stats = client.get(METRICS).json()["rule_stats"]
    assert (stats["total"], stats["pending"]) == (1, 1)
    assert stats["by_source"][source] == 1


@pytest.mark.asyncio
async def test_rule_the_engine_cannot_run_is_rejected_with_reason(lab):
    client, factory = lab
    rule_id = await add_rule(factory, FILTERED)
    result = client.post(f"{RULES}/{rule_id}/validate", headers=ADMIN, json={}).json()
    assert result["status"] == "rejected"
    assert result["validation_result"]["verdict"] == "UNSUPPORTED_BY_ENGINE"
    assert "filter" in result["validation_result"]["reason"]
    item = client.get(RULES).json()["items"][0]
    assert item["validation"]["verdict"] == "UNSUPPORTED_BY_ENGINE" and "Detection Engine" in item["notes"]
    assert "error" in client.post(f"{RULES}/{rule_id}/activate", headers=ADMIN, json={}).json()


@pytest.mark.asyncio
async def test_invalid_yaml_is_rejected(lab):
    client, factory = lab
    rule_id = await add_rule(factory, "title: broken\ndetection: [unclosed")
    result = client.post(f"{RULES}/{rule_id}/validate", headers=ADMIN, json={}).json()
    assert result["status"] == "rejected" and result["validation_result"]["passed"] is False


@pytest.mark.asyncio
async def test_rule_matching_no_positive_sample_is_inconclusive_not_validated(lab):
    client, factory = lab
    rule_id = await add_rule(factory, NO_POSITIVE)
    result = client.post(f"{RULES}/{rule_id}/validate", headers=ADMIN, json={}).json()
    assert result["validation_result"]["verdict"] == "INCONCLUSIVE"
    assert result["status"] == "pending"
    assert result["validation_result"]["dataset"]["malicious_fixture"] == 10
    assert client.get(METRICS).json()["accuracy_metrics"]["measured_rules"] == 0
    assert "error" in client.post(f"{RULES}/{rule_id}/activate", headers=ADMIN, json={}).json()


@pytest.mark.asyncio
async def test_validated_rule_activates_and_detects_synthetic_telemetry(lab):
    client, factory = lab
    rule_id = await add_rule(factory, SUPPORTED)
    assert client.post(f"{RULES}/{rule_id}/validate", json={}).status_code == 401  # mutation needs a token
    assert client.post(f"{RULES}/{rule_id}/validate", headers=ANALYST, json={}).status_code == 403
    validated = client.post(f"{RULES}/{rule_id}/validate", headers=ADMIN, json={}).json()
    assert validated["status"] == "validated", validated
    assert validated["validation_result"]["confusion"]["tp"] >= 1
    accuracy = client.get(METRICS).json()["accuracy_metrics"]
    assert accuracy["measured_rules"] == 1 and accuracy["avg_fpr"] == validated["fpr"]

    activated = client.post(f"{RULES}/{rule_id}/activate", headers=ADMIN, json={}).json()
    assert activated["status"] == "active" and activated["engine_supported"] is True

    engine = RuleEngine()
    telemetry = {"agent_id": AGENT, "process_list": [
        {"pid": 4242, "name": "vssadmin.exe", "exe": "C:\\Windows\\System32\\vssadmin.exe",
         "cmdline": "vssadmin.exe delete shadows /all /quiet"},
        {"pid": 4243, "name": "notepad.exe", "exe": "C:\\Windows\\notepad.exe", "cmdline": "notepad.exe"},
    ]}
    async with factory() as db:
        incidents = await engine.evaluate(telemetry, db)
        await db.commit()
    assert len(incidents) == 1, incidents
    async with factory() as db:
        stored = (await db.scalars(select(Incident).where(Incident.id == incidents[0].id))).one()
    assert "Shadow copy deletion" in stored.title


@pytest.mark.asyncio
async def test_editing_active_rule_returns_it_to_pending_and_out_of_the_engine(lab):
    client, factory = lab
    rule_id = await add_rule(factory, SUPPORTED)
    client.post(f"{RULES}/{rule_id}/validate", headers=ADMIN, json={})
    client.post(f"{RULES}/{rule_id}/activate", headers=ADMIN, json={})
    edited = client.put(f"{RULES}/{rule_id}", headers=ADMIN,
                        json={"rule_yaml": SUPPORTED.replace("delete shadows", "resize shadowstorage")})
    assert edited.status_code == 200 and "error" not in edited.json(), edited.text
    item = client.get(RULES).json()["items"][0]
    assert item["status"] == "pending" and item["validation"] is None
    async with factory() as db:
        assert await RuleEngine()._get_active_rules(db) == []


def test_engine_support_check():
    import yaml
    assert RuleEngine.check_sigma_support(yaml.safe_load(SUPPORTED))[0] is True
    for text, fragment in [(FILTERED, "filter"),
                           ("detection: {selection: {User: root}, condition: selection}", "User".lower()),
                           ("detection: {selection: {CommandLine|base64: x}, condition: selection}", "base64"),
                           ("logsource: {category: dns}\ndetection: {selection: {CommandLine: x}, condition: selection}", "dns"),
                           ("detection: {keywords: [mimikatz], condition: keywords}", "keywords")]:
        ok, reason = RuleEngine.check_sigma_support(yaml.safe_load(text))
        assert ok is False and fragment in reason.lower(), (text, reason)
