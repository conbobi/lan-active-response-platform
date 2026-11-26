"""P0 regression: AI response proposal routing for HTTP incidents (RESPONSE_ROOT_CAUSE.md).

Reproduces the production symptom on inc_d7242d3eb8fa: the legacy suggestion path silently produced
nothing for an HTTP incident, the legacy quick action answered a bare 400 and no failure carried a
machine-readable outcome. Uses the isolated SQLite/stub-model fixture of the Response Assist suite.
"""
import pytest
from sqlalchemy import func, select

from app.models.ai_analysis import AIAnalysis
from app.models.command import Command
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.enums import IncidentStatus
from test_http_response_assist import ADMIN, ANALYST, PATH, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

BASE = "/api/v1/incidents/inc"


async def _counts(factory):
    async with factory() as db:
        return (await db.scalar(select(func.count()).select_from(ResponseAction)),
                await db.scalar(select(func.count()).select_from(Command)))


@pytest.mark.asyncio
async def test_legacy_quick_isolate_on_http_incident_is_policy_denied(lab):
    client, factory = lab
    before = await _counts(factory)
    r = client.post(f"{BASE}/action", headers=ADMIN, json={"action_type": "isolate", "params": {"confirmed": True}})
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["outcome_code"] == "POLICY_DENIED"
    assert body["use"] == "response_assist"
    assert await _counts(factory) == before  # nothing persisted or dispatched


def test_legacy_quick_action_rejects_unknown_type_as_validation_error(lab):
    client, _ = lab
    r = client.post(f"{BASE}/action", headers=ADMIN, json={"action_type": "refresh", "params": {}})
    assert r.status_code == 400
    assert r.json()["outcome_code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_legacy_suggest_for_http_incident_is_rejected_synchronously(lab):
    client, factory = lab
    async with factory.begin() as db:
        db.add(AIAnalysis(id="ai_t", incident_id="inc", summary="triage", confidence=0.6))
    r = client.post(f"{BASE}/ai-analysis/suggest-response", headers=ADMIN)
    assert r.status_code == 409, r.text
    assert r.json()["outcome_code"] == "POLICY_DENIED"
    assert r.json()["use"] == "response_assist"


@pytest.mark.asyncio
async def test_legacy_suggest_without_triage_reports_insufficient_evidence(lab):
    client, factory = lab
    async with factory.begin() as db:
        db.add(Incident(id="inc_host", title="host", risk_score=70, agent_id=AGENT, detection_evidence={}))
    r = client.post("/api/v1/incidents/inc_host/ai-analysis/suggest-response", headers=ADMIN)
    assert r.status_code == 409, r.text
    assert r.json()["outcome_code"] == "INSUFFICIENT_EVIDENCE"


def test_response_assist_failures_are_distinguished(lab):
    client, _ = lab
    unauth = client.get(PATH)
    assert unauth.status_code == 401 and unauth.json()["outcome_code"] == "AUTHORIZATION_FAILED"

    created = client.post(PATH, headers=ANALYST, json={})
    assert created.status_code == 200, created.text
    assert created.json()["outcome_code"] == "APPROVAL_REQUIRED"
    url = "/api/v1/response-actions/" + created.json()["action_id"]

    forbidden = client.post(url + "/approve", headers=ANALYST, json={})
    assert forbidden.status_code == 403 and forbidden.json()["outcome_code"] == "AUTHORIZATION_FAILED"

    early = client.post(url + "/execute", headers=ADMIN, json={})
    assert early.status_code == 409 and early.json()["outcome_code"] == "APPROVAL_REQUIRED"

    assert client.post(url + "/approve", headers=ADMIN, json={}).json()["outcome_code"] == "SUCCESS"
    offline = client.post(url + "/execute", headers=ADMIN, json={})
    assert offline.status_code == 409 and offline.json()["outcome_code"] == "AGENT_OFFLINE"

    invalid = client.post(PATH, headers=ANALYST, json={"action_type": "run_shell"})
    assert invalid.status_code == 422 and invalid.json()["outcome_code"] == "VALIDATION_ERROR"

    no_block = client.post(PATH, headers=ANALYST, json={"action_type": "temporary_ip_block"})
    assert no_block.status_code == 409 and no_block.json()["outcome_code"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.asyncio
async def test_historical_incident_remains_readable_and_host_score_does_not_erase_http_evidence(lab):
    client, factory = lab
    async with factory.begin() as db:
        incident = await db.get(Incident, "inc")
        incident.status = IncidentStatus.RESOLVED
        incident.risk_score = 0.0
    r = client.get(PATH, headers=ANALYST)
    assert r.status_code == 200, r.text
    investigation = r.json()["investigation"]
    assert investigation["classification"] == "sqli_tool_indicator"
    kinds = {p["action_type"] for p in investigation["recommended_responses"]}
    assert "temporary_ip_block" not in kinds and "apply_rate_limit" not in kinds
