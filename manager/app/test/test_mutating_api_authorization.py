"""P1 regression: every state-changing API needs a configured operator once credentials exist.

Before this change the auth middleware exempted /incidents, /agents, /groups, /policies, /settings,
/whitelist, /risk and /attack, so isolate/kill/policy/whitelist changes needed no credentials and the
actor was whatever name the client sent (CODE_MAP.md, security findings).
"""
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from test_http_response_assist import ADMIN, ANALYST, PATH, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

ADMIN_ONLY = [
    ("post", "/api/v1/incidents/inc/action", {"action_type": "isolate", "params": {"confirmed": True}}),
    ("post", "/api/v1/incidents/inc/ai-analysis/apply-suggestion", {"analyst": "x", "confirmed": True}),
    ("delete", "/api/v1/incidents/inc", None),
    ("post", "/api/v1/incidents/bulk-delete", {"incident_ids": ["inc"]}),
    ("post", f"/api/v1/agents/{AGENT}/isolate", {"confirmed": True}),
    ("post", f"/api/v1/agents/{AGENT}/quarantine", {}),
    ("post", "/api/v1/groups/g1/actions", {"action_type": "isolate"}),
    ("post", "/api/v1/policies", {}),
    ("post", "/api/v1/policies/evaluate", {}),
    ("put", "/api/v1/settings/auto_response_enabled", {"value": True}),
    ("post", "/api/v1/whitelist/", {"type": "process", "value": "x"}),
    ("post", "/api/v1/risk/evaluate", {}),
    ("post", "/api/v1/attack/syn-flood", {}),
    ("post", "/api/v1/agents/heartbeat", {}),
    ("post", "/api/v1/events/", {}),
]


def call(client, method, url, body, headers=None):
    kwargs = {"headers": headers or {}}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(url, **kwargs)


@pytest.mark.parametrize("method,url,body", ADMIN_ONLY)
def test_containment_and_configuration_require_admin(lab, method, url, body):
    client, _ = lab
    anonymous = call(client, method, url, body)
    assert anonymous.status_code == 401, (url, anonymous.text)
    assert anonymous.json()["outcome_code"] == "AUTHORIZATION_FAILED"
    analyst = call(client, method, url, body, ANALYST)
    assert analyst.status_code == 403, (url, analyst.text)
    assert analyst.json()["outcome_code"] == "AUTHORIZATION_FAILED"
    admin = call(client, method, url, body, ADMIN)
    assert admin.status_code not in (401, 403), (url, admin.text)


@pytest.mark.parametrize("url,body", [
    ("/api/v1/incidents/inc/notes", {"content": "triage note", "user": "x"}),
    ("/api/v1/incidents/inc/assign", {"user_id": "soc"}),
    ("/api/v1/incidents/bulk-resolve", {"incident_ids": ["inc"]}),
])
def test_incident_workflow_allows_any_configured_operator(lab, url, body):
    client, _ = lab
    assert client.post(url, json=body).status_code == 401
    r = client.post(url, headers=ANALYST, json=body)
    assert r.status_code not in (401, 403), r.text


def test_response_assist_keeps_its_own_scoped_authorization(lab):
    client, _ = lab
    assert client.post(PATH, json={}).status_code == 401
    assert client.post(PATH, headers=ANALYST, json={}).status_code == 200


@pytest.mark.asyncio
async def test_actor_is_the_authenticated_identity_not_the_body(lab):
    client, factory = lab
    async with factory.begin() as db:
        db.add(Incident(id="inc_unknown", title="t", risk_score=50, agent_id=AGENT, detection_evidence={}))
    r = client.post("/api/v1/incidents/inc_unknown/notes", headers=ANALYST,
                    json={"content": "note", "user": "mallory"})
    assert r.status_code in (200, 201), r.text
    # The quick-action route records the verified operator even when the action is refused.
    client.post("/api/v1/incidents/inc_unknown/action", headers=ADMIN,
                json={"action_type": "unisolate", "params": {}, "user": "mallory"})
    async with factory() as db:
        users = set(await db.scalars(select(IncidentNote.user).where(IncidentNote.incident_id == "inc_unknown")))
    assert "mallory" not in users, users
    assert {"reader", "admin"} <= users, users


def test_development_mode_without_credentials_stays_open(lab, monkeypatch):
    client, _ = lab
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {})
    monkeypatch.setattr(settings, "NETWORK_LEGACY_ADMIN_TOKEN", None)
    r = client.post("/api/v1/incidents/inc/notes", json={"content": "dev"})
    assert r.status_code not in (401, 403), r.text
