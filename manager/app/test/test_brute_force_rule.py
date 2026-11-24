from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.models.event import Event
from app.services.detection.behavior_evidence import BRUTE_FORCE, REPEATED, SQLI
from app.services.detection.risk_rules.brute_force_rule import BruteForceRule


def attempt(stamp, index=0, **changes):
    return {
        "service": "ssh", "source_ip": "192.0.2.20", "username": "operator",
        "status": "failed", "auth_method": "password", "timestamp": stamp.isoformat(),
        "timestamp_source": "log", "evidence_id": f"auth_{index}", **changes,
    }


async def classify(events, context=None, rule=None):
    context = context if context is not None else {}
    score, reason = await (rule or BruteForceRule()).evaluate({"auth_events": events}, context)
    findings = [item for _, item in context.get("behavior_findings", {}).get("brute_force", ())]
    return score, reason, findings


@pytest.mark.asyncio
async def test_legitimate_mistypes_and_aggregate_failure_count():
    now = datetime.now(timezone.utc)
    assert (await classify([]))[0] == 0.0
    assert (await classify([attempt(now, count=2)]))[0] == 0.0
    score, reason, findings = await classify([attempt(now, count=18)])
    assert score == 55.0 and REPEATED in reason
    assert findings[0]["failed_attempts"] == 18
    assert "brute_force_criteria" not in findings[0]


@pytest.mark.asyncio
async def test_password_burst_and_success_on_same_account():
    start = datetime.now(timezone.utc)
    attempts = [attempt(start + timedelta(seconds=index), index) for index in range(8)]
    success = attempt(start + timedelta(seconds=9), 9, status="success")
    score, _, findings = await classify([*attempts, success])
    assert score == 85.0
    assert findings[0]["classification"] == BRUTE_FORCE
    assert len(findings[0]["source_event_ids"]) == 9
    for mismatch in ({"auth_method": "publickey"}, {"username": "other"}, {"source_ip": "192.0.2.99"}):
        assert (await classify([*attempts, {**success, **mismatch}]))[0] == 75.0


@pytest.mark.asyncio
async def test_sql_signals_prevent_login_burst_from_becoming_brute_force():
    start = datetime.now(timezone.utc)
    attempts = [
        attempt(start + timedelta(seconds=index), index, service="flask_web", method="POST", path="/login",
                user_agent="sqlmap fixture", payload_indicators=["sql_boolean_expression"])
        for index in range(15)
    ]
    _, _, findings = await classify(attempts)
    assert [item["classification"] for item in findings] == [SQLI]
    assert findings[0]["exploitation_outcome"] == "undetermined"
    assert findings[0]["failed_attempts"] == 15
    assert findings[0]["request_path"] == "/login"


@pytest.mark.asyncio
async def test_history_is_scoped_to_agent_service_source_and_sliding_window():
    engine = create_engine("sqlite:///:memory:")
    now = datetime.now(timezone.utc)
    try:
        AuthEvent.__table__.create(engine)
        Event.__table__.create(engine)
        with Session(engine) as session:
            session.add_all([
                AuthEvent(agent_id="a", service="ssh", source_ip="192.0.2.20", username="operator",
                          status="failed", count=4, timestamp=now - timedelta(seconds=15)),
                AuthEvent(agent_id="a", service="ssh", source_ip="192.0.2.20", username="operator",
                          status="failed", count=20, timestamp=now - timedelta(seconds=61)),
                AuthEvent(agent_id="b", service="ssh", source_ip="192.0.2.20", username="operator",
                          status="failed", count=20, timestamp=now - timedelta(seconds=15)),
                AuthEvent(agent_id="a", service="flask_web", source_ip="192.0.2.20", username="operator",
                          status="failed", count=20, timestamp=now - timedelta(seconds=15)),
                AuthEvent(agent_id="a", service="ssh", source_ip="192.0.2.99", username="other",
                          status="failed", count=20, timestamp=now - timedelta(seconds=15)),
            ])
            session.flush()
            async_session = AsyncMock()
            async_session.execute.side_effect = session.execute
            context = {"session": async_session, "agent_id": "a", "auth_history_before": now}
            assert (await classify([attempt(now, status="success")], context))[0] == 0
            current = attempt(now, 1)
            score, _, findings = await classify([current, current], context)
            assert score == 55.0 and findings[0]["failed_attempts"] == 5
            assert len(findings[0]["source_event_ids"]) == 2
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_brute_force_respects_configured_source_thresholds():
    rule = BruteForceRule()
    rule.config = {"threshold": 7, "critical_threshold": 10}
    event = attempt(datetime.now(timezone.utc), auth_method=None)
    for count, expected in [(5, 0), (7, 55), (10, 55)]:
        assert (await classify([{**event, "count": count}], rule=rule))[0] == expected
