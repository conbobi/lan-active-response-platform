from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.services.detection.risk_rules.brute_force_rule import BruteForceRule


@pytest.mark.asyncio
async def test_brute_force_rule_no_events():
    rule = BruteForceRule()
    score, reason = await rule.evaluate({}, {})
    assert score == 0.0
    assert reason == ""


@pytest.mark.asyncio
async def test_brute_force_rule_under_threshold():
    rule = BruteForceRule()
    telemetry = {
        "auth_events": [
            {"service": "ssh", "source_ip": "192.168.1.100", "username": "root", "status": "failed", "count": 2}
        ]
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score == 0.0


@pytest.mark.asyncio
async def test_brute_force_rule_threshold_met():
    rule = BruteForceRule()
    telemetry = {
        "auth_events": [
            {"service": "ssh", "source_ip": "192.168.1.100", "username": "root", "status": "failed", "count": 6}
        ]
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 30.0
    assert "Brute force" in reason


@pytest.mark.asyncio
async def test_brute_force_rule_breach_detection():
    rule = BruteForceRule()
    telemetry = {
        "auth_events": [
            {"service": "ssh", "source_ip": "192.168.1.100", "username": "root", "status": "failed", "count": 8},
            {"service": "ssh", "source_ip": "192.168.1.100", "username": "root", "status": "success", "count": 1},
        ]
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 80.0
    assert "same account and source" in reason


@pytest.mark.asyncio
async def test_brute_force_correlates_history_with_current_batch():
    engine = create_engine("sqlite:///:memory:")
    now = datetime.now(timezone.utc)
    try:
        AuthEvent.__table__.create(engine)
        with Session(engine) as session:
            session.add_all([
                AuthEvent(agent_id="a", service="ssh", source_ip="192.0.2.1", username="alice",
                          status="failed", count=4, timestamp=now - timedelta(seconds=15)),
                AuthEvent(agent_id="a", service="web", source_ip="192.0.2.1", username="alice",
                          status="failed", count=20, timestamp=now - timedelta(seconds=15)),
                AuthEvent(agent_id="a", service="ssh", source_ip="192.0.2.1", username="alice",
                          status="failed", count=20, timestamp=now - timedelta(seconds=61)),
                AuthEvent(agent_id="b", service="ssh", source_ip="192.0.2.1", username="alice",
                          status="failed", count=20, timestamp=now - timedelta(seconds=15)),
                AuthEvent(agent_id="a", service="ssh", source_ip="192.0.2.1", username="alice",
                          status="failed", count=1, timestamp=now),
            ])
            session.flush()
            async_session = AsyncMock()
            async_session.execute.side_effect = session.execute
            context = {"session": async_session, "agent_id": "a", "auth_history_before": now}
            failure = {"service": "ssh", "source_ip": "192.0.2.1", "username": "alice", "status": "failed"}
            success = {**failure, "status": "success", "auth_method": "password"}
            rule = BruteForceRule()

            assert (await rule.evaluate({"auth_events": [success]}, context))[0] == 0.0
            assert (await rule.evaluate({"auth_events": [failure]}, context))[0] == 55.0
            assert (await rule.evaluate({"auth_events": [failure, success]}, context))[0] == 85.0
            for mismatch in (
                {"username": "bob"}, {"source_ip": "192.0.2.2"},
                {"service": "web-other"}, {"auth_method": "publickey"},
            ):
                events = [failure, {**success, **mismatch}]
                assert (await rule.evaluate({"auth_events": events}, context))[0] == 55.0
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_brute_force_respects_configured_source_thresholds():
    rule = BruteForceRule()
    rule.config = {"threshold": 7, "critical_threshold": 10}
    event = {"service": "ssh", "source_ip": "192.0.2.1", "status": "failed"}
    for count, expected in [(5, 0), (7, 55), (10, 75)]:
        assert (await rule.evaluate({"auth_events": [{**event, "count": count}]}, {}))[0] == expected
