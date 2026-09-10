import pytest
from app.services.risk_rules.brute_force_rule import BruteForceRule


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
    assert "Successful authentication breach" in reason
