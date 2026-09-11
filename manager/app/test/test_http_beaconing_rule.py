from datetime import datetime, timezone, timedelta
import pytest
from app.services.risk_rules.http_beaconing_rule import (
    BeaconingDetectionService,
    HttpBeaconingRule,
)


def test_beaconing_interval_analysis():
    now = datetime.now(timezone.utc)
    # Perfectly periodic 60s intervals (low CV)
    timestamps = [now + timedelta(seconds=i * 60) for i in range(10)]
    intervals = BeaconingDetectionService.calculate_intervals(timestamps)
    assert len(intervals) == 9

    stats = BeaconingDetectionService.analyze_intervals(intervals)
    assert stats["is_beaconing"]
    assert stats["cv"] == 0.0
    assert stats["rhythm_score"] == 100.0


@pytest.mark.asyncio
async def test_http_beaconing_rule_evaluation():
    rule = HttpBeaconingRule()

    now = datetime.now(timezone.utc)
    conns = []
    # 10 periodic connections to C2 IP 203.0.113.5
    for i in range(10):
        conns.append({
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "timestamp": (now + timedelta(seconds=i * 30)).isoformat()
        })

    telemetry = {"connection_history": conns}
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 50.0
    assert "Periodic outbound beaconing detected" in reason


@pytest.mark.asyncio
async def test_manager_ip_ignored_in_beaconing():
    rule = HttpBeaconingRule()
    now = datetime.now(timezone.utc)
    
    # 100 periodic connections to Manager IP (172.19.0.3 on port 8000)
    connections = [
        {
            "dst_ip": "172.19.0.3",
            "dst_port": 8000,
            "timestamp": (now + timedelta(seconds=i * 15)).isoformat()
        }
        for i in range(100)
    ]
    result = rule.detect_beaconing(connections)
    assert result == []

    telemetry = {"connection_history": connections}
    score, reason = await rule.evaluate(telemetry, {})
    assert score == 0.0
    assert reason == ""

