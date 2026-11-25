import json
from datetime import datetime, timezone

import pytest

from agent.web_log_monitor import WebLogMonitor
from app.services.detection.behavior_evidence import (
    SQLI, SQLI_TOOL, SQLI_PROBE, AUTOMATED_HTTP, UNKNOWN,
)
from app.services.detection.risk_rules.web_attack_rule import WebAttackRule
from app.services.rule_engine import rule_engine


@pytest.mark.parametrize("agent_string,expected_kind,expected_score", [
    ("sqlmap fixture", SQLI_TOOL, 60.0),
    ("Nmap fixture", AUTOMATED_HTTP, 55.0),
    ("Hydra fixture", AUTOMATED_HTTP, 55.0),
])
@pytest.mark.asyncio
async def test_user_agent_hint_has_no_exploit_or_brute_force_mapping(agent_string, expected_kind, expected_score):
    telemetry = {
        "src_ip": "192.0.2.20", "method": "POST", "path": "/login", "user_agent": agent_string,
        "evidence_id": "web_observation", "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    score, reason = await WebAttackRule().evaluate(telemetry, {})
    assert score == expected_score and expected_kind in reason
    matches = rule_engine.evaluate_web_log(telemetry)
    assert len(matches) == 1 and matches[0].rule_id == expected_kind
    assert not matches[0].mitre_techniques


@pytest.mark.parametrize("status", [200, 302, 500])
@pytest.mark.asyncio
async def test_observed_sql_indicator_classifies_probing_without_success(status):
    log = {
        "src_ip": "192.0.2.20", "method": "POST", "path": "/login", "status_code": status,
        "evidence_id": "web_observation", "payload_indicators": ["sql_query_operator"],
    }
    assert (await WebAttackRule().evaluate(log, {}))[0] == 75.0
    match, = rule_engine.evaluate_web_log(log)
    assert match.rule_id in (SQLI, SQLI_PROBE)
    assert match.mitre_techniques == ["T1190"]
    assert match.evidence["exploitation_outcome"] == "undetermined"


@pytest.mark.asyncio
async def test_access_post_counts_do_not_prove_auth_failure():
    log = {"src_ip": "192.0.2.20", "method": "POST", "path": "/login", "login_count": 90}
    assert (await WebAttackRule().evaluate({"web_logs": [log] * 10, "web_log": log}, {})) == (0.0, "")
    assert not rule_engine.evaluate_web_log(log)


@pytest.mark.asyncio
async def test_path_traversal_remains_a_separate_request_detection():
    log = {"src_ip": "192.0.2.20", "method": "GET", "path": "/static/../../etc/shadow"}
    assert (await WebAttackRule().evaluate(log, {}))[0] == 90.0
    assert rule_engine.evaluate_web_log(log)[0].rule_id == "web_path_traversal"


def test_web_log_monitor_preserves_timestamp_and_drops_credentials():
    sample = {
        "client_ip": "192.0.2.20", "method": "POST", "path": "/login?token=private-test-value",
        "timestamp": "2026-11-24T04:43:45.649489+00:00", "request_id": "a" * 32,
        "status_code": 302, "user_agent": "test UA", "service": "flask_web",
        "headers": {"Authorization": "Bearer private-test-value", "Cookie": "session=private-test-value"},
    }
    parsed = WebLogMonitor.parse_raw_log_line(json.dumps(sample))
    assert parsed["path"] == "/login"
    assert parsed["timestamp"] == sample["timestamp"] and parsed["request_id"] == sample["request_id"]
    assert parsed["user_agent"] == "test UA" and parsed["status_code"] == 302
    assert "private-test-value" not in json.dumps(parsed)
