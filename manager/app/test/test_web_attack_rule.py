import pytest
import time
from unittest.mock import AsyncMock, MagicMock
from app.services.detection.risk_rules.web_attack_rule import WebAttackRule
from app.services.rule_engine import rule_engine
from agent.web_log_monitor import WebLogMonitor

pytestmark = pytest.mark.asyncio


async def test_web_attack_rule_normal_traffic():
    rule = WebAttackRule()
    telemetry = {
        "src_ip": "203.0.113.5",
        "method": "GET",
        "path": "/index.html",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "status_code": 200,
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score == 0.0
    assert reason == ""


async def test_web_attack_rule_malicious_user_agent_hydra():
    rule = WebAttackRule()
    telemetry = {
        "src_ip": "104.28.19.10",
        "method": "POST",
        "path": "/login",
        "user_agent": "Mozilla/5.0 (Hydra)",
        "status_code": 401,
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 85.0
    assert "hydra" in reason.lower()
    assert "104.28.19.10" in reason


async def test_web_attack_rule_malicious_user_agent_sqlmap():
    rule = WebAttackRule()
    telemetry = {
        "src_ip": "198.51.100.22",
        "method": "GET",
        "path": "/items?category=1",
        "user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "status_code": 200,
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 85.0
    assert "sqlmap" in reason.lower()


async def test_web_attack_rule_sql_injection():
    rule = WebAttackRule()
    # SQLi in URL path / query string
    telemetry = {
        "src_ip": "198.51.100.33",
        "method": "GET",
        "path": "/search?q=' UNION SELECT 1,username,password FROM users--",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 90.0
    assert "T1190" in reason
    assert "SQL Injection" in reason


async def test_web_attack_rule_path_traversal():
    rule = WebAttackRule()
    # Path traversal looking for /etc/passwd
    telemetry = {
        "src_ip": "198.51.100.44",
        "method": "GET",
        "path": "/download?file=../../../../etc/passwd",
        "user_agent": "Mozilla/5.0",
    }
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 90.0
    assert "T1190" in reason
    assert "Path Traversal" in reason


async def test_web_attack_rule_brute_force_sliding_window():
    rule = WebAttackRule()
    WebAttackRule.reset_tracker()
    agent_id = "test-desktop"
    attacker_ip = "198.51.100.99"
    now = time.time()

    # Send 4 requests -> not yet threshold (threshold is >= 5)
    for _ in range(4):
        WebAttackRule.record_login_attempt(agent_id, attacker_ip, ts=now)

    telemetry = {
        "src_ip": attacker_ip,
        "method": "POST",
        "path": "/login",
        "user_agent": "Mozilla/5.0",
        "login_count": 4
    }
    score, reason = await rule.evaluate(telemetry, {"agent_id": agent_id})
    assert score == 0.0

    # 5th request triggers brute force
    telemetry["login_count"] = 5
    score, reason = await rule.evaluate(telemetry, {"agent_id": agent_id})
    assert score >= 80.0
    assert "T1110" in reason
    assert "Brute Force" in reason
    assert attacker_ip in reason

    # 15+ requests triggers critical brute force (score 95)
    telemetry["login_count"] = 16
    score, reason = await rule.evaluate(telemetry, {"agent_id": agent_id})
    assert score >= 95.0


async def test_rule_engine_evaluate_web_log():
    # 1. Hydra User-Agent match
    hydra_log = {
        "src_ip": "1.2.3.4",
        "path": "/login",
        "method": "POST",
        "user_agent": "Mozilla/5.0 (Hydra)"
    }
    matches = rule_engine.evaluate_web_log(hydra_log)
    assert len(matches) >= 1
    m = matches[0]
    assert m.rule_id == "web_malicious_user_agent"
    assert "T1190" in m.mitre_techniques
    assert m.severity == "high"

    # 2. Path Traversal match
    traversal_log = {
        "src_ip": "1.2.3.4",
        "path": "/static/../../etc/shadow",
        "method": "GET",
        "user_agent": "curl/7.81.0"
    }
    matches = rule_engine.evaluate_web_log(traversal_log)
    assert any(m.rule_id == "web_path_traversal" for m in matches)
    tr_match = next(m for m in matches if m.rule_id == "web_path_traversal")
    assert tr_match.severity == "critical"
    assert "T1190" in tr_match.mitre_techniques

    # 3. SQLi match
    sqli_log = {
        "src_ip": "1.2.3.4",
        "path": "/users?id=1' OR 1=1--",
        "method": "GET",
        "user_agent": "curl/7.81.0"
    }
    matches = rule_engine.evaluate_web_log(sqli_log)
    assert any(m.rule_id == "web_sql_injection" for m in matches)


async def test_web_log_monitor_parsing():
    # Test unstructured journalctl / cloudflared log line
    sample_line = (
        '{"MESSAGE":"2026-11-20T08:00:00Z INF HTTP request '
        'headers={\\"Cf-Connecting-Ip\\":[\\"198.51.100.77\\"],\\"User-Agent\\":[\\"Mozilla/5.0 (Hydra)\\"]} '
        'host=target.alwayready.id.vn method=POST path=/login status=401"}'
    )
    parsed = WebLogMonitor.parse_raw_log_line(sample_line)
    assert parsed is not None
    assert parsed["src_ip"] == "198.51.100.77"
    assert parsed["user_agent"] == "Mozilla/5.0 (Hydra)"
    assert parsed["http_method"] == "POST"
    assert parsed["path"] == "/login"
    assert parsed["status_code"] == 401
