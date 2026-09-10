import os
import tempfile
import pytest
from app.services.risk_rules.yara_match_rule import YaraMatchRule


@pytest.mark.asyncio
async def test_yara_match_rule():
    rule = YaraMatchRule()

    # No match
    score, reason = await rule.evaluate({}, {})
    assert score == 0.0

    # Match detected in telemetry
    telemetry = {"yara_matches": ["Webshell_Generic_PHP", "ELF_Ransomware_LockBit_Sim"]}
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 90.0
    assert "YARA signature match detected" in reason


def test_agent_yara_scanner():
    import sys
    agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../agent"))
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)
    from yara_scanner import YaraScanner

    scanner = YaraScanner()

    with tempfile.NamedTemporaryFile("w+", suffix=".php", delete=False) as f:
        f.write("<?php eval($_POST['cmd']); ?>")
        temp_path = f.name

    try:
        matches = scanner.scan_file(temp_path)
        assert len(matches) > 0
        rule_names = [m["rule"] for m in matches]
        assert any("Webshell" in r for r in rule_names)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
