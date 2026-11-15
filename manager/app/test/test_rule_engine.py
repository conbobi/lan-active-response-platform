import pytest
from app.services.rule_engine import RuleEngine


def test_match_contains():
    engine = RuleEngine()
    event = {"cmdline": "powershell -enc ABC123"}
    assert engine._match_field("CommandLine|contains", "-enc", event) is True
    assert engine._match_field("CommandLine|contains", "-dec", event) is False


def test_match_endswith():
    engine = RuleEngine()
    event = {"exe": "/usr/bin/npm"}
    assert engine._match_field("Image|endswith", "npm", event) is True
    assert engine._match_field("process|endswith", "python", event) is False


def test_match_startswith():
    engine = RuleEngine()
    event = {"exe": "/usr/bin/python3"}
    assert engine._match_field("Image|startswith", "/usr/bin", event) is True
    assert engine._match_field("Image|startswith", "/tmp", event) is False


def test_selection_and_logic():
    engine = RuleEngine()
    selection = {
        "Image|endswith": "bash",
        "ParentImage|endswith": "npm"
    }
    event = {"exe": "/usr/bin/bash", "parent_exe": "/usr/bin/npm"}
    assert engine._match_selection(selection, event) is True

    # Failed parent
    event_bad = {"exe": "/usr/bin/bash", "parent_exe": "/usr/bin/systemd"}
    assert engine._match_selection(selection, event_bad) is False


def test_selection_or_logic_for_list():
    engine = RuleEngine()
    selection = {
        "CommandLine|contains": ["-enc", "-encodedcommand"]
    }
    assert engine._match_selection(selection, {"cmdline": "powershell -enc aaaa"}) is True
    assert engine._match_selection(selection, {"cmdline": "powershell -encodedcommand aaaa"}) is True
    assert engine._match_selection(selection, {"cmdline": "powershell -ExecutionPolicy Bypass"}) is False


def test_evaluate_rule_against_telemetry():
    engine = RuleEngine()
    rule = {
        "id": "test-rule-1",
        "rule_name": "Detect Shadow Copy Deletion",
        "severity": "high",
        "mitre_techniques": ["T1490"],
        "detection": {
            "selection": {
                "process|endswith": "vssadmin.exe",
                "cmdline|contains": "delete shadows"
            }
        },
        "logsource": {"category": "process_creation"}
    }
    telemetry = {
        "agent_id": "test-agent",
        "process_list": [
            {"name": "vssadmin.exe", "exe": "C:\\Windows\\System32\\vssadmin.exe", "cmdline": "vssadmin delete shadows /all /quiet"},
            {"name": "notepad.exe", "exe": "C:\\Windows\\notepad.exe", "cmdline": "notepad.exe text.txt"}
        ]
    }
    matches = engine._evaluate_rule(rule, telemetry)
    assert len(matches) == 1
    assert matches[0].rule_id == "test-rule-1"
    assert matches[0].rule_name == "Detect Shadow Copy Deletion"
    assert matches[0].severity == "high"

