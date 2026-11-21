import pytest
from unittest.mock import AsyncMock, MagicMock

from app.services.rule_engine import RuleEngine, match_endpoint_telemetry


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


def test_endpoint_network_rules_require_process_and_socket_evidence():
    shell = {
        "exe_path": "/usr/bin/bash", "pid": 808, "process_start_time": 1000.5,
        "dst_ip": "192.0.2.21", "dst_port": 443, "protocol": "TCP",
        "status": "ESTABLISHED", "socket_stdio": True,
    }
    temp_exec = {**shell, "exe_path": "/dev/shm/tool", "socket_stdio": False}
    matches = match_endpoint_telemetry({"network_connections": [shell, temp_exec]})
    assert [match.rule_id for match in matches] == [
        "builtin_linux_network_shell", "builtin_linux_temp_network_exec",
    ]
    assert "192.0.2.21" in matches[0].detail
    different_start = match_endpoint_telemetry(
        {"network_connections": [{**shell, "process_start_time": 1001}]}
    )[0]
    assert different_start.entity != matches[0].entity

    benign = [
        {**shell, "socket_stdio": False},
        {**shell, "dst_ip": "127.0.0.1"},
        {**shell, "dst_ip": "::ffff:127.0.0.1"},
        {**shell, "status": "SYN_SENT"},
        {**shell, "protocol": "UDP"},
        {**temp_exec, "process_start_time": None},
        {**temp_exec, "exe_path": "/tmp-backup/tool"},
        {**temp_exec, "exe_path": "/tmp/../usr/bin/tool"},
    ]
    assert match_endpoint_telemetry({"network_connections": benign}) == []


@pytest.mark.asyncio
async def test_endpoint_fim_deduplicates_transitions_and_preserves_distinct_changes():
    engine = RuleEngine()
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock())
    session.execute.return_value.scalars.return_value.all.return_value = []
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    change = {"file_path": "/etc/sudoers.d/example", "action": "MODIFIED",
              "old_hash": "a" * 64, "new_hash": "b" * 64}
    incidents = await engine.evaluate({
        "agent_id": "a",
        "file_changes": [
            change, change, {**change, "old_hash": "b" * 64, "new_hash": "c" * 64},
            {**change, "file_path": "/tmp/passwd"}, {**change, "new_hash": "a" * 64},
        ],
    }, session)
    assert [incident.risk_score for incident in incidents] == [75.0, 75.0]
    assert incidents[0].notes != incidents[1].notes
    assert "new_sha256=" + "b" * 64 in incidents[0].description


