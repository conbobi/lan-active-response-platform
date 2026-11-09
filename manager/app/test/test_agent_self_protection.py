import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.common.agent_protection import is_agent_process, check_agent_kill_protection
from app.models.process_info import ProcessInfo
from app.services.response.policy_engine_service import PolicyEngineService
from app.services.detection.risk_assessment_service import RiskAssessmentService
from app.services.response.response_action_service import ResponseActionService
from app.core.exceptions import BadRequestError

pytestmark = pytest.mark.asyncio


def test_is_agent_process_detection():
    # 1. Agent processes themselves
    assert is_agent_process({"name": "python.exe", "cmdline": "python.exe win_agent_minimal.py"})
    assert is_agent_process({"name": "larp_agent.exe", "cmdline": "larp_agent.exe"})
    assert is_agent_process({"name": "win_agent_minimal.exe", "cmdline": "C:\\LARP\\win_agent_minimal.exe"})
    assert is_agent_process({"name": "python", "cmdline": "python3 /opt/larp/agent.py"})
    assert is_agent_process({"name": "watchdog.py", "cmdline": "python watchdog.py"})

    # 2. Legitimate agent child processes
    assert is_agent_process({
        "name": "cmd.exe",
        "cmdline": "cmd.exe /c netsh advfirewall firewall add rule name=LARP_BLOCK_OUT dir=out action=block",
        "parent_name": "python.exe"
    })
    assert is_agent_process({
        "name": "taskkill.exe",
        "cmdline": "taskkill /f /pid 1234",
        "parent_name": "python.exe"
    })
    assert is_agent_process({
        "name": "powershell.exe",
        "cmdline": "powershell -NoProfile -Command Get-NetTCPConnection",
        "parent_name": "python.exe"
    })
    assert is_agent_process({
        "name": "netsh.exe",
        "cmdline": "netsh advfirewall set allprofiles state on",
        "parent_name": "win_agent_minimal.exe"
    })

    # 3. Direct isolation command lines
    assert is_agent_process({"name": "cmd.exe", "cmdline": "netsh advfirewall firewall delete rule name=LARP_BLOCK_OUT"})

    # 4. Non-agent / Malicious processes
    assert not is_agent_process({"name": "mimikatz.exe", "cmdline": "mimikatz.exe privilege::debug", "parent_name": "cmd.exe"})
    assert not is_agent_process({"name": "nc.exe", "cmdline": "nc.exe -lvp 4444", "parent_name": "python.exe"})
    assert not is_agent_process({"name": "whoami.exe", "cmdline": "whoami /all", "parent_name": "explorer.exe"})
    assert not is_agent_process({"name": "powershell.exe", "cmdline": "powershell -enc aW52b2tl...", "parent_name": "cmd.exe"})


def test_check_agent_kill_protection():
    procs = [
        ProcessInfo(id="p1", agent_id="agent-win", pid=1000, parent_pid=1, name="explorer.exe", cmdline="explorer.exe"),
        # Agent itself
        ProcessInfo(id="p2", agent_id="agent-win", pid=5000, parent_pid=1000, name="python.exe", cmdline="python win_agent_minimal.py"),
        # Agent's child (netsh)
        ProcessInfo(id="p3", agent_id="agent-win", pid=5050, parent_pid=5000, name="cmd.exe", cmdline="cmd.exe /c netsh advfirewall add rule"),
        # Malicious process
        ProcessInfo(id="p4", agent_id="agent-win", pid=6666, parent_pid=1000, name="mimikatz.exe", cmdline="mimikatz.exe"),
        # Malicious process's child
        ProcessInfo(id="p5", agent_id="agent-win", pid=6667, parent_pid=6666, name="cmd.exe", cmdline="cmd.exe /c whoami"),
    ]

    # Target is agent -> Refused
    allowed, reason = check_agent_kill_protection(procs, 5000)
    assert not allowed
    assert "LARP agent" in reason

    # Target is agent's child -> Refused
    allowed, reason = check_agent_kill_protection(procs, 5050)
    assert not allowed
    assert "agent" in reason.lower()

    # Target is ancestor of agent -> Refused (killing explorer would kill agent)
    allowed, reason = check_agent_kill_protection(procs, 1000)
    assert not allowed
    assert "agent descendant" in reason.lower()

    # Target is malicious process -> Allowed
    allowed, reason = check_agent_kill_protection(procs, 6666)
    assert allowed
    assert reason is None

    # Target is malicious process's child -> Allowed
    allowed, reason = check_agent_kill_protection(procs, 6667)
    assert allowed
    assert reason is None


async def test_policy_engine_self_protection_blocks_kill(mock_db):
    engine = PolicyEngineService(mock_db)
    procs = [
        ProcessInfo(id="p1", agent_id="agent-win", pid=5000, parent_pid=1, name="python.exe", cmdline="python win_agent_minimal.py"),
        ProcessInfo(id="p2", agent_id="agent-win", pid=5050, parent_pid=5000, name="cmd.exe", cmdline="cmd.exe /c netsh advfirewall firewall add rule"),
        ProcessInfo(id="p3", agent_id="agent-win", pid=9000, parent_pid=1, name="malware.exe", cmdline="malware.exe"),
    ]
    engine._get_process_tree = AsyncMock(return_value=procs)
    engine.action_service = MagicMock()
    engine.action_service.create_and_apply_action = AsyncMock(return_value=MagicMock(id="act_123"))

    # Test 1: Kill agent PID -> Rejected
    res_agent = await engine._dispatch_action(
        agent_id="agent-win",
        action_type="kill_process",
        target_pid=5000
    )
    assert res_agent["status"] == "rejected"
    assert "LARP agent" in res_agent["reason"]
    engine.action_service.create_and_apply_action.assert_not_awaited()

    # Test 2: Kill agent child PID -> Rejected
    res_child = await engine._dispatch_action(
        agent_id="agent-win",
        action_type="kill_process_tree",
        target_pid=5050
    )
    assert res_child["status"] == "rejected"
    engine.action_service.create_and_apply_action.assert_not_awaited()

    # Test 3: Kill malicious PID -> Applied
    res_malware = await engine._dispatch_action(
        agent_id="agent-win",
        action_type="kill_process_tree",
        target_pid=9000
    )
    assert res_malware["status"] == "applied"
    assert res_malware["action_id"] == "act_123"
    engine.action_service.create_and_apply_action.assert_awaited_once()


async def test_risk_assessment_filters_agent_processes(mock_db):
    service = RiskAssessmentService(mock_db)
    service.detection_rule_service = MagicMock()
    service.detection_rule_service.sync_registry = AsyncMock()

    # Telemetry contains agent, agent child, and normal process
    data = {
        "cpu_usage": 15.0,
        "ram_usage": 30.0,
        "process_list": [
            {"pid": 5000, "name": "python.exe", "cmdline": "python win_agent_minimal.py"},
            {"pid": 5050, "name": "cmd.exe", "cmdline": "cmd.exe /c netsh advfirewall add rule", "parent_name": "python.exe"},
            {"pid": 2000, "name": "notepad.exe", "cmdline": "notepad.exe"}
        ]
    }

    # Mock rule registry to inspect telemetry passed to rules
    captured_telemetry = None
    async def mock_rule_eval(telemetry, context):
        nonlocal captured_telemetry
        captured_telemetry = telemetry
        return 0.0, "ok"

    mock_rule = MagicMock(rule_id="test_rule", weight=1.0)
    mock_rule.evaluate = AsyncMock(side_effect=mock_rule_eval)
    service.registry = MagicMock()
    service.registry.get_enabled_rules.return_value = [mock_rule]

    score, factors = await service.evaluate("agent-win", data)

    # Verify agent and child were filtered out
    assert captured_telemetry is not None
    filtered_pids = [p["pid"] for p in captured_telemetry["process_list"]]
    assert 5000 not in filtered_pids
    assert 5050 not in filtered_pids
    assert 2000 in filtered_pids


async def test_response_action_service_rejects_agent_kill(mock_db):
    service = ResponseActionService(mock_db)
    service.agent_repo = MagicMock()
    service.agent_repo.get = AsyncMock(return_value=MagicMock(id="agent-win"))

    procs = [
        ProcessInfo(id="p1", agent_id="agent-win", pid=5000, parent_pid=1, name="python.exe", cmdline="python win_agent_minimal.py"),
    ]

    with patch("app.repositories.process_info_repository.ProcessInfoRepository.find_by_agent", AsyncMock(return_value=procs)):
        with pytest.raises(BadRequestError) as exc_info:
            await service.create_and_apply_action(
                agent_id="agent-win",
                action_type="kill_process",
                action_params={"pid": 5000}
            )
        assert "target is LARP agent" in str(exc_info.value)

