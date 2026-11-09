import pytest
from unittest.mock import AsyncMock, MagicMock
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.services.incident.incident_service import IncidentService
from app.services.incident.incident_timeline_service import IncidentTimelineService
from app.services.detection.risk_rules.cpu_spike_rule import CpuSpikeRule


def test_generate_story_system_idle_process_with_parent():
    service = IncidentService(MagicMock())
    incident = Incident(
        id="inc_test1",
        title="Test Incident",
        description="Test",
        risk_score=0.0,
        agent_id="WIN-DEMO-01"
    )
    culprit = {
        "pid": 0,
        "name": "System Idle Process",
        "exe_path": "",
        "cmdline": ""
    }
    parent = {
        "pid": 4,
        "name": "System"
    }

    story = service.generate_story(incident, culprit, parent)
    assert "Tiến trình `System Idle Process` (PID 0)" in story
    assert "được khởi chạy bởi `System` (PID 4)" in story
    assert "Hệ thống phân tích rủi ro kích hoạt điểm đe dọa 0/100." in story
    # MUST NOT contain hallucinated strings
    assert "/tmp/" not in story
    assert "bash" not in story
    assert "cmd.exe" not in story
    assert "key_test.exe" not in story


def test_generate_story_system_idle_process_no_parent():
    service = IncidentService(MagicMock())
    incident = Incident(
        id="inc_test2",
        title="Test Incident",
        description="Test",
        risk_score=0.0,
        agent_id="WIN-DEMO-01"
    )
    culprit = {
        "pid": 0,
        "name": "System Idle Process",
        "exe_path": "",
        "cmdline": ""
    }

    story = service.generate_story(incident, culprit, parent=None)
    assert "Tiến trình `System Idle Process` (PID 0)" in story
    assert "/tmp/" not in story
    assert "bash" not in story
    assert "cmd.exe" not in story
    assert "hoạt động từ" not in story  # exe is empty, should not invent


def test_generate_story_real_process_with_path():
    service = IncidentService(MagicMock())
    incident = Incident(
        id="inc_test3",
        title="Malware Detected",
        description="Test",
        risk_score=85.0,
        agent_id="WIN-DEMO-01"
    )
    culprit = {
        "pid": 4444,
        "name": "mimikatz.exe",
        "exe_path": "C:\\Tools\\mimikatz.exe",
        "cmdline": "mimikatz.exe"
    }
    parent = {
        "pid": 3333,
        "name": "powershell.exe"
    }

    story = service.generate_story(incident, culprit, parent)
    assert "Tiến trình `mimikatz.exe` (PID 4444)" in story
    assert "được khởi chạy bởi `powershell.exe` (PID 3333)" in story
    assert "hoạt động từ `C:\\Tools\\mimikatz.exe`" in story
    assert "85/100" in story


@pytest.mark.asyncio
async def test_timeline_service_no_hallucinations(mock_db):
    service = IncidentTimelineService(mock_db)
    incident = Incident(
        id="inc_mock",
        agent_id="WIN-DEMO-01",
        title="Idle Test",
        description="Telemetry check",
        risk_score=0.0
    )
    proc_idle = ProcessInfo(
        id="p_idle",
        agent_id="WIN-DEMO-01",
        pid=0,
        parent_pid=None,
        name="System Idle Process",
        exe="",
        exe_path="",
        cmdline=""
    )

    # Mock execute results: first incident, second procs, third flows, fourth risk records, fifth actions
    mock_db.execute = AsyncMock()
    mock_db.execute.side_effect = [
        MagicMock(scalar_one_or_none=MagicMock(return_value=incident)),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[proc_idle])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
    ]

    res = await service.build_timeline("inc_mock")
    timeline = res["timeline"]
    assert len(timeline) >= 1
    spawn_event = next((item for item in timeline if item["type"] == "process_spawn"), None)
    assert spawn_event is not None
    assert "bash" not in spawn_event["title"]
    assert spawn_event["details"]["path"] == ""  # NOT /tmp/System Idle Process
    assert spawn_event["details"].get("parent") is None  # NOT bash / 1000


@pytest.mark.asyncio
async def test_cpu_spike_rule_skips_kernel_idle():
    rule = CpuSpikeRule()

    # Case 1: System Idle Process consumes 95% CPU -> normal idle, score 0.0
    telemetry_idle = {
        "cpu_usage": 95.0,
        "process_list": [
            {"pid": 0, "name": "System Idle Process", "cpu_percent": 95.0},
            {"pid": 1234, "name": "chrome.exe", "cpu_percent": 2.0}
        ]
    }
    score, reason = await rule.evaluate(telemetry_idle, {})
    assert score == 0.0

    # Case 2: Real malware consumes 92% CPU -> alert triggered
    telemetry_malware = {
        "cpu_usage": 92.0,
        "process_list": [
            {"pid": 5555, "name": "xmrig.exe", "cpu_percent": 90.0},
            {"pid": 0, "name": "System Idle Process", "cpu_percent": 5.0}
        ]
    }
    score_malware, reason_malware = await rule.evaluate(telemetry_malware, {})
    assert score_malware == 30.0
    assert "Critical CPU spike" in reason_malware
