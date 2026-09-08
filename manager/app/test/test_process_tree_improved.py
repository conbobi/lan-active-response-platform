import sys
import json
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import psutil
from fastapi import WebSocketDisconnect

# Ensure agent directory is importable
agent_dir = Path(__file__).resolve().parents[3] / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

import agent

from app.services.process_tree_service import ProcessTreeService
from app.models.process_info import ProcessInfo
from app.websocket.agent_ws import agent_websocket_endpoint

pytestmark = pytest.mark.asyncio


async def test_collect_process_info_filters_zombies():

    """Verify collect_process_info() excludes zombie, defunct, and dead processes."""
    mock_p1 = MagicMock()
    mock_p1.info = {
        "pid": 100,
        "ppid": 1,
        "name": "python3",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3", "app.py"],
        "cpu_percent": 1.2,
        "memory_percent": 2.5,
        "status": psutil.STATUS_RUNNING
    }

    mock_p2_zombie = MagicMock()
    mock_p2_zombie.info = {
        "pid": 101,
        "ppid": 100,
        "name": "sh",
        "exe": "",
        "cmdline": [],
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "status": psutil.STATUS_ZOMBIE
    }

    mock_p3_defunct = MagicMock()
    mock_p3_defunct.info = {
        "pid": 102,
        "ppid": 100,
        "name": "child",
        "exe": "",
        "cmdline": [],
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "status": "defunct"
    }

    mock_p4_dead = MagicMock()
    mock_p4_dead.info = {
        "pid": 103,
        "ppid": 1,
        "name": "terminated",
        "exe": "",
        "cmdline": [],
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "status": psutil.STATUS_DEAD
    }

    mock_p5_normal = MagicMock()
    mock_p5_normal.info = {
        "pid": 104,
        "ppid": 1,
        "name": "bash",
        "exe": "/bin/bash",
        "cmdline": ["/bin/bash"],
        "cpu_percent": 0.1,
        "memory_percent": 0.4,
        "status": psutil.STATUS_SLEEPING
    }

    with patch("psutil.process_iter", return_value=[mock_p1, mock_p2_zombie, mock_p3_defunct, mock_p4_dead, mock_p5_normal]):
        procs = agent.collect_process_info()

    collected_pids = [p["pid"] for p in procs]
    assert 100 in collected_pids
    assert 104 in collected_pids
    # Zombie, defunct, and dead must be filtered out
    assert 101 not in collected_pids
    assert 102 not in collected_pids
    assert 103 not in collected_pids
    assert len(procs) == 2


async def test_build_tree_attaches_orphan_nodes_to_root():
    """Verify ProcessTreeService.build_tree() anchors orphan/missing-parent nodes to root PID 1."""
    mock_session = AsyncMock()
    service = ProcessTreeService(mock_session)

    procs = [
        ProcessInfo(
            id="p1",
            agent_id="test-agent",
            pid=100,
            parent_pid=9999,  # Missing parent
            name="python3",
            exe="/usr/bin/python3",
            cmdline="python3 server.py",
            cpu_percent=1.0,
            memory_percent=2.0
        ),
        ProcessInfo(
            id="p2",
            agent_id="test-agent",
            pid=200,
            parent_pid=100,   # Child of 100
            name="worker",
            exe="/usr/bin/worker",
            cmdline="worker run",
            cpu_percent=0.5,
            memory_percent=1.0
        ),
        ProcessInfo(
            id="p3",
            agent_id="test-agent",
            pid=300,
            parent_pid=None,  # Orphan
            name="cron",
            exe="/usr/sbin/cron",
            cmdline="cron -f",
            cpu_percent=0.1,
            memory_percent=0.2
        )
    ]

    service.process_repo.get_by_agent = AsyncMock(return_value=procs)

    tree_result = await service.build_tree("test-agent")

    assert tree_result["agent_id"] == "test-agent"
    assert tree_result["root_count"] >= 1
    # Check that root node exists (PID 1 virtual root)
    root_node = tree_result["tree"][0]
    assert root_node["pid"] == 1

    # Check children of root PID 1
    children_pids = [c["pid"] for c in root_node.get("children", [])]
    assert 100 in children_pids
    assert 300 in children_pids

    # Find node 100 and verify child 200 is attached to 100
    node_100 = next(c for c in root_node["children"] if c["pid"] == 100)
    assert any(child["pid"] == 200 for child in node_100.get("children", []))


async def test_telemetry_risk_and_process_list_no_conflict():
    """
    Verify that PROCESS_LIST stores process snapshot, while TELEMETRY_RISK
    does not overwrite or clear the saved process tree records.
    """
    mock_ws = MagicMock()
    mock_ws.query_params = {"agent_id": "client1"}

    process_list_msg = {
        "type": "PROCESS_LIST",
        "payload": {
            "agent_id": "client1",
            "processes": [
                {"pid": 50, "parent_pid": 1, "name": "nginx", "cpu": 0.5, "ram": 1.0}
            ]
        },
        "wait_ack": True
    }

    telemetry_risk_msg = {
        "type": "TELEMETRY_RISK",
        "payload": {
            "agent_id": "client1",
            "cpu_usage": 10.0,
            "ram_usage": 20.0,
            "process_list": [{"name": "mimikatz.exe", "is_suspicious": True}]
        },
        "wait_ack": True
    }

    mock_ws.receive_text = AsyncMock(side_effect=[
        json.dumps(process_list_msg),
        json.dumps(telemetry_risk_msg),
        WebSocketDisconnect()
    ])
    mock_ws.send_json = AsyncMock()

    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session_local = MagicMock(return_value=mock_session)
    mock_session_local.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_local.__aexit__ = AsyncMock(return_value=None)

    mock_risk_record = MagicMock()
    mock_risk_record.score = 25.0
    mock_risk_service = MagicMock()
    mock_risk_service.process_risk = AsyncMock(return_value=mock_risk_record)

    with patch("app.websocket.agent_ws.connection_manager.connect", AsyncMock()), \
         patch("app.websocket.agent_ws.connection_manager.disconnect", MagicMock()), \
         patch("app.websocket.agent_ws.AsyncSessionLocal", mock_session_local), \
         patch("app.websocket.agent_ws._save_process_list", AsyncMock(return_value=1)) as mock_save_proc, \
         patch("app.websocket.agent_ws.RiskAssessmentService", return_value=mock_risk_service):

        await agent_websocket_endpoint(mock_ws)

        # _save_process_list should be called exactly ONCE (for PROCESS_LIST), NOT for TELEMETRY_RISK
        mock_save_proc.assert_awaited_once()
        call_args = mock_save_proc.call_args[0]
        assert call_args[1] == "client1"
        assert len(call_args[2]) == 1
        assert call_args[2][0]["name"] == "nginx"

        # Risk service should be invoked for TELEMETRY_RISK
        mock_risk_service.process_risk.assert_awaited_once()
