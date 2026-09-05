import os
import tempfile
import time
import asyncio
import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fim import FileIntegrityMonitor
import agent


def test_fim_detects_modification_and_suppresses_repeat():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("initial content")

        fim = FileIntegrityMonitor(agent_id="test-agent", watched_files=[test_file], watched_dirs=[])
        assert len(fim.check_integrity()) == 0

        # Modify file
        with open(test_file, "w") as f:
            f.write("compromised content")

        alerts = fim.check_integrity()
        assert len(alerts) == 1
        assert alerts[0]["action"] == "MODIFIED"
        assert alerts[0]["file_path"] == test_file
        assert alerts[0]["old_hash"] != alerts[0]["new_hash"]

        # Second check without changes should NOT generate repeat alert
        repeat_alerts = fim.check_integrity()
        assert len(repeat_alerts) == 0

        # Delete file
        os.remove(test_file)
        del_alerts = fim.check_integrity()
        assert len(del_alerts) == 1
        assert del_alerts[0]["action"] == "DELETED"


def test_get_network_flow_stats_calculates_delta():
    # Mock psutil.net_io_counters
    mock_io_1 = MagicMock(bytes_sent=1000, bytes_recv=2000, packets_sent=10, packets_recv=20)
    mock_io_2 = MagicMock(bytes_sent=1500, bytes_recv=2800, packets_sent=15, packets_recv=28)

    with patch("psutil.net_io_counters", side_effect=[mock_io_1, mock_io_2]):
        agent._prev_net_io = None
        agent._prev_net_time = None

        stats1 = agent.get_network_flow_stats()
        assert stats1["bytes_sent_delta"] == 0
        assert stats1["packets_sent_delta"] == 0

        time.sleep(0.05)
        stats2 = agent.get_network_flow_stats()
        assert stats2["bytes_sent_delta"] == 500
        assert stats2["bytes_recv_delta"] == 800
        assert stats2["packets_sent_delta"] == 5
        assert stats2["packets_recv_delta"] == 8
        assert stats2["tcp_packets_delta"] + stats2["udp_packets_delta"] == 5


def test_collect_process_info_filters_zombies():
    mock_proc_running = MagicMock()
    mock_proc_running.info = {
        'pid': 10,
        'ppid': 1,
        'name': 'bash',
        'exe': '/bin/bash',
        'cmdline': ['bash'],
        'cpu_percent': 0.0,
        'memory_percent': 0.1,
        'status': 'running'
    }

    mock_proc_zombie = MagicMock()
    mock_proc_zombie.info = {
        'pid': 20,
        'ppid': 10,
        'name': 'defunct_child',
        'exe': '',
        'cmdline': [],
        'cpu_percent': 0.0,
        'memory_percent': 0.0,
        'status': 'zombie'
    }

    with patch("psutil.process_iter", return_value=[mock_proc_running, mock_proc_zombie]):
        procs = agent.collect_process_info()
        assert len(procs) == 1
        assert procs[0]["pid"] == 10
        assert procs[0]["name"] == "bash"


@pytest.mark.asyncio
async def test_send_ws_json_no_wait_does_not_block_for_recv():
    mock_ws = AsyncMock()
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock(side_effect=Exception("recv should not be called"))

    msg = {"type": "FLOW_STATS", "payload": {"bytes": 100}}
    await agent.send_ws_json_no_wait(mock_ws, msg)

    mock_ws.send.assert_awaited_once_with(json.dumps(msg))
    mock_ws.recv.assert_not_called()


@pytest.mark.asyncio
async def test_send_ws_json_and_wait_receives_response():
    mock_ws = AsyncMock()
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock(return_value=json.dumps({"status": "ack", "message": "Heartbeat processed"}))

    msg = {"type": "HEARTBEAT", "payload": {}}
    res = await agent.send_ws_json_and_wait(mock_ws, msg)

    mock_ws.send.assert_awaited_once_with(json.dumps(msg))
    mock_ws.recv.assert_awaited_once()
    assert res == {"status": "ack", "message": "Heartbeat processed"}
