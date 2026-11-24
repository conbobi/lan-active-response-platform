import os
import tempfile
import time
import asyncio
import json
from types import SimpleNamespace
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import sys
from pathlib import Path
agent_dir = str(Path(__file__).resolve().parent)
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

from fim import FileIntegrityMonitor
import importlib.util
spec = importlib.util.spec_from_file_location("agent", Path(agent_dir) / "agent.py")
agent = importlib.util.module_from_spec(spec)
sys.modules["agent"] = agent
spec.loader.exec_module(agent)


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


def test_auth_monitor_web_and_ssh_events():
    from auth_monitor import AuthMonitor
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        log_path = f.name
        f.write("# Initial existing content\n")
        f.flush()

    try:
        monitor = AuthMonitor(agent_id="test-agent")
        monitor.LOG_PATHS = [log_path]
        monitor.file_positions[log_path] = os.path.getsize(log_path)

        # Append events
        with open(log_path, "a") as f:
            f.write("[WEB_AUTH] status=failed username=admin ip=172.67.204.217 service=flask_web\n")
            f.write('{"service": "flask_web", "username": "victim", "source_ip": "1.2.3.4", "status": "failed"}\n')
            f.write("pam_unix(sshd:auth): authentication failure; rhost=192.168.1.100 user=root\n")
            f.write("Failed password for invalid user root from 192.168.1.100 port 2222 ssh2\n")
            f.write("[WEB_AUTH] status=success username=admin ip=172.67.204.217 service=flask_web\n")
            f.write("Accepted publickey for root from 192.168.1.100 port 2222 ssh2\n")

        events = monitor.get_new_events()
        assert len(events) == 5
        assert events[0]["service"] == "flask_web"
        assert events[0]["username"] == "admin"
        assert events[0]["status"] == "failed"
        assert events[0]["source_ip"] == "172.67.204.217"

        assert events[1]["username"] == "victim"
        assert events[1]["status"] == "failed"

        assert events[2]["service"] == "ssh"
        assert events[2]["username"] == "root"
        assert events[2]["status"] == "failed"

        assert events[3]["username"] == "admin"
        assert events[3]["status"] == "success"
        assert events[4]["auth_method"] == "publickey"
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)


def test_socket_telemetry_uses_the_observed_file_descriptor(monkeypatch):
    from connection_tracker import ConnectionTracker
    import socket_telemetry as telemetry

    observed = {
        "protocol": "TCP", "status": "ESTAB", "family": "IPv4",
        "src_ip": "192.0.2.6", "src_port": 32001, "dst_ip": "192.0.2.5", "dst_port": 443,
        "owners": [(123, 5)], "inode": "42", "socket_id": "IPv4:1",
    }
    metadata = {"pid": 123, "parent_pid": 17, "process_start_time": 1000.5,
                "process_name": "bash", "exe_path": "/usr/bin/bash", "pty_requested": False}
    descriptors = {"0": "socket:[42]", "1": "socket:[42]", "2": "/dev/null", "5": "socket:[42]"}
    monkeypatch.setattr(telemetry, "socket_rows", lambda _: [observed])
    monkeypatch.setattr(telemetry, "_process", lambda *_: metadata.copy())
    monkeypatch.setattr(telemetry, "_ancestry", lambda *_: [])
    monkeypatch.setattr(telemetry, "_descendants", lambda *_: [])
    monkeypatch.setattr(telemetry.psutil, "Process", lambda _: SimpleNamespace(create_time=lambda: 1000.5))
    monkeypatch.setattr(telemetry.os, "readlink", lambda path: descriptors[path.rsplit("/", 1)[-1]])

    tracker = ConnectionTracker()
    sample, = telemetry.collect_connections(tracker)
    assert sample["protocol"] == "TCP"
    assert sample["process_start_time"] == 1000.5
    assert sample["holders"][0]["socket_stdio"] is True
    descriptors["1"] = "socket:[43]"
    sample, = telemetry.collect_connections(tracker)
    assert sample["holders"][0]["socket_stdio"] is False


def test_auth_monitor_deduplicates_mirrors_and_ignores_non_auth_records(tmp_path):
    from auth_monitor import AuthMonitor

    monitor = AuthMonitor(agent_id="test-agent")
    paths = [tmp_path / "primary.log", tmp_path / "mirror.log"]
    monitor.LOG_PATHS = [str(path) for path in paths]
    event = {
        "event_type": "WEB_AUTH_ERROR", "status": "error", "username": "operator",
        "source_ip": "192.0.2.5", "timestamp": "2026-11-24T04:43:45+00:00",
        "service": "flask_web", "path": "/login", "method": "POST", "request_id": "a" * 32,
    }
    unrelated = {**event, "status": None, "event_type": "LAB_EVENT", "request_id": "b" * 32}
    for path in paths:
        path.write_text(json.dumps(event) + "\n" + json.dumps(unrelated) + "\n")
    observed, = monitor.get_new_events()
    assert observed["status"] == "error"
    assert observed["timestamp"] == event["timestamp"]
    assert observed["event_id"] == event["request_id"]
    assert monitor.get_new_events() == []
