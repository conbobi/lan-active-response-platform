import os
import shutil
import socket
import time
from types import SimpleNamespace

import psutil
import pytest

from commands import process_target
import socket_telemetry as telemetry


def test_collector_verifies_live_tcp_inode_and_descriptor(monkeypatch):
    if not shutil.which("ss"):
        pytest.skip("ss is required")
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        client.connect(listener.getsockname())
        peer, _ = listener.accept()
        with peer:
            started = time.time()
            rows = telemetry.socket_rows({})
            row, = [item for item in rows if item["src_ip"] == "127.0.0.1"
                    and item["src_port"] == client.getsockname()[1] and item["status"] == "ESTAB"]
            my_pid = os.getpid()
            monkeypatch.setattr(telemetry.os, "getpid", lambda: -1)
            holders, attribution = telemetry.socket_holders(row, started)
            assert attribution == "inode_verified"
            assert holders[0]["pid"] == my_pid
            assert client.fileno() in holders[0]["socket_fds"]
            assert holders[0]["socket_stdio"] is False


@pytest.mark.parametrize(("error_type", "reason"), [
    (psutil.AccessDenied, "access_denied"),
    (psutil.NoSuchProcess, "owner_changed_or_exited"),
])
def test_unavailable_process_is_untargeted(monkeypatch, error_type, reason):
    def unavailable(pid, _):
        raise error_type(pid)

    monkeypatch.setattr(telemetry, "_process", unavailable)
    assert telemetry.socket_holders({"inode": "12", "owners": [(500, 4)]}, 100) == ([], reason)
    assert telemetry.socket_holders({"inode": None, "owners": [(500, 4)]}, 100) == ([], "unverified_socket")


def test_shared_socket_preserves_each_verified_holder(monkeypatch):
    monkeypatch.setattr(telemetry, "_process", lambda pid, _: {
        "pid": pid, "exe_path": "/usr/bin/python3", "process_start_time": float(pid), "pty_requested": False,
    })
    monkeypatch.setattr(telemetry.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: float(pid)))
    monkeypatch.setattr(telemetry.os, "readlink", lambda path: "socket:[42]" if path.endswith("/4") else "/dev/null")
    holders, status = telemetry.socket_holders({"inode": "42", "owners": [(500, 4), (501, 4), (500, 5)]}, 1000)
    assert status == "inode_verified"
    assert [(item["pid"], item["socket_fds"]) for item in holders] == [(500, [4]), (501, [4])]


def test_termination_rejects_missing_pid_and_reused_identity(monkeypatch):
    signals = []
    monkeypatch.setattr(process_target.os, "pidfd_open", lambda pid: signals.append(pid))
    monkeypatch.setattr(process_target.psutil, "Process", lambda pid=None: SimpleNamespace(
        pid=pid or 1001, parents=lambda: [], create_time=lambda: 900.0,
        exe=lambda: "/usr/bin/bash", ppid=lambda: 700,
    ))
    params = {"confirmed": True, "pid": 1000, "process_start_time": 899.0, "exe_path": "/usr/bin/bash", "parent_pid": 700}
    assert process_target.terminate({**params, "pid": None}, True)["status"] == "failed"
    assert "identity changed" in process_target.terminate(params, True)["message"]
    assert not signals


@pytest.mark.parametrize(("name", "expected"), [
    ("sshd", "protected"), ("tailscaled", "protected"), ("systemd", "protected"),
])
def test_termination_protects_essential_processes(monkeypatch, name, expected):
    def fake_process(pid=None):
        return SimpleNamespace(pid=pid or 1001, parents=lambda: [], create_time=lambda: 900.0,
                               name=lambda: name, exe=lambda: f"/usr/bin/{name}", ppid=lambda: 700)

    monkeypatch.setattr(process_target.psutil, "Process", fake_process)
    params = {"confirmed": True, "pid": 1000, "process_start_time": 900.0, "exe_path": f"/usr/bin/{name}", "parent_pid": 700}
    assert expected in process_target.terminate(params, True)["message"]


def test_validated_termination_verifies_exit_of_each_holder(monkeypatch):
    def make_proc(pid=None):
        def children(recursive=False):
            return [make_proc(1002)] if pid == 1000 else []
        return SimpleNamespace(pid=pid or 1001, parents=lambda: [], create_time=lambda: float(pid or 1001),
                               name=lambda: "sleep", exe=lambda: "/usr/bin/sleep",
                               ppid=lambda: 1000 if pid == 1002 else 700, children=children)

    signals = []
    closed = []
    monkeypatch.setattr(process_target.psutil, "Process", make_proc)
    monkeypatch.setattr(process_target.os, "pidfd_open", lambda pid: pid + 1)
    monkeypatch.setattr(process_target.os, "close", closed.append)
    monkeypatch.setattr(process_target.signal, "pidfd_send_signal", lambda fd, _: signals.append(fd))
    monkeypatch.setattr(process_target.select, "poll", lambda: SimpleNamespace(
        register=lambda *_: None, poll=lambda _: [(1, process_target.select.POLLIN)],
    ))
    params = {"confirmed": True, "pid": 1000, "process_start_time": 1000.0,
              "exe_path": "/usr/bin/sleep", "parent_pid": 700}
    assert process_target.terminate(params, tree=True)["killed_pids"] == [1002, 1000]
    assert signals == [1003, 1001]
    assert closed == [1003, 1001]
