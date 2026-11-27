"""Task B: socket holders carry their verified parent chain and effective UID; outbound direction."""
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

import socket_telemetry as telemetry

CHILD = (
    "import os,socket,sys,time\n"
    "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))\n"
    "[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\n"
    "time.sleep(30)\n"
)


def test_stdio_socket_holder_keeps_launcher_chain(tmp_path):
    if not shutil.which("ss"):
        pytest.skip("ss is required")
    script = tmp_path / "payload.py"
    script.write_text(CHILD)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        launcher = subprocess.Popen(["/bin/sh", "-c", f"{sys.executable} {script} {port}; sleep 1"])
        try:
            peer, _ = listener.accept()
            with peer:
                deadline = time.time() + 5
                row = None
                while row is None and time.time() < deadline:
                    rows = telemetry.socket_rows({})
                    row = next((r for r in rows if r["dst_port"] == port and r["status"] == "ESTAB"
                                and any(int(pid) != os.getpid() for pid, _ in r["owners"])), None)
                    time.sleep(0.1)
                assert row is not None
                holders, attribution = telemetry.socket_holders(row, time.time(), {})
                assert attribution == "inode_verified"
                holder = holders[0]
                assert holder["socket_stdio"] is True and holder["cmdline"].endswith(f"payload.py {port}")
                assert holder["euid"] == os.geteuid() and holder["parent_pid"] == launcher.pid
                parent = holder["ancestry"][0]
                assert parent["pid"] == launcher.pid and parent["cmdline"].startswith("/bin/sh -c")
                assert parent["process_start_time"] <= holder["process_start_time"]
        finally:
            launcher.kill()
            subprocess.run(["pkill", "-f", str(script)], check=False)


def test_established_socket_without_local_listener_is_outbound(monkeypatch):
    base = {"family": "IPv4", "protocol": "TCP", "inode": "1", "owners": [(999999, 3)]}
    rows = [
        {**base, "src_ip": "100.112.146.63", "src_port": 40986, "dst_ip": "100.67.222.3", "dst_port": 4444, "status": "ESTAB"},
        {**base, "src_ip": "172.31.32.238", "src_port": 22, "dst_ip": "198.51.100.9", "dst_port": 50000, "status": "ESTAB"},
        {**base, "src_ip": "0.0.0.0", "src_port": 22, "dst_ip": None, "dst_port": None, "status": "LISTEN"},
    ]
    monkeypatch.setattr(telemetry, "socket_rows", lambda errors: rows)
    holder = {"pid": 999999, "parent_pid": 1, "process_start_time": 1.0, "process_name": "python3",
              "exe_path": "/usr/bin/python3.13", "socket_stdio": True}
    monkeypatch.setattr(telemetry, "socket_holders", lambda row, started, cache=None: ([holder], "inode_verified"))

    class Tracker:
        def process_connections(self, connections, **kwargs):
            return connections

    out = {(c["src_port"]): c for c in telemetry.collect_connections(Tracker())}
    assert out[40986]["direction"] == "outbound" and out[40986]["direction_basis"] == "no_local_listener"
    assert out[40986]["is_suspicious"] is True  # interpreter with stdio on an outbound socket
    assert out[22]["direction"] == "inbound" and out[22]["direction_basis"] == "local_listener"
