"""Task B: process connector decoding and event handling (live subscription only when root)."""
import os
import struct
import subprocess
import time

import pytest

import proc_events as pe


def datagram(what, stamp, *fields):
    body = pe.EVENT_HEADER.pack(what, 0, stamp) + struct.pack(f"={len(fields)}I", *fields)
    cn = pe.CN_MSG.pack(pe.CN_IDX_PROC, pe.CN_VAL_PROC, 0, 0, len(body), 0) + body
    return pe.NLMSGHDR.pack(pe.NLMSGHDR.size + len(cn), pe.NLMSG_DONE, 0, 0, 0) + cn


def test_decodes_fork_exec_exit_and_subscription():
    data = (datagram(pe.PROC_EVENT_FORK, 5, 100, 100, 200, 200) + datagram(pe.PROC_EVENT_EXEC, 6, 200, 200)
            + datagram(pe.PROC_EVENT_EXIT, 7, 200, 200, 9, 0))
    kinds = pe.parse_datagram(data)
    assert [k for k, _, _ in kinds] == ["fork", "exec", "exit"]
    assert kinds[0][2] == {"parent_pid": 100, "parent_tgid": 100, "child_pid": 200, "child_tgid": 200}
    assert pe.parse_datagram(b"\x00" * 10) == []
    message = pe.subscribe_message(1234)
    length, kind, _, _, port = pe.NLMSGHDR.unpack_from(message)
    assert length == len(message) and kind == pe.NLMSG_DONE and port == 1234
    assert struct.unpack_from("=I", message, length - 4)[0] == pe.PROC_CN_MCAST_LISTEN


def test_short_lived_exec_is_kept_as_partial_with_fork_parent(monkeypatch):
    listener = pe.ProcEventListener(ignore_parent_pids={42})
    monkeypatch.setattr(pe, "read_process", lambda pid: None)  # already exited when read
    listener.handle("fork", 1_000_000_000, {"parent_pid": 153380, "parent_tgid": 153380, "child_pid": 154105, "child_tgid": 154105})
    listener.handle("exec", 1_000_500_000, {"pid": 154105, "tgid": 154105})
    listener.handle("exit", 2_000_000_000, {"pid": 154105, "tgid": 154105, "exit_code": 9, "exit_signal": 17})
    listener.handle("exec", 1, {"pid": 7, "tgid": 8})  # thread exec ignored
    events, stats = listener.drain()
    exec_event, exit_event = events
    assert exec_event["partial"] is True and exec_event["parent_pid"] == 153380
    assert exec_event["start_time_source"] == "event_clock" and exec_event["fork_observed_at"] < exec_event["observed_at"]
    assert exit_event["exit_signal"] == 9 and exit_event["exit_code"] == 0
    assert stats["dropped"] == 0


def test_exec_snapshot_includes_parent_and_skips_agent_children(monkeypatch):
    procs = {
        154107: {"pid": 154107, "parent_pid": 154105, "process_start_time": 10.0, "name": "python3",
                 "exe": "/usr/bin/python3.13", "cmdline": "python3 /tmp/uploads/backdoor.py", "uid": 0, "euid": 0},
        154105: {"pid": 154105, "parent_pid": 153380, "process_start_time": 9.9, "name": "sh", "exe": "/usr/bin/dash",
                 "cmdline": "/bin/sh -c ping -c 1 127.0.0.1;python3 /tmp/uploads/backdoor.py", "uid": 0, "euid": 0},
        5000: {"pid": 5000, "parent_pid": 42, "process_start_time": 1.0, "name": "ss", "exe": "/usr/bin/ss", "cmdline": "ss"},
    }
    monkeypatch.setattr(pe, "read_process", procs.get)
    listener = pe.ProcEventListener(ignore_parent_pids={42})
    listener.handle("exec", 3, {"pid": 154107, "tgid": 154107})
    listener.handle("exec", 3, {"pid": 5000, "tgid": 5000})
    events, stats = listener.drain()
    assert len(events) == 1 and stats["skipped_own"] == 1
    event = events[0]
    assert event["euid"] == 0 and event["parent"]["cmdline"].startswith("/bin/sh -c ping")
    assert event["start_time_source"] == "procfs"


def test_buffer_is_bounded():
    listener = pe.ProcEventListener(max_buffer=3)
    for n in range(5):
        listener._push({"n": n})
    events, stats = listener.drain()
    assert [e["n"] for e in events] == [2, 3, 4] and stats["dropped"] == 2


@pytest.mark.skipif(os.geteuid() != 0, reason="the process connector requires CAP_NET_ADMIN")
def test_live_subscription_sees_a_short_lived_shell():
    listener = pe.ProcEventListener(ignore_parent_pids=set())
    assert listener.open(), listener.error
    listener.start()
    try:
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 0.3"])
        child.wait()
        time.sleep(0.5)
        events, _ = listener.drain(5000)
        assert any(e["event"] == "exec" and e["pid"] == child.pid for e in events)
    finally:
        listener.stop()


def test_undelivered_events_are_requeued_in_order():
    listener = pe.ProcEventListener(max_buffer=10)
    for n in range(3):
        listener._push({"n": n})
    events, _ = listener.drain(2)
    listener.requeue(events)
    again, _ = listener.drain()
    assert [e["n"] for e in again] == [0, 1, 2]
