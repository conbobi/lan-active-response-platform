"""Event-driven process telemetry from the Linux process connector (netlink, CN_IDX_PROC).

The kernel reports fork/exec/exit of every process as it happens, so short-lived processes that a
15-20 s poll would miss (e.g. a web app's ``/bin/sh -c`` that lives a few seconds) are still seen.
On exec the process is read from /proc immediately; if it has already gone, the event is kept as a
partial record with the parent known from the preceding fork event. Requires CAP_NET_ADMIN (the
Agent runs as root); when the subscription fails the Agent keeps its polling collectors.

Nothing here is a detection: events are raw observations forwarded to the Manager.
"""
import collections
import logging
import os
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger(__name__)

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
NLMSG_DONE = 3
NLMSG_ERROR = 2
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2

PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_EXIT = 0x80000000

NLMSGHDR = struct.Struct("=IHHII")          # len, type, flags, seq, pid
CN_MSG = struct.Struct("=IIIIHH")           # idx, val, seq, ack, len, flags
EVENT_HEADER = struct.Struct("=IIQ")        # what, cpu, timestamp_ns (monotonic)
FORK = struct.Struct("=IIII")               # parent_pid, parent_tgid, child_pid, child_tgid
EXEC = struct.Struct("=II")                 # process_pid, process_tgid
EXIT = struct.Struct("=IIII")               # process_pid, process_tgid, exit_code, exit_signal


def subscribe_message(port_id: int, op: int = PROC_CN_MCAST_LISTEN) -> bytes:
    payload = struct.pack("=I", op)
    cn = CN_MSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0) + payload
    return NLMSGHDR.pack(NLMSGHDR.size + len(cn), NLMSG_DONE, 0, 0, port_id) + cn


def parse_datagram(data: bytes) -> List[Tuple[str, int, Dict[str, int]]]:
    """Decode one netlink datagram into (kind, timestamp_ns, fields) tuples; unknown kinds skipped."""
    events = []
    offset = 0
    while offset + NLMSGHDR.size <= len(data):
        length, msg_type, _, _, _ = NLMSGHDR.unpack_from(data, offset)
        if length < NLMSGHDR.size or offset + length > len(data):
            break
        body = offset + NLMSGHDR.size
        if msg_type not in (NLMSG_ERROR,) and body + CN_MSG.size + EVENT_HEADER.size <= offset + length:
            idx, val, _, _, cn_len, _ = CN_MSG.unpack_from(data, body)
            event_at = body + CN_MSG.size
            if idx == CN_IDX_PROC and val == CN_VAL_PROC and cn_len >= EVENT_HEADER.size:
                what, _, stamp = EVENT_HEADER.unpack_from(data, event_at)
                fields_at = event_at + EVENT_HEADER.size
                end = offset + length
                if what == PROC_EVENT_FORK and fields_at + FORK.size <= end:
                    ppid, ptgid, cpid, ctgid = FORK.unpack_from(data, fields_at)
                    events.append(("fork", stamp, {"parent_pid": ppid, "parent_tgid": ptgid,
                                                   "child_pid": cpid, "child_tgid": ctgid}))
                elif what == PROC_EVENT_EXEC and fields_at + EXEC.size <= end:
                    pid, tgid = EXEC.unpack_from(data, fields_at)
                    events.append(("exec", stamp, {"pid": pid, "tgid": tgid}))
                elif what == PROC_EVENT_EXIT and fields_at + EXIT.size <= end:
                    pid, tgid, code, sig = EXIT.unpack_from(data, fields_at)
                    events.append(("exit", stamp, {"pid": pid, "tgid": tgid, "exit_code": code, "exit_signal": sig}))
        offset += (length + 3) & ~3  # NLMSG_ALIGN
    return events


def read_process(pid: int) -> Optional[Dict[str, Any]]:
    """Snapshot a process right after exec; None if it is already gone."""
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            start = proc.create_time()
            uids = proc.uids()
            try:
                argv = proc.cmdline()
            except psutil.AccessDenied:
                argv = []
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, FileNotFoundError):
                exe = ""
            record = {
                "pid": pid, "parent_pid": proc.ppid(), "process_start_time": start, "name": proc.name()[:128],
                "exe": (exe or "")[:1024], "cmdline": " ".join(argv)[:2048], "uid": uids.real, "euid": uids.effective,
                "username": _safe(proc.username), "cwd": _safe(proc.cwd, 512),
            }
        if psutil.Process(pid).create_time() != start:
            return None  # PID reused between reads
        return record
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ProcessLookupError):
        return None
    except psutil.AccessDenied:
        return {"pid": pid, "access_denied": True}


def _safe(read, limit=64):
    try:
        value = read()
        return str(value)[:limit] if value is not None else None
    except (psutil.Error, OSError):
        return None


class ProcEventListener(threading.Thread):
    """Background reader of the process connector; drain() hands buffered observations to the sender."""

    def __init__(self, max_buffer: int = 4000, ignore_parent_pids: Optional[set] = None):
        super().__init__(name="proc-events", daemon=True)
        self.max_buffer = max_buffer
        self.ignore_parent_pids = ignore_parent_pids if ignore_parent_pids is not None else {os.getpid()}
        self.available = False
        self.error: Optional[str] = None
        self._buffer: collections.deque = collections.deque()
        self._lock = threading.Lock()
        self._dropped = 0
        self._skipped_own = 0
        self._fork_parent: "collections.OrderedDict[int, Tuple[int, int]]" = collections.OrderedDict()
        self._reported: "collections.OrderedDict[int, float]" = collections.OrderedDict()
        self._clock_offset = time.time() - time.monotonic()
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    # Netlink event timestamps are CLOCK_MONOTONIC nanoseconds.
    def wall_time(self, stamp_ns: int) -> float:
        return round(self._clock_offset + stamp_ns / 1e9, 6)

    def open(self) -> bool:
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.bind((0, CN_IDX_PROC))
            sock.send(subscribe_message(sock.getsockname()[0]))
            sock.settimeout(1.0)
        except (AttributeError, OSError) as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            logger.warning("Process connector unavailable (%s); polling only", self.error)
            return False
        self._sock = sock
        self.available = True
        return True

    def run(self):
        if self._sock is None and not self.open():
            return
        while not self._stop.is_set():
            try:
                data = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError as exc:
                if getattr(exc, "errno", None) == 105:  # ENOBUFS: kernel dropped events under load
                    with self._lock:
                        self._dropped += 1
                    continue
                self.error = f"{type(exc).__name__}: {exc}"
                self.available = False
                logger.warning("Process connector stopped: %s", self.error)
                return
            for kind, stamp, fields in parse_datagram(data):
                self.handle(kind, stamp, fields)

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.send(subscribe_message(self._sock.getsockname()[0], PROC_CN_MCAST_IGNORE))
            except OSError:
                pass
            self._sock.close()

    def handle(self, kind: str, stamp: int, fields: Dict[str, int]):
        if kind == "fork":
            if fields["child_pid"] != fields["child_tgid"]:
                return  # new thread, not a new process
            self._fork_parent[fields["child_tgid"]] = (fields["parent_tgid"], stamp)
            while len(self._fork_parent) > 8192:
                self._fork_parent.popitem(last=False)
            return
        if kind == "exec":
            if fields["pid"] != fields["tgid"]:
                return
            pid = fields["pid"]
            record = read_process(pid)
            fork = self._fork_parent.get(pid)
            parent_pid = (record or {}).get("parent_pid") or (fork[0] if fork else None)
            if parent_pid in self.ignore_parent_pids:
                self._skipped_own += 1  # the Agent's own collectors (ss, ip, ufw ...)
                return
            event = {"event": "exec", "observed_at": self.wall_time(stamp), "pid": pid,
                     "source": "proc_connector"}
            if record and not record.get("access_denied"):
                event.update(record)
                event["start_time_source"] = "procfs"
                parent = read_process(record["parent_pid"]) if record.get("parent_pid") else None
                if parent and not parent.get("access_denied"):
                    event["parent"] = {k: parent.get(k) for k in (
                        "pid", "parent_pid", "process_start_time", "name", "exe", "cmdline", "uid", "euid")}
            else:
                # Exited (or unreadable) before it could be read: keep what the kernel told us.
                event.update({"partial": True, "parent_pid": parent_pid,
                              "fork_observed_at": self.wall_time(fork[1]) if fork else None,
                              "start_time_source": "event_clock"})
            self._reported[pid] = event["observed_at"]
            while len(self._reported) > 8192:
                self._reported.popitem(last=False)
            self._push(event)
            return
        if kind == "exit":
            if fields["pid"] != fields["tgid"] or fields["pid"] not in self._reported:
                return
            self._reported.pop(fields["pid"], None)
            self._fork_parent.pop(fields["pid"], None)
            self._push({"event": "exit", "observed_at": self.wall_time(stamp), "pid": fields["pid"],
                        # task->exit_code is a wait status: (code << 8) | terminating signal
                        "exit_code": (fields["exit_code"] >> 8) & 0xFF, "exit_signal": (fields["exit_code"] & 0x7F) or None,
                        "source": "proc_connector"})

    def _push(self, event: Dict[str, Any]):
        with self._lock:
            if len(self._buffer) >= self.max_buffer:
                self._buffer.popleft()
                self._dropped += 1
            self._buffer.append(event)

    def requeue(self, events: List[Dict[str, Any]]):
        """Put undelivered events back in front (oldest dropped first if the buffer is full)."""
        with self._lock:
            for event in reversed(events):
                if len(self._buffer) >= self.max_buffer:
                    self._dropped += 1
                    continue
                self._buffer.appendleft(event)

    def drain(self, limit: int = 1000) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        with self._lock:
            events = [self._buffer.popleft() for _ in range(min(limit, len(self._buffer)))]
            stats = {"dropped": self._dropped, "skipped_own": self._skipped_own,
                     "available": self.available, "error": self.error, "pending": len(self._buffer)}
            self._dropped = 0
            self._skipped_own = 0
        return events, stats
