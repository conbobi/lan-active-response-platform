import os
import threading
from collections import deque
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None


class ConnectionTracker:
    """
    Monitors active outbound TCP network connections on the agent host.
    Maintains stable connection identity across sampling cycles:
    - Distinguishes repeated observations of an existing socket (observation_count)
      from genuine new connection establishments (new_connection_count).
    - Preserves process PID, process executable, process start time, and first_seen timestamp.
    - Prevents polling frequency (e.g. 15s) from generating artificial beaconing rhythms.
    """

    def __init__(self, max_history: int = 150):
        self.history = deque(maxlen=max_history)
        self.lock = threading.Lock()
        self.active_sockets: Dict[Tuple[str, int, str, int, Optional[int]], Dict[str, Any]] = {}

    def _get_process_metadata(self, pid: Optional[int]) -> Tuple[str, str, Optional[float]]:
        """Safely extract process name, exe path, and process creation timestamp."""
        if not pid or pid <= 0:
            return "unknown", "", None
        try:
            proc = psutil.Process(pid)
            name = proc.name() or "unknown"
            try:
                exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ""
            try:
                create_time = proc.create_time()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                create_time = None
            return name, exe, create_time
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            return "unknown", "", None

    def sample_connections(self) -> List[Dict[str, Any]]:
        """
        Sample active established network connections from psutil and process them.
        """
        if psutil is None:
            return []

        raw_conns = []
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if not conn.raddr or conn.status == "LISTEN":
                    continue
                raw_conns.append({
                    "src_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                    "src_port": conn.laddr.port if conn.laddr else 0,
                    "dst_ip": conn.raddr.ip,
                    "dst_port": conn.raddr.port,
                    "status": conn.status,
                    "pid": conn.pid,
                })
        except Exception:
            pass

        return self.process_connections(raw_conns)

    def process_connections(
        self,
        raw_conns: List[Dict[str, Any]],
        now_dt: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Processes a list of raw connection dictionaries.
        Accurately differentiates new connection opens from continuous persistent sockets.
        Used both by sample_connections and for deterministic testing.
        """
        now_dt = now_dt or datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        current_seen_keys: Set[Tuple[str, int, str, int, Optional[int]]] = set()
        new_samples = []

        for conn in raw_conns:
            status = conn.get("status", "ESTABLISHED")
            if status == "LISTEN":
                continue

            dst_ip = conn.get("dst_ip", "")
            dst_port = conn.get("dst_port", 0)
            src_ip = conn.get("src_ip", "0.0.0.0")
            src_port = conn.get("src_port", 0)
            pid = conn.get("pid")

            if not dst_ip or dst_ip.startswith("127.") or dst_ip in ("::1", "0.0.0.0", "localhost"):
                continue

            socket_key = (src_ip, src_port, dst_ip, dst_port, pid)
            current_seen_keys.add(socket_key)

            with self.lock:
                if socket_key in self.active_sockets:
                    # Existing persistent socket: increment observation count, DO NOT append duplicate timeline event
                    state = self.active_sockets[socket_key]
                    state["observation_count"] += 1
                    state["last_seen"] = now_iso
                    state["status"] = status
                    state["is_new"] = False
                else:
                    # Brand new connection establishment event!
                    proc_name = conn.get("process_name")
                    exe_path = conn.get("exe_path")
                    proc_start = conn.get("process_start_time")
                    if proc_name is None:
                        proc_name, exe_path, proc_start = self._get_process_metadata(pid)

                    state = {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "pid": pid,
                        "process_name": proc_name or "unknown",
                        "exe_path": exe_path or "",
                        "process_start_time": proc_start,
                        "status": status,
                        "first_seen": now_iso,
                        "last_seen": now_iso,
                        "timestamp": now_iso,  # Timestamp of establishment!
                        "observation_count": 1,
                        "new_connection_count": 1,
                        "is_new": True,
                    }
                    self.active_sockets[socket_key] = state
                    self.history.append(state)

                new_samples.append(dict(state))

        # Housekeeping: prune closed sockets no longer present in current sample
        with self.lock:
            closed_keys = [k for k in self.active_sockets if k not in current_seen_keys]
            for k in closed_keys:
                del self.active_sockets[k]

        return new_samples

    def get_connection_history(self) -> List[Dict[str, Any]]:
        """Return snapshot of genuine new connection events timeline."""
        with self.lock:
            return list(self.history)

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Return snapshot of currently active connections with observation counts."""
        with self.lock:
            return [dict(v) for v in self.active_sockets.values()]


global_connection_tracker = ConnectionTracker()
