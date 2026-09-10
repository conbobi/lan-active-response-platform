import psutil
import threading
from collections import deque
from datetime import datetime, timezone
from typing import List, Dict, Any


class ConnectionTracker:
    """
    Monitors active outbound TCP network connections on the agent host.
    Maintains a sliding timeline of remote endpoints and connection timestamps
    to empower beaconing detection algorithms on the SOC Manager.
    """

    def __init__(self, max_history: int = 100):
        self.history = deque(maxlen=max_history)
        self.lock = threading.Lock()
        self.seen_connections = set()

    def sample_connections(self) -> List[Dict[str, Any]]:
        """Sample active established network connections."""
        now_iso = datetime.now(timezone.utc).isoformat()
        new_samples = []

        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    dst_ip = conn.raddr.ip
                    dst_port = conn.raddr.port
                    src_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    src_port = conn.laddr.port if conn.laddr else 0

                    # Filter out local loopback connections
                    if dst_ip.startswith("127.") or dst_ip in ("::1", "0.0.0.0"):
                        continue

                    conn_key = (src_ip, src_port, dst_ip, dst_port)
                    item = {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "status": "ESTABLISHED",
                        "timestamp": now_iso
                    }

                    # Add new connections to history
                    with self.lock:
                        self.history.append(item)
                    new_samples.append(item)
        except Exception:
            pass

        return new_samples

    def get_connection_history(self) -> List[Dict[str, Any]]:
        """Return snapshot of recent connection timeline."""
        with self.lock:
            return list(self.history)


global_connection_tracker = ConnectionTracker()
