import math
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple


class BeaconingDetectionService:
    """
    Detects C2 (Command and Control) HTTP/TCP Beaconing patterns using time-series interval analysis.
    Calculates Coefficient of Variation (CV = sigma / mu) of connection intervals.
    Low CV (< 0.20) indicates fixed heartbeat/jitter intervals characteristic of C2 malware.
    """

    @staticmethod
    def calculate_intervals(timestamps: List[datetime]) -> List[float]:
        """Convert sorted timestamps into delta seconds intervals."""
        if len(timestamps) < 2:
            return []
        sorted_ts = sorted(timestamps)
        intervals = []
        for i in range(1, len(sorted_ts)):
            delta = (sorted_ts[i] - sorted_ts[i - 1]).total_seconds()
            if delta > 0:  # Skip simultaneous connections in the same second
                intervals.append(delta)
        return intervals

    @classmethod
    def analyze_intervals(cls, intervals: List[float]) -> Dict[str, Any]:
        """
        Calculates mean, standard deviation, and Coefficient of Variation (CV).
        """
        if len(intervals) < 3:
            return {
                "count": len(intervals),
                "mean_interval": 0.0,
                "std_dev": 0.0,
                "cv": 1.0,
                "is_beaconing": False,
                "score": 0.0
            }

        n = len(intervals)
        mean_val = sum(intervals) / n
        variance = sum((x - mean_val) ** 2 for x in intervals) / n
        std_dev = math.sqrt(variance)

        cv = (std_dev / mean_val) if mean_val > 0 else 1.0
        cv = round(cv, 3)

        # CV < 0.20 indicates highly regular beaconing (< 20% jitter)
        # CV between 0.20 and 0.35 indicates beaconing with moderate jitter
        is_beaconing = (cv <= 0.25 and n >= 5) or (cv <= 0.35 and n >= 10)

        # Score ranges from 0 to 100 based on regular rhythm and sample count
        rhythm_score = max(0.0, min(100.0, (1.0 - cv) * 100.0))

        return {
            "count": n,
            "mean_interval_sec": round(mean_val, 2),
            "std_dev_sec": round(std_dev, 2),
            "cv": cv,
            "rhythm_score": round(rhythm_score, 1),
            "is_beaconing": is_beaconing
        }

    @classmethod
    def evaluate_connections(
        cls,
        connection_history: List[Dict[str, Any]],
        min_connections: int = 8,
        cv_threshold: float = 0.25
    ) -> List[Dict[str, Any]]:
        """
        Groups connection history by (dst_ip, dst_port) and identifies beaconing candidates.
        """
        groups: Dict[str, List[datetime]] = {}

        for conn in connection_history:
            dst_ip = conn.get("dst_ip")
            if not dst_ip or dst_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
                continue

            # Exclude local subnet default gateway if needed
            if dst_ip.startswith("127.") or dst_ip == "192.168.10.1":
                continue

            dst_port = conn.get("dst_port", 80)
            key = f"{dst_ip}:{dst_port}"

            ts_raw = conn.get("timestamp")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except Exception:
                    continue
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                continue

            groups.setdefault(key, []).append(ts)

        candidates = []
        for key, ts_list in groups.items():
            if len(ts_list) < min_connections:
                continue

            intervals = cls.calculate_intervals(ts_list)
            stats = cls.analyze_intervals(intervals)

            if stats["cv"] <= cv_threshold and stats["count"] >= (min_connections - 1):
                dst_ip, port_str = key.split(":")
                candidates.append({
                    "dst_ip": dst_ip,
                    "dst_port": int(port_str),
                    "total_connections": len(ts_list),
                    "mean_interval_sec": stats["mean_interval_sec"],
                    "std_dev_sec": stats["std_dev_sec"],
                    "cv": stats["cv"],
                    "rhythm_score": stats["rhythm_score"],
                    "is_beaconing": True
                })

        return candidates
