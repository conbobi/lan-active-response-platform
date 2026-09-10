import math
import asyncio
from datetime import datetime
from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


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


class HttpBeaconingRule(RiskRule):
    """
    Risk rule detecting C2 communication via regular HTTP/HTTPS/TCP Beaconing rhythms.
    Correlates regular intervals (low CV) with Threat Intelligence reputation.
    """
    rule_id = "http_beaconing"
    name = "HTTP/TCP Beaconing Detection"
    description = "Detects persistent periodic outbound connections characteristic of Command & Control beacons."
    enabled = True
    weight = 1.0
    base_score = 50.0
    category = "network"

    DEFAULT_CONFIG = {
        "min_connections": 8,
        "cv_threshold": 0.25
    }

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        connection_history: List[Dict[str, Any]] = telemetry.get("connection_history", [])

        # Fallback: check network_connections if timestamps included
        if not connection_history:
            raw_conns = telemetry.get("network_connections", [])
            connection_history = [c for c in raw_conns if c.get("timestamp")]

        if not connection_history:
            return 0.0, ""

        min_conns = int(self.config.get("min_connections", 8))
        cv_th = float(self.config.get("cv_threshold", 0.25))

        # Run non-blocking analysis
        candidates = await asyncio.to_thread(
            BeaconingDetectionService.evaluate_connections,
            connection_history,
            min_conns,
            cv_th
        )

        if not candidates:
            return 0.0, ""

        top_candidate = max(candidates, key=lambda c: c["rhythm_score"])
        dst_ip = top_candidate["dst_ip"]
        interval = top_candidate["mean_interval_sec"]
        cv = top_candidate["cv"]
        total = top_candidate["total_connections"]

        score = self.base_score

        # Correlate with Threat Intelligence Service if present in context
        threat_intel = context.get("threat_intel_service")
        is_known_c2 = False
        if threat_intel:
            try:
                ti_result = await threat_intel.check_ip(dst_ip)
                if ti_result.get("is_malicious"):
                    is_known_c2 = True
                    score = 90.0  # Elevate directly to Critical
            except Exception:
                pass

        if is_known_c2:
            return min(100.0, score * self.weight), (
                f"CRITICAL: C2 Beaconing to known malicious host {dst_ip} "
                f"({total} connections, interval={interval}s, CV={cv})"
            )

        return min(100.0, score * self.weight), (
            f"Periodic outbound beaconing detected to {dst_ip} "
            f"({total} connections, mean interval={interval}s, CV={cv})"
        )
