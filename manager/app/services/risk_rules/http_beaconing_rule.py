import os
import math
import socket
import logging
import asyncio
import ipaddress
from datetime import datetime
from typing import Any, Dict, Tuple, List, Set
from app.services.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)

DOCKER_SUBNET = ipaddress.ip_network("172.16.0.0/12")


def _get_ignored_ips() -> Set[str]:
    """Return set of IP addresses to ignore for beaconing detection."""
    ignored = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}

    manager_ip_env = os.getenv("MANAGER_IP")
    if manager_ip_env:
        ignored.add(manager_ip_env.strip())

    try:
        manager_dns_ip = socket.gethostbyname("manager")
        ignored.add(manager_dns_ip)
    except Exception:
        pass

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        ignored.add(host_ip)
    except Exception:
        pass

    return ignored


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
        ignored_ips = _get_ignored_ips()

        for conn in connection_history:
            dst_ip = conn.get("dst_ip")
            if not dst_ip or dst_ip in ignored_ips:
                logger.debug(f"[BEACONING] Ignored connection to ignored IP: {dst_ip}")
                continue

            # Exclude loopback
            if dst_ip.startswith("127."):
                logger.debug(f"[BEACONING] Ignored connection to loopback IP: {dst_ip}")
                continue

            dst_port = conn.get("dst_port", 80)

            # Ignore Manager traffic in internal Docker subnet (172.16.0.0/12 on port 8000/8002)
            if dst_port in (8000, 8002):
                try:
                    if ipaddress.ip_address(dst_ip) in DOCKER_SUBNET:
                        logger.debug(f"[BEACONING] Ignored connection to Docker Manager IP {dst_ip}:{dst_port}")
                        continue
                except ValueError:
                    pass

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

    def detect_beaconing(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Direct helper to evaluate connections against beaconing criteria."""
        min_conns = int(self.config.get("min_connections", 8))
        cv_th = float(self.config.get("cv_threshold", 0.25))
        return BeaconingDetectionService.evaluate_connections(connections, min_conns, cv_th)

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
