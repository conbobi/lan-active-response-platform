import os
import math
import socket
import logging
import asyncio
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, List, Set, Optional
from app.services.detection.risk_rules.base import RiskRule
from app.services.detection.network_reputation_service import NetworkReputationService

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

    # Automatically exclude EDR Manager domain addresses
    known_manager_domains = [
        "edr.alwayready.id.vn",
        os.getenv("MANAGER_DOMAIN", ""),
        os.getenv("MANAGER_HOST", "")
    ]
    for dom in known_manager_domains:
        dom = dom.strip()
        if dom:
            try:
                resolved_ips = socket.gethostbyname_ex(dom)[2]
                for ip in resolved_ips:
                    ignored.add(ip)
            except Exception:
                pass

    return ignored


class BeaconingDetectionService:
    """
    Detects C2 (Command and Control) HTTP/TCP Beaconing patterns using time-series interval analysis.
    Calculates Coefficient of Variation (CV = sigma / mu) of connection intervals.
    Low CV (< 0.25) indicates fixed heartbeat/jitter intervals characteristic of C2 malware.

    CRITICAL FIX (Section 4.B & 4.C):
    - Evaluates GENUINE connection-open / reconnect events, NOT repeated polling observations of the same socket.
    - Sockets observed multiple times (observation_count > 1, new_connection_count = 1) count as 1 connection.
    - Rejects LISTEN sockets and loopback/wildcard sockets.
    """

    @staticmethod
    def calculate_intervals(timestamps: List[datetime]) -> List[float]:
        """Convert sorted timestamps of distinct connection events into delta seconds intervals."""
        if len(timestamps) < 2:
            return []
        sorted_ts = sorted(timestamps)
        intervals = []
        for i in range(1, len(sorted_ts)):
            delta = (sorted_ts[i] - sorted_ts[i - 1]).total_seconds()
            if delta > 0.05:  # Skip nearly simultaneous connections
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

        # CV <= 0.25 indicates highly regular beaconing (< 25% jitter)
        # Requires at least 4 intervals (5 distinct connection events)
        is_beaconing = (cv <= 0.25 and n >= 4) or (cv <= 0.35 and n >= 8)

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
        min_connections: int = 5,
        cv_threshold: float = 0.25
    ) -> List[Dict[str, Any]]:
        """
        Groups connection history by destination and process instance,
        deduplicating repeated observations of the same active socket.
        """
        # Key: (dst_ip, dst_port) -> Dict[socket_identity, datetime]
        groups: Dict[str, Dict[Any, datetime]] = {}
        process_map: Dict[str, Dict[str, Any]] = {}
        ignored_ips = _get_ignored_ips()

        for conn in connection_history:
            # 1. Reject LISTEN sockets or sockets without destination
            if conn.get("status") == "LISTEN":
                continue

            dst_ip = conn.get("dst_ip")
            if not dst_ip or dst_ip in ignored_ips:
                continue

            # 2. Exclude loopback and wildcard
            if dst_ip.startswith("127.") or dst_ip in ("::1", "0.0.0.0", "localhost"):
                continue

            dst_port = int(conn.get("dst_port") or 80)

            # 3. Ignore Manager traffic in internal Docker subnet
            if dst_port in (8000, 8005):
                try:
                    if ipaddress.ip_address(dst_ip) in DOCKER_SUBNET:
                        continue
                except ValueError:
                    pass

            # Parse establishment timestamp
            ts_raw = conn.get("first_seen") or conn.get("timestamp")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except Exception:
                    continue
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                continue

            key = f"{dst_ip}:{dst_port}"
            groups.setdefault(key, {})

            # Socket identity tuple
            src_ip = conn.get("src_ip", "0.0.0.0")
            src_port = conn.get("src_port")
            pid = conn.get("pid")
            if src_port:
                sock_id = (src_ip, src_port, dst_ip, dst_port, pid)
            else:
                sock_id = (dst_ip, dst_port, ts.isoformat())

            # If this exact socket was already recorded, preserve its earliest establishment timestamp!
            # Do NOT treat repeated observations as new connections!
            if sock_id not in groups[key]:
                groups[key][sock_id] = ts

            # Keep process metadata
            if key not in process_map or (pid and not process_map[key].get("pid")):
                process_map[key] = {
                    "pid": pid,
                    "process_name": conn.get("process_name") or conn.get("process") or "unknown",
                    "exe_path": conn.get("exe_path", ""),
                    "process_start_time": conn.get("process_start_time")
                }

        candidates = []
        for key, socket_dict in groups.items():
            distinct_timestamps = list(socket_dict.values())
            # Must have at least min_connections independent connection establishment events!
            if len(distinct_timestamps) < min_connections:
                continue

            intervals = cls.calculate_intervals(distinct_timestamps)
            stats = cls.analyze_intervals(intervals)

            if stats["is_beaconing"] and stats["cv"] <= cv_threshold:
                dst_ip, port_str = key.split(":")
                proc_info = process_map.get(key, {})
                rep = NetworkReputationService.get_reputation(dst_ip)
                candidates.append({
                    "dst_ip": dst_ip,
                    "dst_port": int(port_str),
                    "pid": proc_info.get("pid"),
                    "process_name": proc_info.get("process_name", "unknown"),
                    "exe_path": proc_info.get("exe_path", ""),
                    "total_connections": len(distinct_timestamps),
                    "mean_interval_sec": stats["mean_interval_sec"],
                    "std_dev_sec": stats["std_dev_sec"],
                    "cv": stats["cv"],
                    "rhythm_score": stats["rhythm_score"],
                    "is_beaconing": True,
                    "asn": rep.get("asn", "UNKNOWN"),
                    "org": rep.get("org", "Unknown Operator"),
                    "category": rep.get("category", "public_internet")
                })

        return candidates


class HttpBeaconingRule(RiskRule):
    """
    Risk rule detecting C2 communication via regular HTTP/HTTPS/TCP Beaconing rhythms.
    Correlates regular intervals (low CV) with Threat Intelligence and Process Reputation.
    Strictly avoids flagging normal long-lived persistent connections or legitimate cloud services.
    """
    rule_id = "http_beaconing"
    name = "HTTP/TCP Beaconing Detection"
    description = "Detects persistent periodic outbound connections characteristic of Command & Control beacons."
    enabled = True
    weight = 1.0
    base_score = 50.0
    category = "network"

    DEFAULT_CONFIG = {
        "min_connections": 5,
        "cv_threshold": 0.25
    }

    def detect_beaconing(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Direct helper to evaluate connections against beaconing criteria."""
        min_conns = int(self.config.get("min_connections", 5))
        cv_th = float(self.config.get("cv_threshold", 0.25))
        return BeaconingDetectionService.evaluate_connections(connections, min_conns, cv_th)

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        connection_history: List[Dict[str, Any]] = telemetry.get("connection_history", [])

        # Fallback: check network_connections if timestamps included
        if not connection_history:
            raw_conns = telemetry.get("network_connections", [])
            connection_history = [c for c in raw_conns if c.get("timestamp") or c.get("first_seen")]

        if not connection_history:
            return 0.0, ""

        min_conns = int(self.config.get("min_connections", 5))
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

        threat_intel = context.get("threat_intel_service")
        valid_candidates = []

        for c in candidates:
            c_ip = c["dst_ip"]
            c_port = c["dst_port"]
            p_name = c["process_name"]

            # Threat Intel check
            is_malicious = False
            if threat_intel:
                try:
                    ti_res = await threat_intel.check_ip(c_ip)
                    if ti_res.get("is_malicious"):
                        is_malicious = True
                except Exception:
                    pass

            c["is_known_c2"] = is_malicious

            # Contextual Behavioral Evaluation:
            # Does this traffic represent expected benign service operation (e.g. AnyDesk relay, Copilot/VS Code)?
            is_expected, reason = NetworkReputationService.evaluate_behavioral_context(
                process_name=p_name,
                dst_ip=c_ip,
                dst_port=c_port,
                threat_intel_malicious=is_malicious
            )

            if is_expected and not is_malicious:
                logger.info(
                    f"http_beaconing: Contextually suppressed expected vendor communication: "
                    f"'{p_name}' -> {c_ip}:{c_port} ({reason})"
                )
                continue

            valid_candidates.append(c)

        if not valid_candidates:
            return 0.0, ""

        top_candidate = max(valid_candidates, key=lambda c: c["rhythm_score"])
        dst_ip = top_candidate["dst_ip"]
        dst_port = top_candidate["dst_port"]
        interval = top_candidate["mean_interval_sec"]
        cv = top_candidate["cv"]
        total = top_candidate["total_connections"]
        proc_name = top_candidate["process_name"]
        pid = top_candidate["pid"]
        asn = top_candidate.get("asn", "")
        org = top_candidate.get("org", "")
        is_known_c2 = top_candidate.get("is_known_c2", False)

        proc_tag = f"from '{proc_name}' (PID {pid})" if pid else f"from '{proc_name}'"
        net_tag = f"[{asn} {org}]" if asn and asn != "UNKNOWN" else ""

        if is_known_c2:
            return 90.0 * self.weight, (
                f"CRITICAL: C2 Beaconing {proc_tag} to known malicious host {dst_ip}:{dst_port} {net_tag} "
                f"({total} connections, interval={interval}s, CV={cv})"
            )

        return min(100.0, self.base_score * self.weight), (
            f"Periodic outbound beaconing detected {proc_tag} to {dst_ip}:{dst_port} {net_tag} "
            f"({total} independent connections, mean interval={interval}s, CV={cv})"
        )
