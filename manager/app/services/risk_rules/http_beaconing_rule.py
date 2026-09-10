import asyncio
from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule
from app.services.beaconing_detection_service import BeaconingDetectionService


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
