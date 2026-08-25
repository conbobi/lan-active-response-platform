from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule


class NetworkConnectionRule(RiskRule):
    rule_id = "network_connection"
    name = "Suspicious Network Connection & Threat Intel IP"
    description = "Detects connections to suspicious ports and Threat Intelligence blacklisted IPs."
    enabled = True
    weight = 1.0
    category = "network"

    DEFAULT_SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6667, 23, 8080, 445}

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        connections = telemetry.get("network_connections", [])
        if not connections:
            return 0.0, ""

        suspicious_ports = set(self.config.get("suspicious_ports", self.DEFAULT_SUSPICIOUS_PORTS))
        suspicious_conns = 0
        threat_ip_count = 0

        threat_intel_service = context.get("threat_intel_service")

        for conn in connections:
            c_dict = conn if isinstance(conn, dict) else conn.model_dump() if hasattr(conn, "model_dump") else getattr(conn, "__dict__", {})
            dst_port = c_dict.get("dst_port", 0)
            src_port = c_dict.get("src_port", 0)
            dst_ip = c_dict.get("dst_ip")
            is_susp = c_dict.get("is_suspicious", False)

            if is_susp or dst_port in suspicious_ports or src_port in suspicious_ports:
                suspicious_conns += 1

            if dst_ip and threat_intel_service:
                try:
                    ip_intel = await threat_intel_service.check_ip(dst_ip)
                    if ip_intel and ip_intel.get("is_malicious"):
                        threat_ip_count += 1
                except Exception:
                    pass

        score = 0.0
        reasons = []

        if suspicious_conns > 0:
            score += min(35.0, suspicious_conns * 20.0)
            reasons.append(f"Detected {suspicious_conns} connections to suspicious ports")

        if threat_ip_count > 0:
            score += 30.0
            reasons.append(f"Detected {threat_ip_count} connections to malicious IPs")

        if score > 0:
            return score * self.base_score, "; ".join(reasons)

        return 0.0, ""
