from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class C2CommunicationRule(RiskRule):
    rule_id = "c2_communication"
    name = "C2 Communication Anomaly"
    description = "Detects connections to potential Command & Control servers or dynamic DNS infrastructure."
    enabled = True
    weight = 1.0
    category = "network"

    DEFAULT_SUSPICIOUS_DOMAINS = [
        ".duckdns.org", ".ngrok.io", ".onion", ".bazar", ".bip.sh", ".serveo.net", ".trycloudflare.com"
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        dns_queries = telemetry.get("dns_queries", [])
        connections = telemetry.get("network_connections", [])

        c2_indicators: List[str] = []
        susp_domains = self.config.get("suspicious_domains", self.DEFAULT_SUSPICIOUS_DOMAINS)

        # Check DNS queries
        for query in dns_queries:
            q_str = ""
            if isinstance(query, str):
                q_str = query
            elif isinstance(query, dict):
                q_str = query.get("query", "")
            elif hasattr(query, "query"):
                q_str = getattr(query, "query", "")

            q_lower = q_str.lower()
            if any(dom in q_lower for dom in susp_domains):
                c2_indicators.append(f"Suspicious DNS query: '{q_str}'")

        # Check network connections to uncommon C2 ports
        c2_ports = set(self.config.get("c2_ports", [4444, 8443, 9001, 31337, 6667]))
        for conn in connections:
            c_dict = conn if isinstance(conn, dict) else conn.model_dump() if hasattr(conn, "model_dump") else getattr(conn, "__dict__", {})
            dst_port = c_dict.get("dst_port", 0)
            dst_ip = c_dict.get("dst_ip", "")

            if dst_port in c2_ports:
                c2_indicators.append(f"Direct connection to C2 port {dst_port} (IP: {dst_ip})")

        if c2_indicators:
            score = min(45.0, len(c2_indicators) * 35.0) * self.base_score
            return score, f"C2 communication indicator detected: {', '.join(c2_indicators)}"

        return 0.0, ""
