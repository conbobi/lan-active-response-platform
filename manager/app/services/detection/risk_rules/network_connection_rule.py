import ipaddress
import logging
from typing import Any, Dict, Tuple

from app.services.detection.network_shell import connection_key
from app.services.detection.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)


class NetworkConnectionRule(RiskRule):
    rule_id = "network_connection"
    name = "Suspicious Network Connection"
    description = "Scores uncommon destinations and threat intelligence matches."
    category = "network"

    DEFAULT_SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6667, 23, 8080, 445, 9001, 8443}

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        ports = set(self.config.get("suspicious_ports", self.DEFAULT_SUSPICIOUS_PORTS))
        shell_connections = context.get("shell_connections", set())
        threat_intel = context.get("threat_intel_service")
        unusual = set()
        malicious = set()
        queried = set()

        for conn in telemetry.get("network_connections", []):
            if not isinstance(conn, dict):
                continue
            try:
                remote = ipaddress.ip_address(conn.get("dst_ip"))
            except ValueError:
                continue
            remote = getattr(remote, "ipv4_mapped", None) or remote
            if remote.is_loopback or remote.is_unspecified or remote.is_multicast:
                continue
            if type(conn.get("dst_port")) is not int or not 0 < conn["dst_port"] <= 65535:
                continue
            if conn["dst_port"] in ports and conn.get("direction") != "inbound":
                key = connection_key(conn)
                if key not in shell_connections:
                    unusual.add((str(remote), conn["dst_port"]))

            # Shared, local and private addresses have no public threat-feed attribution.
            if threat_intel and remote.is_global and remote not in queried:
                queried.add(remote)
                try:
                    result = await threat_intel.check_ip(str(remote))
                    if result and result.get("is_malicious"):
                        malicious.add(remote)
                except Exception as error:
                    logger.debug("IP reputation unavailable: %s", error)

        reasons = []
        port_score = min(10.0, len(unusual) * 6.0)
        if unusual:
            reasons.append(f"Suspicious network connection: {len(unusual)} uncommon remote endpoint(s)")
        if malicious:
            reasons.append(f"Threat intelligence matched {len(malicious)} remote IP(s)")
        intel_points = 30.0 if malicious else 0.0
        context["network_threat_intel_points"] = intel_points
        score = (port_score + intel_points) * self.base_score
        return score, "; ".join(reasons)
