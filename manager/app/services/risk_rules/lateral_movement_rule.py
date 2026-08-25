from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class LateralMovementRule(RiskRule):
    rule_id = "lateral_movement"
    name = "Lateral Movement Activity"
    description = "Detects internal reconnaissance, port scanning, SMB/WMI session sweeps, or WinRM misuse."
    enabled = True
    weight = 1.0
    category = "network"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        lateral_events = telemetry.get("lateral_movement_events", [])
        connections = telemetry.get("network_connections", [])

        events_found: List[str] = []

        for ev in lateral_events:
            e_dict = ev if isinstance(ev, dict) else ev.model_dump() if hasattr(ev, "model_dump") else getattr(ev, "__dict__", {})
            e_type = e_dict.get("event_type", "unknown")
            t_ip = e_dict.get("target_ip", "")
            events_found.append(f"Type: {e_type} targeting {t_ip}")

        # Check internal connections count to administrative ports (445: SMB, 135: RPC/WMI, 5985/5986: WinRM, 3389: RDP)
        admin_ports = {445, 135, 5985, 5986, 3389}
        internal_targets = set()
        for conn in connections:
            c_dict = conn if isinstance(conn, dict) else conn.model_dump() if hasattr(conn, "model_dump") else getattr(conn, "__dict__", {})
            dst_port = c_dict.get("dst_port", 0)
            dst_ip = str(c_dict.get("dst_ip", ""))
            if dst_port in admin_ports:
                internal_targets.add(f"{dst_ip}:{dst_port}")

        if len(internal_targets) >= 1:
            events_found.append(f"Internal admin port connection sweep ({len(internal_targets)} target(s): {', '.join(internal_targets)})")

        commands = telemetry.get("suspicious_commands", [])
        for cmd in commands:
            cmd_lower = cmd.lower()
            if "nmap" in cmd_lower or "lateral" in cmd_lower:
                events_found.append(f"Lateral movement command: {cmd}")

        if events_found:
            score = min(45.0, len(events_found) * 35.0) * self.base_score
            return score, f"Lateral movement activity detected: {', '.join(events_found)}"

        return 0.0, ""
