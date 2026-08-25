from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule


class CpuSpikeRule(RiskRule):
    rule_id = "cpu_spike"
    name = "CPU Spike Anomaly"
    description = "Detects abnormally high CPU utilization spikes."
    enabled = True
    weight = 1.0
    category = "os"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        cpu = telemetry.get("cpu_usage", 0.0)
        high_threshold = self.config.get("high_threshold", 85.0)
        high_score = self.config.get("high_score", 30.0) * self.base_score
        medium_threshold = self.config.get("medium_threshold", 70.0)
        medium_score = self.config.get("medium_score", 15.0) * self.base_score

        if cpu > high_threshold:
            return high_score, f"Critical CPU spike ({cpu}%)"
        elif cpu > medium_threshold:
            return medium_score, f"Elevated CPU usage ({cpu}%)"

        return 0.0, ""
