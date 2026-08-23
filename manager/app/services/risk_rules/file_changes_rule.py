from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule


class FileChangesRule(RiskRule):
    rule_id = "file_changes"
    name = "File Modification Volume Anomaly"
    description = "Detects unusually high volumes of file modification events."
    enabled = True
    weight = 1.0

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        file_changes = telemetry.get("file_changes_count", 0)
        high_threshold = self.config.get("high_threshold", 100)
        high_score = self.config.get("high_score", 25.0)
        medium_threshold = self.config.get("medium_threshold", 30)
        medium_score = self.config.get("medium_score", 10.0)

        if file_changes > high_threshold:
            return high_score, f"Massive file modifications count ({file_changes})"
        elif file_changes > medium_threshold:
            return medium_score, f"Elevated file modifications count ({file_changes})"

        return 0.0, ""
