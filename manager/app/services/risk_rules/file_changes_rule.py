from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule


class FileChangesRule(RiskRule):
    rule_id = "file_changes"
    name = "File Modification Volume Anomaly"
    description = "Detects unusually high volumes of file modification events."
    enabled = True
    weight = 1.0
    category = "os"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        file_changes = telemetry.get("file_changes_count", 0)

        critical_threshold = self.config.get("critical_threshold", self.config.get("high_threshold", 100))
        elevated_threshold = self.config.get("elevated_threshold", self.config.get("medium_threshold", 30))

        setting_service = context.get("setting_service")
        if setting_service:
            try:
                thresholds = await setting_service.get_file_changes_thresholds()
                critical_threshold = thresholds.get("file_changes_critical", critical_threshold)
                elevated_threshold = thresholds.get("file_changes_elevated", elevated_threshold)
            except Exception:
                pass

        high_score = self.config.get("high_score", 25.0) * self.base_score
        medium_score = self.config.get("medium_score", 10.0) * self.base_score

        if file_changes >= critical_threshold and critical_threshold > 0:
            return high_score, f"Massive file modifications count ({file_changes})"
        elif file_changes >= elevated_threshold and elevated_threshold > 0:
            return medium_score, f"Elevated file modifications count ({file_changes})"

        return 0.0, ""
