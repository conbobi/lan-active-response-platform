from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule


class MassFileModificationRule(RiskRule):
    rule_id = "mass_file_modification"
    name = "Mass File Modification (Ransomware Indicator)"
    description = "Detects rapid mass file modifications or file extension mass renaming."
    enabled = True
    weight = 1.0
    category = "behavior"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        mass_flag = telemetry.get("mass_file_modification", False)
        file_changes = telemetry.get("file_changes_count", 0)

        threshold = self.config.get("file_change_threshold", 200)

        if mass_flag or file_changes > threshold:
            score = (40.0 if mass_flag else 25.0) * self.base_score
            return score, f"Mass file modification / Ransomware activity detected (flag={mass_flag}, count={file_changes})"

        return 0.0, ""
