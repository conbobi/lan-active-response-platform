from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class RegistryRule(RiskRule):
    rule_id = "registry"
    name = "Suspicious Registry Modification"
    description = "Detects registry keys modification targeting system persistence and startup locations."
    enabled = True
    weight = 1.0

    DEFAULT_PERSISTENCE_KEYS = [
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\winlogon",
        "\\image file execution options",
        "\\system\\currentcontrolset\\services",
        "\\microsoft\\windows\\currentversion\\explorer\\user shell folders"
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        registry_changes = telemetry.get("registry_changes", [])
        if not registry_changes:
            return 0.0, ""

        persistence_keys = self.config.get("persistence_keys", self.DEFAULT_PERSISTENCE_KEYS)
        suspicious_changes: List[str] = []

        for change in registry_changes:
            c_dict = change if isinstance(change, dict) else change.model_dump() if hasattr(change, "model_dump") else getattr(change, "__dict__", {})
            key_path = str(c_dict.get("key_path", "")).lower()

            if any(p_key in key_path for p_key in persistence_keys):
                val_name = c_dict.get("value_name", "")
                suspicious_changes.append(f"Key: {c_dict.get('key_path')} (Value: {val_name})")

        if suspicious_changes:
            score = min(40.0, len(suspicious_changes) * 25.0)
            return score, f"Suspicious registry modification detected: {', '.join(suspicious_changes)}"

        return 0.0, ""
