from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class ShadowCopyRule(RiskRule):
    rule_id = "shadow_copy"
    name = "Shadow Copy Deletion (Ransomware Precursor)"
    description = "Detects attempts to delete Volume Shadow Copies or disable backup catalog recovery."
    enabled = True
    weight = 1.0

    SHADOW_PATTERNS = [
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "wbadmin delete catalog"
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        shadow_flag = telemetry.get("shadow_copy_deletion", False)
        commands = telemetry.get("suspicious_commands", [])
        processes = telemetry.get("process_list", [])

        detected: List[str] = []

        if shadow_flag:
            detected.append("shadow_copy_deletion flag set to True")

        for cmd in commands:
            cmd_lower = cmd.lower()
            if any(pat in cmd_lower for pat in self.SHADOW_PATTERNS):
                detected.append(f"Command: '{cmd}'")

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            cmdline = str(p_dict.get("cmdline", "")).lower()
            if any(pat in cmdline for pat in self.SHADOW_PATTERNS):
                detected.append(f"Process cmdline: '{p_dict.get('cmdline')}'")

        if detected:
            return 50.0, f"Volume Shadow Copy deletion detected: {', '.join(detected)}"

        return 0.0, ""
