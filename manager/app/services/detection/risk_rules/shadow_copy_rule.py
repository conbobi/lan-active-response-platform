import re
import logging
from typing import Any, Dict, Tuple, List
from app.services.detection.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)


class ShadowCopyRule(RiskRule):
    rule_id = "shadow_copy"
    name = "Shadow Copy Deletion (Ransomware Precursor)"
    description = "Detects attempts to delete Volume Shadow Copies or disable backup catalog recovery."
    enabled = True
    weight = 1.0
    category = "behavior"

    SHADOW_DELETE_PATTERNS = [
        r"vssadmin.*delete.*shadows",
        r"wmic.*shadowcopy.*delete",
        r"Get-WmiObject.*Win32_ShadowCopy.*Delete",
        r"bcdedit.*recoveryenabled.*no",
        r"wbadmin.*delete.*catalog",
        r"bcdedit.*bootstatuspolicy.*ignoreallfailures",
    ]

    SHADOW_PATTERNS = [
        "vssadmin delete shadows",
        "vssadmin",
        "wmic shadowcopy delete",
        "wmic shadowcopy",
        "bcdedit /set {default} recoveryenabled no",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "bcdedit",
        "wbadmin delete catalog",
        "wbadmin",
        "shadow_deletion",
        "delete shadows"
    ]

    def _matches_any(self, text: str) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        if any(pat in text_lower for pat in self.SHADOW_PATTERNS):
            return True
        for regex in self.SHADOW_DELETE_PATTERNS:
            if re.search(regex, text, re.IGNORECASE):
                return True
        return False

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        shadow_flag = telemetry.get("shadow_copy_deletion", False)
        indicators = telemetry.get("shadow_copy_indicators", [])
        commands = telemetry.get("suspicious_commands", [])
        processes = telemetry.get("process_list", [])

        detected: List[str] = []

        if shadow_flag:
            ind_str = f" (indicators: {', '.join(indicators)})" if indicators else ""
            detected.append(f"shadow_copy_deletion flag is True{ind_str}")

        for cmd in commands:
            cmd_str = str(cmd)
            if self._matches_any(cmd_str):
                match_msg = f"Command: '{cmd_str}'"
                if match_msg not in detected:
                    detected.append(match_msg)

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name", ""))
            cmdline = str(p_dict.get("cmdline", ""))
            full_str = f"{name} {cmdline}"
            if self._matches_any(full_str):
                match_msg = f"Process: '{name}' cmdline: '{cmdline}'"
                if match_msg not in detected:
                    detected.append(match_msg)

        if detected:
            reason = f"Volume Shadow Copy deletion detected: {', '.join(detected)}"
            score = 50.0 * self.base_score
            logger.info(f"[EVALUATE] Rule shadow_copy triggered: score={score}, reason={reason}")
            return score, reason

        logger.debug("[EVALUATE] Rule shadow_copy: score=0.0")
        return 0.0, ""
