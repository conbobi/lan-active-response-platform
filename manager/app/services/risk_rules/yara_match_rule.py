from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class YaraMatchRule(RiskRule):
    """
    Risk rule detecting signature matches from YARA malware scanning.
    Immediate high/critical risk score when malicious binaries or scripts are identified.
    """
    rule_id = "yara_match"
    name = "YARA Signature Match"
    description = "Detects files matching known malware, ransomware, or webshell YARA signatures."
    enabled = True
    weight = 1.0
    base_score = 90.0
    category = "malware"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        # 1. Check yara_matches in root telemetry
        matches: List[str] = telemetry.get("yara_matches", [])

        # 2. Check FIM alerts or process list with yara match info
        if not matches:
            fim_events = telemetry.get("fim_events", [])
            for evt in fim_events:
                if isinstance(evt, dict) and evt.get("yara_match"):
                    matches.append(f"{evt.get('file_path')}: {evt.get('yara_match')}")

        if not matches:
            details = telemetry.get("details", {})
            if isinstance(details, dict) and details.get("matched_rules"):
                matches.extend(details.get("matched_rules", []))

        if matches:
            match_str = ", ".join(str(m) for m in matches[:5])
            score = min(100.0, self.base_score + min(10.0, (len(matches) - 1) * 5.0))
            return score, f"YARA signature match detected: {match_str}"

        return 0.0, ""
