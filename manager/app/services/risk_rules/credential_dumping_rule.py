from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class CredentialDumpingRule(RiskRule):
    rule_id = "credential_dumping"
    name = "Credential Dumping Activity"
    description = "Detects access or extraction attempts targeting LSASS memory, SAM, or credential stores."
    enabled = True
    weight = 1.0
    category = "behavior"

    DUMP_PATTERNS = ["sekurlsa", "lsass", "procdump", "comsvcs", "sam", "security", "ntds.dit", "mimikatz"]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        cred_events = telemetry.get("credential_access_events", [])
        commands = telemetry.get("suspicious_commands", [])
        processes = telemetry.get("process_list", [])

        dumps: List[str] = []

        # 1. Check credential access events
        for ev in cred_events:
            e_dict = ev if isinstance(ev, dict) else ev.model_dump() if hasattr(ev, "model_dump") else getattr(ev, "__dict__", {})
            target = str(e_dict.get("target_object", "")).lower()
            if any(pat in target for pat in ["lsass", "sam", "security", "ntds"]):
                dumps.append(f"Target object: {e_dict.get('target_object')}")

        # 2. Check suspicious commands
        for cmd in commands:
            cmd_lower = cmd.lower()
            if any(pat in cmd_lower for pat in self.DUMP_PATTERNS):
                dumps.append(f"Credential dump command: {cmd}")

        # 3. Check process list cmdlines
        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            cmdline = str(p_dict.get("cmdline", "")).lower()
            if any(pat in cmdline for pat in ["comsvcs.dll", "sekurlsa", "procdump", "lsass.dmp"]):
                dumps.append(f"Process dump cmdline: {p_dict.get('cmdline')}")

        if dumps:
            score = min(50.0, len(dumps) * 45.0)
            return score, f"Credential dumping activity detected: {', '.join(dumps)}"

        return 0.0, ""
