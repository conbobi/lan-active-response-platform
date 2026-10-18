import re
from typing import Any, Dict, Tuple, List
from app.services.detection.risk_rules.base import RiskRule


class CredentialDumpingRule(RiskRule):
    rule_id = "credential_dumping"
    name = "Credential Dumping Activity"
    description = "Detects access or extraction attempts targeting LSASS memory, SAM, or credential stores."
    enabled = True
    weight = 1.0
    category = "behavior"
    base_score = 80.0

    # CHỈ match khi cmdline chứa pattern dump
    DUMP_PATTERNS = [
        (r"procdump.*(-ma|-mm).*lsass", 80.0),
        (r"comsvcs\.dll.*MiniDump", 80.0),
        (r"sekurlsa::logonpasswords", 90.0),
        (r"sekurlsa::wdigest", 90.0),
        (r"lsadump::sam", 90.0),
        (r"kerberos::golden", 90.0),
        (r"MiniDumpWriteDump", 60.0),
        (r"lsass\.exe.*(?:dump|procdump)", 70.0),
    ]

    # Whitelist process hợp pháp — KHÔNG trigger nếu cmdline rỗng hoặc bình thường
    LEGIT_PROCESSES = {
        "lsass.exe", "lsaiso.exe", "svchost.exe",
        "csrss.exe", "winlogon.exe", "services.exe",
        "MsMpEng.exe", "msmpeng.exe",
    }

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        commands = telemetry.get("suspicious_commands", [])

        # 1. Check suspicious commands list (for Mimikatz, etc.)
        for cmd in commands:
            cmd_str = str(cmd)
            for pattern, score in self.DUMP_PATTERNS:
                if re.search(pattern, cmd_str, re.IGNORECASE):
                    return score, f"Credential dumping activity detected: {pattern} in command '{cmd_str}'"

        # 2. Check process list cmdlines
        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name") or "").lower()
            cmdline_raw = p_dict.get("cmdline") or ""
            if isinstance(cmdline_raw, list):
                cmdline = " ".join(str(x) for x in cmdline_raw).lower()
            else:
                cmdline = str(cmdline_raw).lower()

            # Skip nếu cmdline rỗng (không có gì để match)
            if not cmdline or cmdline.strip() == "":
                continue

            # Skip process hợp pháp VÀ cmdline không chứa dump pattern
            if name in self.LEGIT_PROCESSES:
                has_dump_pattern = any(
                    re.search(p, cmdline, re.IGNORECASE)
                    for p, _ in self.DUMP_PATTERNS
                )
                if not has_dump_pattern:
                    continue

            # Match pattern
            for pattern, score in self.DUMP_PATTERNS:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    return score, f"Credential dumping activity detected: pattern {pattern} in {name}"

        return 0.0, ""
