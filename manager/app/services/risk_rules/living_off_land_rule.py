from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class LivingOffLandRule(RiskRule):
    rule_id = "living_off_land"
    name = "Living-off-the-Land (LOLBins) Abuse"
    description = "Detects abuse of legitimate system administrative tools for malicious execution."
    enabled = True
    weight = 1.0
    category = "behavior"

    LOLBIN_BINARIES = [
        "curl.exe", "curl", "wget.exe", "wget",
        "powershell.exe", "powershell", "pwsh.exe", "wmic.exe", "wmic",
        "certutil.exe", "certutil", "bitsadmin.exe", "bitsadmin",
        "mshta.exe", "mshta", "regsvr32.exe", "regsvr32", "rundll32.exe", "rundll32",
        "cscript.exe", "wscript.exe", "schtasks.exe", "schtasks"
    ]

    SUSPICIOUS_PATTERNS = [
        "-enc", "-encodedcommand", "downloadstring", "downloadfile", "iex",
        "/urlcache", "-urlcache", "/transfer", "-split", "-o", "-O",
        "process call create", "javascript:", "vbscript:", "/s /u /i:",
        "http://", "https://", "invoke-webrequest", "invoke-restmethod"
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        commands = telemetry.get("suspicious_commands", [])

        lol_matches: List[str] = []

        # Check processes & command line arguments
        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name", "")).strip().lower()
            cmdline = str(p_dict.get("cmdline", "")).strip().lower()

            is_lolbin = any(
                name == bin_name or name.endswith("/" + bin_name) or name.endswith("\\" + bin_name) or (bin_name in name)
                for bin_name in self.LOLBIN_BINARIES
            )

            if is_lolbin:
                if any(pat in cmdline for pat in self.SUSPICIOUS_PATTERNS):
                    lol_matches.append(f"'{p_dict.get('name')}' with suspicious cmdline: {p_dict.get('cmdline')}")
                elif p_dict.get("is_suspicious"):
                    lol_matches.append(f"'{p_dict.get('name')}' execution flagged suspicious")

        # Check explicit suspicious commands list
        for cmd in commands:
            cmd_lower = cmd.lower()
            if any(bin_name in cmd_lower for bin_name in self.LOLBIN_BINARIES):
                if any(pat in cmd_lower for pat in self.SUSPICIOUS_PATTERNS) or "curl" in cmd_lower or "wget" in cmd_lower or "certutil" in cmd_lower:
                    match_str = f"LOLBin command: {cmd}"
                    if match_str not in lol_matches:
                        lol_matches.append(match_str)

        if lol_matches:
            score = min(45.0, len(lol_matches) * 12.5) * self.base_score
            return score, f"LOLBin execution detected: {', '.join(lol_matches)}"

        return 0.0, ""
