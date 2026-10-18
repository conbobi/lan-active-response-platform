import re
from typing import Any, Dict, Tuple, List
from app.services.detection.risk_rules.base import RiskRule


class LivingOffLandRule(RiskRule):
    rule_id = "living_off_land"
    name = "Living-off-the-Land (LOLBins) Abuse"
    description = "Detects abuse of legitimate system administrative tools for malicious execution."
    enabled = True
    weight = 1.0
    category = "behavior"
    base_score = 45.0

    LOLBINS = {
        "msbuild.exe", "msbuild", "certutil.exe", "certutil",
        "rundll32.exe", "regsvr32.exe", "mshta.exe",
        "wmic.exe", "bitsadmin.exe", "schtasks.exe",
        "cscript.exe", "wscript.exe",
        "powershell.exe", "powershell", "pwsh.exe",
    }

    # Parent context — quan trọng nhất
    PARENT_SCORES = {
        # Legit dev tools → GIẢM điểm (không flag dev thật)
        "devenv.exe": -25,
        "msbuild.exe": -15,
        "code.exe": -20,

        # User-initiated → trung bình
        "explorer.exe": 0,
        "cmd.exe": 10,
        "powershell.exe": 15,

        # HIGH SUSPICIOUS — parent không bao giờ nên spawn LOLBin
        "electron.exe": 50,
        "winword.exe": 50,
        "excel.exe": 50,
        "powerpnt.exe": 50,
        "outlook.exe": 50,
        "chrome.exe": 40,
        "firefox.exe": 40,
    }

    CMDLINE_PATTERNS = [
        (r"\.csproj", 30),
        (r"/t:Run", 40),
        (r"-urlcache", 40),
        (r"-decodehex", 40),
        (r"-encodedcommand", 40),
        (r"-enc\b", 40),
        (r"-windowstyle hidden", 30),
        (r"\\users\\public\\", 30),
        (r"\\appdata\\local\\temp\\", 30),
        (r"\\windows\\temp\\", 30),
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        commands = telemetry.get("suspicious_commands", [])

        # Build pid_map
        pid_map: Dict[Any, Dict[str, Any]] = {}
        for p in processes:
            p_dict = p if isinstance(p, dict) else p.model_dump() if hasattr(p, "model_dump") else getattr(p, "__dict__", {})
            if p_dict.get("pid") is not None:
                pid_map[p_dict.get("pid")] = p_dict

        total_score = 0
        all_reasons: List[str] = []

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name") or "").lower()
            name_base = name.replace("\\", "/").split("/")[-1]
            if name not in self.LOLBINS and name_base not in self.LOLBINS:
                continue
            matched_bin = name if name in self.LOLBINS else name_base

            cmdline_raw = p_dict.get("cmdline") or ""
            if isinstance(cmdline_raw, list):
                cmdline = " ".join(str(x) for x in cmdline_raw).lower()
            else:
                cmdline = str(cmdline_raw).lower()

            proc_score = 0
            proc_reasons: List[str] = []

            # Signal 1: Parent context
            parent_pid = p_dict.get("ppid") or p_dict.get("parent_pid")
            parent = pid_map.get(parent_pid)
            if parent:
                parent_name = str(parent.get("name") or "").lower()
                parent_base = parent_name.replace("\\", "/").split("/")[-1]
                parent_score = self.PARENT_SCORES.get(parent_base, self.PARENT_SCORES.get(parent_name, 0))
                proc_score += parent_score
                if parent_score != 0:
                    proc_reasons.append(f"parent={parent_base} ({parent_score:+d})")

            # Signal 2: Cmdline patterns
            for pattern, score in self.CMDLINE_PATTERNS:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    proc_score += score
                    proc_reasons.append(f"pattern={pattern} (+{score})")

            # Signal 3: Child process suspicious
            my_pid = p_dict.get("pid")
            if my_pid is not None:
                children = [
                    p for p in processes
                    if (isinstance(p, dict) and (p.get("ppid") == my_pid or p.get("parent_pid") == my_pid))
                ]
                suspicious_children = [
                    c for c in children
                    if str(c.get("name") or "").lower().replace("\\", "/").split("/")[-1] in ["powershell.exe", "powershell", "cmd.exe", "cmd", "cscript.exe", "wscript.exe"]
                ]
                if suspicious_children:
                    proc_score += 40
                    proc_reasons.append("spawns shell (+40)")

            if proc_score > 0:
                total_score += proc_score
                all_reasons.extend(proc_reasons)

        # Check explicit suspicious commands list
        for cmd in commands:
            cmd_str = str(cmd)
            cmd_lower = cmd_str.lower()
            if any(b in cmd_lower for b in self.LOLBINS):
                for pattern, score in self.CMDLINE_PATTERNS:
                    if re.search(pattern, cmd_str, re.IGNORECASE):
                        total_score += score
                        all_reasons.append(f"command pattern={pattern} (+{score})")

        if total_score > 0:
            final_score = min(100.0, max(0.0, float(total_score)))
            return final_score, f"LOLBin execution detected: {'; '.join(all_reasons)}"

        return 0.0, ""
