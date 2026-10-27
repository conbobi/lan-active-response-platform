import os
import re
from typing import Any, Dict, Tuple, List
from app.services.detection.risk_rules.base import RiskRule


class SuspiciousProcessRule(RiskRule):
    rule_id = "suspicious_process"
    name = "Suspicious Process & Threat Intel Hash"
    description = "Detects known malicious binaries, suspicious flags, and Threat Intelligence hash matches."
    enabled = True
    weight = 1.0
    category = "os"
    base_score = 1.0

    SUSPICIOUS_PATTERNS = [
        # Tool tấn công cụ thể — match full word/pattern
        r"\bmimikatz\b",
        r"\bmeterpreter\b",
        r"\bcobaltstrike\b",
        r"\blazagne\b",
        r"\bprocdump(?:\.exe)?\b.*\blsass\b",
        r"\bcomsvcs\.dll\b.*MiniDump",
        r"\bsekurlsa::",
        r"\blsadump::",
        r"\bkerberos::golden",

        # Reverse shell patterns
        r"\bnc(?:\.exe)?\b.*-e\b",
        r"\bnc(?:\.exe)?\b.*-l",
        r"\bncat\b.*-e\b",
        r"\bpowershell\b.*-enc\b.*[A-Za-z0-9+/=]{50,}",
        r"\bpowershell\b.*-w(?:indowstyle)?\s+hidden",

        # MSBuild inline exec
        r"\bmsbuild(?:\.exe)?\b.*/t:Run",

        # Certificate abuse
        r"\bcertutil\b.*-urlcache.*-split",
        r"\bcertutil\b.*-decodehex",

        # Suspicious paths (chỉ match executable nằm trực tiếp trong thư mục temp/public, không match tham số flag thư mục)
        r"\\users\\public\\[^\\/\s\"']+\.(?:exe|dll|ps1|vbs|js)\b",
        r"\\appdata\\local\\temp\\[^\\/\s\"']+\.(?:exe|dll|ps1|vbs|js)\b",

        # Test simulations & admin abuse
        r"\bkey_test\b",
        r"\bransomware_sim\b",
        r"\bbackdoor_sim\b",
        r"\bpsexec\b",
        r"\bchisel\b",
    ]

    HIGH_SEVERITY_PATTERNS = [
        r"\bnc(?:\.exe)?\b.*-e\b",
        r"\bncat\b.*-e\b",
        r"\bmimikatz\b",
        r"\bmeterpreter\b",
        r"\bcobaltstrike\b",
        r"\bprocdump(?:\.exe)?\b.*\blsass\b",
        r"\bcomsvcs\.dll\b.*MiniDump",
        r"\bpowershell\b.*-enc\b",
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        if not processes:
            return 0.0, ""

        threat_intel_service = context.get("threat_intel_service")
        whitelist_service = context.get("whitelist_service")
        agent_id = context.get("agent_id")

        suspicious_count = 0
        has_high_severity = False
        threat_hash_count = 0
        proc_names: List[str] = []

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name") or "").strip().lower()
            cmdline = str(p_dict.get("cmdline") or "").strip().lower()
            exe = str(p_dict.get("exe") or p_dict.get("path") or p_dict.get("exe_path") or "").strip().lower()
            is_susp_flag = bool(p_dict.get("is_suspicious", False))
            p_hash = p_dict.get("hash")

            # Skip the LARP agent process itself
            if "agent.py" in cmdline or name == "agent.py":
                continue

            # Check whitelist first if available
            if whitelist_service:
                try:
                    if await whitelist_service.is_whitelisted(agent_id=agent_id, process_name=name, path=exe):
                        continue
                except Exception:
                    pass

            # Threat Intel hash check
            if p_hash and threat_intel_service:
                try:
                    intel_res = await threat_intel_service.check_hash(p_hash)
                    if intel_res and intel_res.get("is_malicious"):
                        threat_hash_count += 1
                except Exception:
                    pass

            if not cmdline and not exe and not is_susp_flag:
                continue

            full_str = f"{name} {cmdline} {exe}".strip()
            matched = False

            # Match patterns cụ thể (KHÔNG substring match tên process)
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, full_str, re.IGNORECASE):
                    matched = True
                    break

            # Check if binary executable itself is located directly in temp directories
            if not matched and exe:
                if exe.startswith(("/tmp/", "/dev/shm/", "/var/tmp/", "\\temp\\", "c:\\temp\\")):
                    matched = True

            if not matched and is_susp_flag:
                # If agent flagged it, verify it is not a normal application binary running from legitimate install dirs
                is_legit_path = any(exe.startswith(prefix) for prefix in (
                    "c:\\program files", "c:\\program files (x86)", "c:\\windows",
                    "/usr/bin", "/usr/sbin", "/bin", "/sbin"
                )) or "\\programs\\microsoft vs code" in exe
                if not is_legit_path or not exe:
                    # Test simulations (empty exe) or untrusted paths retain agent flag
                    matched = True

            if matched:
                suspicious_count += 1
                display_name = p_dict.get("name") or name or "suspicious_process"
                if display_name not in proc_names:
                    proc_names.append(display_name)

                for hp in self.HIGH_SEVERITY_PATTERNS:
                    if re.search(hp, full_str, re.IGNORECASE):
                        has_high_severity = True
                        break

        score = 0.0
        reasons = []

        if suspicious_count > 0:
            if has_high_severity:
                score += min(60.0, max(50.0, suspicious_count * 25.0))
            else:
                score += min(45.0, suspicious_count * 25.0)
            reasons.append(f"Found {suspicious_count} suspicious processes: {', '.join(proc_names[:5])}")

        if threat_hash_count > 0:
            score += 40.0
            reasons.append(f"Matched {threat_hash_count} malicious file hashes with Threat Intelligence")

        if score > 0:
            return score * self.base_score, "; ".join(reasons)

        return 0.0, ""
