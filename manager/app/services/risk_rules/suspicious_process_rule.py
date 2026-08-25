from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class SuspiciousProcessRule(RiskRule):
    rule_id = "suspicious_process"
    name = "Suspicious Process & Threat Intel Hash"
    description = "Detects known malicious binaries, suspicious flags, and Threat Intelligence hash matches."
    enabled = True
    weight = 1.0
    category = "os"

    DEFAULT_SUSPICIOUS_NAMES = [
        "mimikatz.exe", "mimikatz", "netcat", "nc", "nc.exe", "nc.openbsd", "nc.traditional", "nmap", "chisel",
        "psexec.exe", "procdump.exe", "bloodhound", "sharphound", "lazagne", "vssadmin", "sleep", "ransomware_sim"
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        if not processes:
            return 0.0, ""

        suspicious_list = self.config.get("suspicious_names", self.DEFAULT_SUSPICIOUS_NAMES)
        suspicious_proc_count = 0
        threat_hash_count = 0
        proc_names: List[str] = []

        threat_intel_service = context.get("threat_intel_service")

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name", "")).strip().lower()
            cmdline = str(p_dict.get("cmdline", "")).strip().lower()
            is_susp = p_dict.get("is_suspicious", False)
            p_hash = p_dict.get("hash")

            full_str = f"{name} {cmdline}"
            is_match = is_susp or any(s.lower() in full_str for s in suspicious_list)

            if is_match:
                suspicious_proc_count += 1
                display_name = p_dict.get("name") or name or "suspicious_process"
                if display_name not in proc_names:
                    proc_names.append(display_name)

            if p_hash and threat_intel_service:
                try:
                    intel_res = await threat_intel_service.check_hash(p_hash)
                    if intel_res and intel_res.get("is_malicious"):
                        threat_hash_count += 1
                except Exception:
                    pass

        score = 0.0
        reasons = []

        if suspicious_proc_count > 0:
            score += min(45.0, suspicious_proc_count * 25.0)
            reasons.append(f"Found {suspicious_proc_count} suspicious processes: {', '.join(proc_names)}")

        if threat_hash_count > 0:
            score += 40.0
            reasons.append(f"Matched {threat_hash_count} malicious file hashes with Threat Intelligence")

        if score > 0:
            return score * self.base_score, "; ".join(reasons)

        return 0.0, ""
