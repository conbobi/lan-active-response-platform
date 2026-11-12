import os
from typing import Any, Dict, Tuple, List
from app.services.detection.risk_rules.base import RiskRule


class MassFileModificationRule(RiskRule):
    """
    Detect ransomware behavior by analyzing file modifications and extensions.
    Triggers when:
    1. > N files modified in short window (default: 30 files/60s)
    2. High-entropy file extensions appear (.encrypted, .locked, .crypto, etc.)
    3. Many files renamed to same new extension (> 20)
    """
    rule_id = "mass_file_modification"
    name = "Mass File Modification (Ransomware Indicator)"
    description = "Detects rapid mass file modifications, ransomware extensions, or mass extension renames."
    enabled = True
    weight = 1.0
    category = "behavior"

    RANSOM_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".ransom",
        ".wcry", ".wnry", ".locky", ".cerber", ".zepto", ".crypted"
    }
    MAX_FILES_PER_MINUTE = 30
    MAX_EXTENSION_CHANGES = 20

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        file_events = telemetry.get("file_changes") or telemetry.get("file_events") or []
        mass_flag = telemetry.get("mass_file_modification", False)
        file_changes_count = int(telemetry.get("file_changes_count", 0))

        # Extract paths
        paths: List[str] = []
        if isinstance(file_events, list):
            for e in file_events:
                if isinstance(e, dict):
                    p = e.get("path") or e.get("file_path") or e.get("target_path")
                    if p:
                        paths.append(str(p))
                elif isinstance(e, str):
                    paths.append(e)

        total_files = max(len(paths), file_changes_count)

        # Check 1: Ransomware extensions (highest priority)
        ransom_files = [p for p in paths if any(p.lower().endswith(ext) for ext in self.RANSOM_EXTENSIONS)]
        if len(ransom_files) >= 5 or (ransom_files and total_files >= 10):
            sample = ", ".join(os.path.basename(p) for p in ransom_files[:3])
            reason = f"Ransomware extension detected: {len(ransom_files)} files with ransomware extensions ({sample})"
            return 80.0 * self.base_score, reason

        # Check 2: Mass rename to same extension
        if paths:
            ext_counts: Dict[str, int] = {}
            for p in paths:
                ext = os.path.splitext(p)[1].lower()
                if ext and ext not in (".tmp", ".log", ".txt", ".json", ".dat"):
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1
            if ext_counts:
                most_common_ext, count = max(ext_counts.items(), key=lambda x: x[1])
                if count >= self.MAX_EXTENSION_CHANGES:
                    reason = f"Mass rename to extension {most_common_ext}: {count} files"
                    return 70.0 * self.base_score, reason

        # Check 3: Mass modification count / flag
        if mass_flag or total_files >= self.MAX_FILES_PER_MINUTE:
            score = 40.0 if mass_flag else (70.0 if total_files >= 50 else 60.0)
            reason = f"Mass file modification / Ransomware activity detected (flag={mass_flag}, count={total_files})"
            return score * self.base_score, reason

        return 0.0, ""
