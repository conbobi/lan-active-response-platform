from typing import Any, Dict, Tuple
from app.services.detection.risk_rules.base import RiskRule

KERNEL_PROCESSES = {
    "system idle process",
    "system",
    "registry",
    "memory compression",
    "smss.exe",
    "idle",
}


class CpuSpikeRule(RiskRule):
    rule_id = "cpu_spike"
    name = "CPU Spike Anomaly"
    description = "Detects abnormally high CPU utilization spikes."
    enabled = True
    weight = 1.0
    category = "os"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        cpu = float(telemetry.get("cpu_usage") or telemetry.get("cpu") or 0.0)
        high_threshold = self.config.get("high_threshold", 85.0)
        high_score = self.config.get("high_score", 30.0) * self.base_score
        medium_threshold = self.config.get("medium_threshold", 70.0)
        medium_score = self.config.get("medium_score", 15.0) * self.base_score

        # Skip kernel processes / idle time
        # On Windows, System Idle Process (PID 0) reports high CPU when system is idle.
        processes = telemetry.get("process_list", [])
        if processes:
            # Check if System Idle Process or kernel process is dominant
            for p in processes:
                p_name = str(p.get("name") if isinstance(p, dict) else getattr(p, "name", "")).strip().lower()
                p_pid = p.get("pid") if isinstance(p, dict) else getattr(p, "pid", None)
                p_cpu = float(p.get("cpu_percent") or p.get("cpu") or 0.0) if isinstance(p, dict) else float(getattr(p, "cpu_percent", 0.0) or 0.0)
                
                # If System Idle Process or kernel process has high CPU, it's normal idle state
                if (p_name in KERNEL_PROCESSES or p_pid == 0) and p_cpu > 70.0:
                    return 0.0, ""

            # Check if any non-kernel process is actually consuming high CPU
            non_kernel_procs = [
                p for p in processes
                if str(p.get("name") if isinstance(p, dict) else getattr(p, "name", "")).strip().lower() not in KERNEL_PROCESSES
                and (p.get("pid") if isinstance(p, dict) else getattr(p, "pid", None)) != 0
            ]
            if non_kernel_procs:
                max_user_cpu = max(
                    (float(p.get("cpu_percent") or p.get("cpu") or 0.0) if isinstance(p, dict) else float(getattr(p, "cpu_percent", 0.0) or 0.0))
                    for p in non_kernel_procs
                )
                if max_user_cpu < 25.0 and cpu > medium_threshold:
                    has_idle = any(
                        str(p.get("name") if isinstance(p, dict) else getattr(p, "name", "")).strip().lower() in KERNEL_PROCESSES
                        for p in processes
                    )
                    if has_idle:
                        return 0.0, ""

        if cpu > high_threshold:
            return high_score, f"Critical CPU spike ({cpu}%)"
        elif cpu > medium_threshold:
            return medium_score, f"Elevated CPU usage ({cpu}%)"

        return 0.0, ""
