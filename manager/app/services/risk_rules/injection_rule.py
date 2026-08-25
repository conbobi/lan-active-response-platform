from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class InjectionRule(RiskRule):
    rule_id = "injection"
    name = "Process Injection Anomaly"
    description = "Detects code injection or memory tampering within legitimate process contexts."
    enabled = True
    weight = 1.0
    category = "process"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        injected_procs: List[str] = []

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            if p_dict.get("is_injected"):
                name = p_dict.get("name", "unknown")
                pid = p_dict.get("pid", "?")
                injected_procs.append(f"'{name}' (PID: {pid})")

        if injected_procs:
            score = min(50.0, len(injected_procs) * 40.0) * self.base_score
            return score, f"Process injection detected in: {', '.join(injected_procs)}"

        return 0.0, ""
