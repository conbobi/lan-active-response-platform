from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class ProcessChainRule(RiskRule):
    rule_id = "process_chain"
    name = "Process Chain Anomaly"
    description = "Detects suspicious parent-child process chains (e.g. Office apps spawning shells)."
    enabled = True
    weight = 1.0

    DEFAULT_PARENTS = [
        "winword.exe", "word.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", "firefox.exe"
    ]
    DEFAULT_CHILDREN = [
        "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "bitsadmin.exe",
        "bash", "sh", "python", "python.exe"
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        process_tree = telemetry.get("process_tree", [])
        process_list = telemetry.get("process_list", [])

        parents = set(self.config.get("suspicious_parents", self.DEFAULT_PARENTS))
        children = set(self.config.get("suspicious_children", self.DEFAULT_CHILDREN))

        anomalies: List[str] = []

        # 1. Check explicit process_tree items
        for item in process_tree:
            p_dict = item if isinstance(item, dict) else item.model_dump() if hasattr(item, "model_dump") else getattr(item, "__dict__", {})
            p_name = str(p_dict.get("parent_name", "")).strip().lower()
            c_name = str(p_dict.get("child_name", "")).strip().lower()

            if any(p_name.endswith(p.lower()) for p in parents) and any(c_name.endswith(c.lower()) for c in children):
                anomalies.append(f"parent '{p_dict.get('parent_name')}' spawned child '{p_dict.get('child_name')}'")

        # 2. Check process_list items with parent_name field
        for proc in process_list:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            p_name = str(p_dict.get("parent_name", "")).strip().lower()
            c_name = str(p_dict.get("name", "")).strip().lower()

            if p_name and any(p_name.endswith(p.lower()) for p in parents) and any(c_name.endswith(c.lower()) for c in children):
                anomaly_desc = f"parent '{p_dict.get('parent_name')}' spawned child '{p_dict.get('name')}'"
                if anomaly_desc not in anomalies:
                    anomalies.append(anomaly_desc)

        if anomalies:
            score = min(50.0, len(anomalies) * 35.0)
            return score, f"Process chain anomaly detected: {', '.join(anomalies)}"

        return 0.0, ""
