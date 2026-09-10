from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule


class MLAnomalyRule(RiskRule):
    """
    Machine Learning Behavioral Anomaly Rule.
    Uses an individualized Isolation Forest baseline to detect subtle deviations
    in CPU, RAM, process count, network sockets, or file modification patterns.
    """
    rule_id = "ml_behavioral_anomaly"
    name = "ML Behavioral Anomaly"
    description = "Detects behavioral deviations from an agent's historical machine learning baseline using Isolation Forest."
    enabled = True
    weight = 1.0
    base_score = 1.0
    category = "anomaly"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        session = context.get("session")
        agent_id = context.get("agent_id") or telemetry.get("agent_id")

        if not session or not agent_id:
            return 0.0, ""

        try:
            from app.services.ml_anomaly_service import MLAnomalyService
            service = MLAnomalyService(session)
            is_anomaly, score, risk_points, reasons = await service.score_telemetry(agent_id, telemetry)

            if is_anomaly and risk_points > 0:
                reason_detail = f": {', '.join(reasons)}" if reasons else ""
                msg = f"Machine Learning behavioral anomaly detected (score={score}){reason_detail}"
                return risk_points * self.base_score, msg
        except Exception:
            # Non-blocking graceful degradation if ML dependencies or history unavailable
            pass

        return 0.0, ""
