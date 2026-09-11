import os
import logging
from typing import Any, Dict, Tuple
from app.services.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)


class MLAnomalyRule(RiskRule):
    """
    Machine Learning Behavioral Anomaly Rule.
    Uses an individualized Isolation Forest baseline to detect subtle deviations
    in CPU, RAM, process count, network sockets, or file modification patterns.
    """
    rule_id = "ml_behavioral_anomaly"
    name = "ML Behavioral Anomaly"
    description = "Detects behavioral deviations from an agent's historical machine learning baseline using Isolation Forest."
    weight = 0.5           # GIẢM từ 1.0 xuống 0.5
    base_score = 10.0      # GIẢM từ 25.0 xuống 10.0
    category = "anomaly"

    def __init__(self):
        super().__init__()
        # Cho phép cấu hình qua env var
        self.enabled = os.getenv("ML_ANOMALY_RULE_ENABLED", "true").lower() == "true"
        self.log_only = os.getenv("ML_ANOMALY_RULE_LOG_ONLY", "false").lower() == "true"

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        if not self.enabled:
            return 0.0, ""

        session = context.get("session")
        agent_id = context.get("agent_id") or telemetry.get("agent_id")

        if not session or not agent_id:
            return 0.0, ""

        try:
            from app.services.ml_anomaly_service import MLAnomalyService
            service = MLAnomalyService(session)
            is_anomaly, score, risk_points, reasons = await service.score_telemetry(agent_id, telemetry)

            if self.log_only:
                if is_anomaly:
                    logger.info(f"[LOG-ONLY] ML anomaly for {agent_id}: score={score}, points={risk_points}, reasons={reasons}")
                return 0.0, ""

            if is_anomaly and risk_points > 0:
                reason_detail = f": {', '.join(reasons)}" if reasons else ""
                msg = f"Machine Learning behavioral anomaly detected (score={score}){reason_detail}"
                scaled_score = (risk_points / 10.0) * self.base_score
                return scaled_score, msg
        except Exception:
            # Non-blocking graceful degradation if ML dependencies or history unavailable
            pass

        return 0.0, ""
