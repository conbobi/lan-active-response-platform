import logging
from typing import List, Dict, Any, Optional
from app.models.event import Event
from app.models.flow import Flow
from app.models.process_info import ProcessInfo
from app.schemas.enums import IncidentSeverity

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Security Detection Engine responsible for correlating events, calculating risk scores,
    classifying security incidents, and updating metric baselines.
    """
    def __init__(self):
        self._baselines: Dict[str, Dict[str, float]] = {}

    def correlate_events(self, events: List[Event]) -> Dict[str, Any]:
        """Correlate security events based on agent ID and event patterns."""
        correlation: Dict[str, List[Event]] = {}
        for ev in events:
            correlation.setdefault(ev.agent_id, []).append(ev)

        correlated_summary = {}
        for agent_id, agent_events in correlation.items():
            event_types = set(e.event_type for e in agent_events)
            is_suspicious_cluster = len(event_types) >= 2 or len(agent_events) >= 5
            correlated_summary[agent_id] = {
                "event_count": len(agent_events),
                "event_types": list(event_types),
                "is_cluster": is_suspicious_cluster
            }
        return correlated_summary

    def calculate_risk_score(self, target: Any) -> float:
        """Calculate dynamic risk score for a flow, event, or process."""
        score = 0.0
        if isinstance(target, Flow):
            # Higher risk for unusual ports or massive byte counts
            if target.dst_port in [4444, 1337, 31337, 6667, 23, 21]:
                score += 40.0
            if target.bytes_sent > 10_000_000:
                score += 20.0
        elif isinstance(target, Event):
            severity_weights = {
                IncidentSeverity.LOW: 10.0,
                IncidentSeverity.MEDIUM: 30.0,
                IncidentSeverity.HIGH: 60.0,
                IncidentSeverity.CRITICAL: 90.0,
            }
            score += severity_weights.get(target.severity, 10.0)
        elif isinstance(target, ProcessInfo):
            if target.is_suspicious_process():
                score += 75.0
            if target.cpu_percent > 80.0:
                score += 15.0

        return min(100.0, round(score, 2))

    def classify_incident(self, risk_score: float) -> IncidentSeverity:
        """Classify incident severity based on risk score."""
        if risk_score >= 80.0:
            return IncidentSeverity.CRITICAL
        elif risk_score >= 50.0:
            return IncidentSeverity.HIGH
        elif risk_score >= 25.0:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW

    def update_baseline(self, agent_id: str, metric_data: Dict[str, float]) -> None:
        """Update statistical baseline metrics for an agent."""
        if agent_id not in self._baselines:
            self._baselines[agent_id] = {}

        for key, value in metric_data.items():
            curr = self._baselines[agent_id].get(key, value)
            # Exponential moving average for baseline update
            self._baselines[agent_id][key] = round(curr * 0.8 + value * 0.2, 2)
        logger.debug(f"Updated baseline for agent '{agent_id}': {self._baselines[agent_id]}")


detection_engine = DetectionEngine()
