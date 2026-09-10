from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class BaselineStatusDTO(BaseModel):
    agent_id: str
    status: str
    samples_count: int
    features: List[str]
    mean_metrics: Dict[str, float]
    std_metrics: Dict[str, float]
    last_trained_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AnomalyResultDTO(BaseModel):
    agent_id: str
    is_anomaly: bool
    anomaly_score: float  # Isolation Forest decision_function (negative = anomaly)
    risk_points: float    # Converted into 0 - 40 points
    reasons: List[str]
    current_metrics: Dict[str, float]
    baseline_means: Dict[str, float]
