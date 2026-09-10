import io
import math
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import joblib
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_baseline import AgentBaseline
from app.models.agent_history import AgentHistory
from app.repositories.agent_baseline_repository import AgentBaselineRepository

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "cpu_usage",
    "ram_usage",
    "disk_usage",
    "process_count",
    "network_connections_count",
    "file_changes_count"
]


class MLAnomalyService:
    """
    Lightweight Machine Learning Behavioral Anomaly Detection Service for Agents.
    Uses Scikit-Learn's Isolation Forest to build baseline profiles for each agent
    and identifies subtle behavioral anomalies without static threshold limits.
    All ML compute executes non-blocking in background thread pools.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = AgentBaselineRepository(session)
        self._model_cache: Dict[str, Any] = {}

    @classmethod
    def extract_features(cls, telemetry: Dict[str, Any]) -> List[float]:
        """Extract standardized 6-dimensional feature vector from telemetry."""
        cpu = float(telemetry.get("cpu_usage", 0.0) or telemetry.get("cpu", 0.0))
        ram = float(telemetry.get("ram_usage", 0.0) or telemetry.get("ram", 0.0))
        disk = float(telemetry.get("disk_usage", 0.0) or telemetry.get("disk", 0.0))

        procs = telemetry.get("process_list", [])
        proc_count = float(len(procs)) if isinstance(procs, list) else 0.0

        conns = telemetry.get("network_connections", [])
        conn_count = float(len(conns)) if isinstance(conns, list) else 0.0

        file_changes = float(telemetry.get("file_changes_count", 0))

        return [cpu, ram, disk, proc_count, conn_count, file_changes]

    def _train_isolation_forest(self, data_matrix: List[List[float]]) -> Tuple[bytes, Dict[str, float], Dict[str, float]]:
        """Fit Isolation Forest and compute baseline statistics (runs in worker thread)."""
        from sklearn.ensemble import IsolationForest
        import numpy as np

        X = np.array(data_matrix, dtype=np.float32)

        # Fit Isolation Forest
        model = IsolationForest(
            n_estimators=100,
            contamination=0.03,  # Expect ~3% anomalous noise in baseline
            random_state=42,
            n_jobs=1
        )
        model.fit(X)

        # Compute mean and standard deviation
        means = np.mean(X, axis=0)
        stds = np.std(X, axis=0)
        stds = np.where(stds == 0, 1.0, stds)  # Avoid division by zero

        mean_dict = {name: round(float(means[i]), 2) for i, name in enumerate(FEATURE_NAMES)}
        std_dict = {name: round(float(stds[i]), 2) for i, name in enumerate(FEATURE_NAMES)}

        buf = io.BytesIO()
        joblib.dump(model, buf, compress=3)
        return buf.getvalue(), mean_dict, std_dict

    async def train_agent_baseline(self, agent_id: str) -> Optional[AgentBaseline]:
        """Collect historical telemetry samples and train individual baseline model."""
        stmt = select(AgentHistory).where(AgentHistory.agent_id == agent_id).limit(500)
        res = await self.session.execute(stmt)
        hist_records = list(res.scalars().all())

        data_matrix = []
        for rec in hist_records:
            t_data = {
                "cpu_usage": rec.cpu,
                "ram_usage": rec.ram,
                "disk_usage": rec.disk,
                "process_list": [],
                "network_connections": [],
                "file_changes_count": 0
            }
            data_matrix.append(self.extract_features(t_data))

        # If sparse history, bootstrap with slight variations around average to form baseline
        if len(data_matrix) < 20:
            base_vec = [15.0, 35.0, 20.0, 25.0, 5.0, 0.0]
            for i in range(30):
                jitter = [(val + (i % 5 - 2) * 1.5) for val in base_vec]
                data_matrix.append(jitter)

        # Run training in background thread
        model_bytes, mean_dict, std_dict = await asyncio.to_thread(self._train_isolation_forest, data_matrix)

        existing = await self.repo.get_by_agent(agent_id)
        now_dt = datetime.now(timezone.utc)

        if existing:
            existing.model_data = model_bytes
            existing.mean_vector = mean_dict
            existing.std_vector = std_dict
            existing.samples_count = len(data_matrix)
            existing.status = "ready"
            existing.last_trained_at = now_dt
            baseline = existing
        else:
            baseline = AgentBaseline(
                agent_id=agent_id,
                model_data=model_bytes,
                features_list=FEATURE_NAMES,
                status="ready",
                samples_count=len(data_matrix),
                mean_vector=mean_dict,
                std_vector=std_dict,
                last_trained_at=now_dt
            )
            await self.repo.add(baseline)

        await self.session.commit()
        # Invalidate cache
        if agent_id in self._model_cache:
            del self._model_cache[agent_id]

        logger.info(f"Trained ML baseline for agent '{agent_id}' with {len(data_matrix)} samples.")
        return baseline

    def _predict_model(self, model: Any, features: List[float], mean_dict: Dict[str, float], std_dict: Dict[str, float]) -> Tuple[bool, float, float, List[str]]:
        """Inference function (runs in worker thread)."""
        import numpy as np
        X = np.array([features], dtype=np.float32)

        # Isolation Forest: -1 is anomaly, 1 is normal
        pred = model.predict(X)[0]
        # decision_function: lower (more negative) means more anomalous
        score = float(model.decision_function(X)[0])

        # Feature deviation analysis (Z-score 3-sigma rule)
        z_reasons = []
        for i, name in enumerate(FEATURE_NAMES):
            val = features[i]
            mean_val = mean_dict.get(name, 0.0)
            std_val = std_dict.get(name, 1.0)
            z_score = abs(val - mean_val) / std_val if std_val > 0 else 0.0
            if z_score > 2.5:
                z_reasons.append(f"{name} spiked to {val} (baseline avg: {mean_val})")

        is_anomaly = (pred == -1 or score < 0.0 or len(z_reasons) > 0)
        risk_points = 0.0
        reasons = z_reasons

        if is_anomaly:
            severity_factor = min(1.0, max(0.0, -score * 3.0)) if score < 0 else min(1.0, len(z_reasons) * 0.3)
            risk_points = round(25.0 + severity_factor * 15.0, 1)

        return is_anomaly, round(score, 3), risk_points, reasons

    async def score_telemetry(self, agent_id: str, telemetry: Dict[str, Any]) -> Tuple[bool, float, float, List[str]]:
        """
        Evaluate incoming agent telemetry against its ML baseline.
        Returns: (is_anomaly, anomaly_score, risk_points, reasons)
        """
        # Retrieve or cache model
        if agent_id not in self._model_cache:
            baseline = await self.repo.get_by_agent(agent_id)
            if not baseline:
                baseline = await self.train_agent_baseline(agent_id)
            if not baseline or not baseline.model_data:
                return False, 0.0, 0.0, []

            try:
                buf = io.BytesIO(baseline.model_data)
                loaded_model = joblib.load(buf)
                self._model_cache[agent_id] = (loaded_model, baseline.mean_vector, baseline.std_vector)
            except Exception as e:
                logger.error(f"Failed to load ML baseline for agent '{agent_id}': {e}")
                return False, 0.0, 0.0, []

        model, mean_dict, std_dict = self._model_cache[agent_id]
        features = self.extract_features(telemetry)

        is_anomaly, score, risk_points, reasons = await asyncio.to_thread(
            self._predict_model,
            model,
            features,
            mean_dict,
            std_dict
        )

        return is_anomaly, score, risk_points, reasons
