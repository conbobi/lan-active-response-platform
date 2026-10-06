import io
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
]

MIN_STD = {
    "cpu_usage": 5.0,   # σ tối thiểu 5% để tránh zero-variance trap
    "ram_usage": 3.0,   # σ tối thiểu 3%
    "disk_delta": 2.0,
}

ABSOLUTE_FLOOR = {
    "cpu_usage": 15.0,  # CPU < 15% không bao giờ anomaly
    "ram_usage": 10.0,  # RAM < 10% không bao giờ anomaly
    "disk_delta": 5.0,  # delta < 5% không anomaly
}


class MLAnomalyResult(dict):
    """Result dictionary that also unpacks like a 4-tuple (is_anomaly, score, risk_points, reasons)."""
    def __iter__(self):
        return iter((self["is_anomaly"], self["score"], self["risk_points"], self["reasons"]))


class MLAnomalyService:
    """
    Lightweight Machine Learning Behavioral Anomaly Detection Service for Agents.
    Uses Scikit-Learn's RobustScaler + Isolation Forest to build baseline profiles
    for each agent and identifies subtle behavioral anomalies without static threshold limits.
    All ML compute executes non-blocking in background thread pools.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = AgentBaselineRepository(session)
        self._model_cache: Dict[str, Any] = {}

    @classmethod
    def extract_features(cls, telemetry: Dict[str, Any]) -> List[float]:
        """Extract standardized 2-dimensional feature vector (cpu, ram) from telemetry."""
        cpu = float(telemetry.get("cpu_usage", 0.0) or telemetry.get("cpu", 0.0) or 0.0)
        ram = float(telemetry.get("ram_usage", 0.0) or telemetry.get("ram", 0.0) or 0.0)
        return [cpu, ram]

    def _train_isolation_forest(self, data_matrix: List[List[float]]) -> Tuple[bytes, Dict[str, float], Dict[str, float]]:
        """Fit RobustScaler + Isolation Forest and compute baseline statistics (runs in worker thread)."""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import RobustScaler
        from sklearn.pipeline import Pipeline
        import numpy as np

        X = np.array(data_matrix, dtype=np.float32)

        # Pipeline with RobustScaler and Isolation Forest (contamination='auto')
        pipeline = Pipeline([
            ("scaler", RobustScaler()),
            ("forest", IsolationForest(
                n_estimators=100,
                contamination="auto",
                random_state=42,
                n_jobs=1
            ))
        ])
        pipeline.fit(X)

        # Compute mean and standard deviation
        means = np.mean(X, axis=0)
        stds = np.std(X, axis=0)
        stds = np.where(stds == 0, 1.0, stds)  # Avoid division by zero

        mean_dict = {name: round(float(means[i]), 2) for i, name in enumerate(FEATURE_NAMES)}
        std_dict = {name: round(float(stds[i]), 2) for i, name in enumerate(FEATURE_NAMES)}

        buf = io.BytesIO()
        joblib.dump(pipeline, buf, compress=3)
        return buf.getvalue(), mean_dict, std_dict

    async def train_agent_baseline(self, agent_id: str) -> Optional[AgentBaseline]:
        """Collect historical telemetry samples and train individual baseline model."""
        stmt = (
            select(AgentHistory)
            .where(AgentHistory.agent_id == agent_id)
            .order_by(AgentHistory.timestamp.desc())
            .limit(500)
        )
        res = await self.session.execute(stmt)
        hist_records = list(res.scalars().all())

        data_matrix = []
        for rec in hist_records:
            t_data = {
                "cpu_usage": rec.cpu,
                "ram_usage": rec.ram,
            }
            data_matrix.append(self.extract_features(t_data))

        # If sparse history, bootstrap with slight variations around average to form baseline
        if len(data_matrix) < 20:
            base_vec = [15.0, 35.0]
            for i in range(30):
                jitter = [(val + (i % 5 - 2) * 1.5) for val in base_vec]
                data_matrix.append(jitter)

        # Run training in background thread
        model_bytes, mean_dict, std_dict = await asyncio.to_thread(self._train_isolation_forest, data_matrix)

        existing = await self.repo.get_by_agent(agent_id)
        now_dt = datetime.now(timezone.utc)

        if existing:
            existing.model_data = model_bytes
            existing.features_list = FEATURE_NAMES
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

        # Feature deviation analysis (Z-score rule with floor & min_std)
        z_reasons = []
        for i, name in enumerate(FEATURE_NAMES):
            val = features[i]
            # Bước 1: Absolute floor — skip nếu giá trị quá thấp
            if name in ABSOLUTE_FLOOR and val < ABSOLUTE_FLOOR[name]:
                continue

            # Bước 2: Lấy baseline stats
            mean_val = mean_dict.get(name, 0.0)
            std_val = std_dict.get(name, 1.0)

            # Bước 3: Áp dụng MIN_STD floor để tránh zero-variance trap
            effective_std = max(std_val, MIN_STD.get(name, 1.0))

            # Bước 4: Tính Z-score
            z_score = abs(val - mean_val) / effective_std
            if z_score > 2.5:
                z_reasons.append(f"{name} spiked to {val:.2f} (baseline avg: {mean_val:.2f})")

        ANOMALY_SCORE_THRESHOLD = -0.05
        MIN_Z_REASONS = 2

        # Chỉ anomaly khi:
        # - Isolation Forest score âm rõ rệt (< -0.05 cho không gian 2 chiều)
        # - VÀ có ít nhất 2 feature vượt ngưỡng Z-score
        is_anomaly = (score < ANOMALY_SCORE_THRESHOLD) and (len(z_reasons) >= MIN_Z_REASONS)

        # Override rule: chỉ override khi độ lệch cực kỳ nghiêm trọng
        # (score < -0.25 kèm 1 reason) để tránh false positive từ các spike đơn lẻ
        if pred == -1 and score < -0.25 and len(z_reasons) >= 1:
            is_anomaly = True

        risk_points = 0.0
        reasons = z_reasons

        if is_anomaly:
            severity_factor = min(1.0, max(0.0, -score * 3.0)) if score < 0 else min(1.0, len(z_reasons) * 0.3)
            risk_points = round(5.0 + severity_factor * 10.0, 1)

        return is_anomaly, round(score, 3), risk_points, reasons

    train_baseline = train_agent_baseline

    async def score_telemetry(self, agent_id: str, telemetry: Dict[str, Any]) -> MLAnomalyResult:
        """
        Evaluate incoming agent telemetry against its ML baseline.
        Returns: MLAnomalyResult dict (unpackable as is_anomaly, score, risk_points, reasons)
        """
        # Retrieve or cache model
        if agent_id not in self._model_cache:
            baseline = await self.repo.get_by_agent(agent_id)
            now_utc = datetime.now(timezone.utc)
            updated_ts = baseline.updated_at if (baseline and baseline.updated_at) else None
            age_seconds = (
                (now_utc - (updated_ts if updated_ts.tzinfo else updated_ts.replace(tzinfo=timezone.utc))).total_seconds()
                if updated_ts else 999999
            )

            # Nếu baseline chưa có, sai schema feature, quá ít mẫu, hoặc quá cũ (> 1h) → retrain
            needs_retrain = (
                baseline is None
                or not baseline.model_data
                or baseline.features_list != FEATURE_NAMES
                or (baseline.samples_count < 100 and age_seconds > 300)
                or age_seconds > 3600
            )
            if needs_retrain:
                logger.info(f"Retraining baseline for {agent_id}: samples={baseline.samples_count if baseline else 0}")
                baseline = await self.train_agent_baseline(agent_id)

            if not baseline or not baseline.model_data:
                return MLAnomalyResult({"is_anomaly": False, "score": 0.0, "risk_points": 0.0, "reasons": [], "z_reasons": []})

            try:
                buf = io.BytesIO(baseline.model_data)
                loaded_model = joblib.load(buf)
                self._model_cache[agent_id] = (loaded_model, baseline.mean_vector, baseline.std_vector)
            except Exception as e:
                logger.error(f"Failed to load ML baseline for agent '{agent_id}': {e}")
                return MLAnomalyResult({"is_anomaly": False, "score": 0.0, "risk_points": 0.0, "reasons": [], "z_reasons": []})

        model, mean_dict, std_dict = self._model_cache[agent_id]
        features = self.extract_features(telemetry)

        try:
            is_anomaly, score, risk_points, reasons = await asyncio.to_thread(
                self._predict_model,
                model,
                features,
                mean_dict,
                std_dict
            )
        except Exception as e:
            logger.warning(f"ML prediction error for agent '{agent_id}': {e}. Retraining baseline...")
            baseline = await self.train_agent_baseline(agent_id)
            if baseline and baseline.model_data:
                buf = io.BytesIO(baseline.model_data)
                loaded_model = joblib.load(buf)
                self._model_cache[agent_id] = (loaded_model, baseline.mean_vector, baseline.std_vector)
                model, mean_dict, std_dict = self._model_cache[agent_id]
                is_anomaly, score, risk_points, reasons = await asyncio.to_thread(
                    self._predict_model,
                    model,
                    features,
                    mean_dict,
                    std_dict
                )
            else:
                return MLAnomalyResult({"is_anomaly": False, "score": 0.0, "risk_points": 0.0, "reasons": [], "z_reasons": []})

        return MLAnomalyResult({
            "is_anomaly": is_anomaly,
            "score": score,
            "risk_points": risk_points,
            "reasons": reasons,
            "z_reasons": reasons,
        })
