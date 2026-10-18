from functools import lru_cache
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score


FEATURE_NAMES = [
    "record_count",
    "frequency_window",
    "denied_attempts",
    "department_mismatch",
    "unusual_time",
    "bulk_operation",
    "unauthorized_export",
]


def synthetic_training_data(seed: int = 2026) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    normal = np.column_stack(
        [
            rng.integers(1, 5, 420),
            rng.integers(1, 8, 420),
            rng.integers(0, 2, 420),
            np.zeros(420),
            rng.binomial(1, 0.04, 420),
            np.zeros(420),
            np.zeros(420),
        ]
    )
    suspicious = np.column_stack(
        [
            rng.integers(20, 70, 120),
            rng.integers(20, 90, 120),
            rng.integers(1, 8, 120),
            rng.binomial(1, 0.7, 120),
            rng.binomial(1, 0.4, 120),
            rng.binomial(1, 0.55, 120),
            rng.binomial(1, 0.25, 120),
        ]
    )
    return np.vstack([normal, suspicious]).astype(float), np.concatenate([np.zeros(420), np.ones(120)])


class AnomalyDetector:
    def __init__(self) -> None:
        self.model: IsolationForest | None = None
        self.status = "unavailable"
        self.error: str | None = None
        self.metrics: dict[str, float] = {}
        try:
            X, y = synthetic_training_data()
            self.model = IsolationForest(n_estimators=160, contamination=0.18, random_state=2026)
            self.model.fit(X)
            raw = self.model.predict(X)
            predicted = (raw == -1).astype(int)
            self.metrics = {
                "precision": round(float(precision_score(y, predicted, zero_division=0)), 3),
                "recall": round(float(recall_score(y, predicted, zero_division=0)), 3),
                "f1": round(float(f1_score(y, predicted, zero_division=0)), 3),
                "evaluation_samples": float(len(y)),
            }
            self.status = "ready"
        except Exception as exc:  # safe fallback keeps rules active
            self.error = str(exc)

    def infer(self, features: dict[str, Any]) -> float | None:
        if not self.model:
            return None
        try:
            values = np.array([[float(features.get(name, 0)) for name in FEATURE_NAMES]])
            raw = float(self.model.decision_function(values)[0])
            # IsolationForest's decision function is higher for normal samples.
            # This is a calibrated demo score, not a probability of wrongdoing.
            score = (0.15 - raw) * 180 + 45
            return round(float(np.clip(score, 0, 100)), 1)
        except Exception:
            return None

    def status_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "model_type": "IsolationForest",
            "version": "isolation-forest-v1",
            "features": FEATURE_NAMES,
            "metrics": self.metrics,
            "error": self.error,
            "limitations": [
                "Evaluation uses reproducible synthetic metadata with ground-truth labels.",
                "Anomaly score is a calibrated prioritization signal, not a probability or accusation.",
                "Rules-based authorization and scoring remain active if the model is unavailable.",
            ],
        }


@lru_cache
def get_detector() -> AnomalyDetector:
    return AnomalyDetector()

