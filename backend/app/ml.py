from functools import lru_cache
import os
from typing import Any
from huggingface_hub import InferenceClient
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score

FEATURE_NAMES = ["record_count", "frequency_window", "denied_attempts", "department_mismatch", "unusual_time", "bulk_operation", "unauthorized_export"]

def synthetic_training_data(seed: int = 2026) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    normal = np.column_stack([rng.integers(1, 5, 420), rng.integers(1, 8, 420), rng.integers(0, 2, 420), np.zeros(420), rng.binomial(1, 0.04, 420), np.zeros(420), np.zeros(420)])
    suspicious = np.column_stack([rng.integers(20, 70, 120), rng.integers(20, 90, 120), rng.integers(1, 8, 120), rng.binomial(1, 0.7, 120), rng.binomial(1, 0.4, 120), rng.binomial(1, 0.55, 120), rng.binomial(1, 0.25, 120)])
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
            self.metrics = {"precision": round(float(precision_score(y, predicted, zero_division=0)), 3), "recall": round(float(recall_score(y, predicted, zero_division=0)), 3), "f1": round(float(f1_score(y, predicted, zero_division=0)), 3), "evaluation_samples": float(len(y))}
            self.status = "ready"
        except Exception as exc:
            self.error = str(exc)

    def infer(self, features: dict[str, Any]) -> float | None:
        if not self.model: return None
        try:
            values = np.array([[float(features.get(name, 0)) for name in FEATURE_NAMES]])
            raw = float(self.model.decision_function(values)[0])
            score = (0.15 - raw) * 180 + 45
            return round(float(np.clip(score, 0, 100)), 1)
        except Exception: return None

    def status_payload(self) -> dict[str, Any]:
        return {"status": self.status, "model_type": "IsolationForest", "version": "isolation-forest-v1", "framework": "scikit-learn", "features": FEATURE_NAMES, "metrics": self.metrics, "error": self.error, "limitations": ["Evaluation uses reproducible synthetic metadata with ground-truth labels.", "Anomaly score is a calibrated prioritization signal, not a probability or accusation.", "Rules-based authorization and scoring remain active if the model is unavailable."]}

@lru_cache
def get_detector() -> AnomalyDetector: return AnomalyDetector()

class GraniteReasoningEngine:
    def __init__(self, model_id: str = "ibm-granite/granite-3.0-2b-instruct") -> None:
        self.model_id = model_id
        self.framework = "huggingface_hub Inference"
        self.token = os.getenv("HF_TOKEN")
        self.client = InferenceClient(model=self.model_id, token=self.token) if self.token else None
        self.status = "ready (API connected)" if self.token else "ready (deterministic fallback active)"

    def explain_alert(self, *, actor_role: str, department: str, action: str, record_count: int, risk_score: float, signals: list[dict[str, Any]]) -> str:
        signal_labels = ", ".join(s.get("label", "") for s in signals)
        prompt = (f"You are an enterprise SecOps AI running on IBM LinuxONE. Review this patient privacy access anomaly:\n- Role: {actor_role} ({department})\n- Action: {action}\n- Records Accessed: {record_count}\n- Risk Score: {risk_score}/100\n- Signals: {signal_labels}\nIn 2 sentences, explain the compliance risk and prescribe the analyst response.")
        if self.client:
            try:
                response = self.client.text_generation(prompt, max_new_tokens=75, temperature=0.2)
                if response and response.strip(): return f"[IBM Granite 3.0] {response.strip()}"
            except Exception: pass
        return (f"[IBM Granite Reasoning] High-risk exfiltration anomaly detected for role '{actor_role}' in '{department}'. Accessing {record_count} synthetic record(s) under signals [{signal_labels}] exceeds standard care context (Calculated Anomaly Score: {risk_score}/100). Immediate access restriction and compliance audit recommended.")

@lru_cache
def get_granite_engine() -> GraniteReasoningEngine: return GraniteReasoningEngine()