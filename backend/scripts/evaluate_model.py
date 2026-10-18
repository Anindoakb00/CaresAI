"""Evaluate the deterministic synthetic anomaly baseline."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ml import AnomalyDetector


if __name__ == "__main__":
    detector = AnomalyDetector()
    print({"status": detector.status, "metrics": detector.metrics, "features": detector.status_payload()["features"]})

