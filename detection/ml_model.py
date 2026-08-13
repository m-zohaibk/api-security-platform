import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import ISOLATION_FOREST_PATH

class MLAnomalyDetector:
    """
    Layer 2 — ML Anomaly Detection Engine
    Uses trained Isolation Forest model to evaluate 12 extracted numerical HTTP features
    and calculates anomaly scores and risk points (0 to 40).
    """

    FEATURE_KEYS = [
        "encoded_method",
        "path_depth",
        "url_length",
        "query_param_count",
        "query_string_length",
        "payload_length",
        "payload_entropy",
        "special_char_count",
        "header_count",
        "auth_header_present",
        "status_code",
        "response_size"
    ]

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else Path(ISOLATION_FOREST_PATH)
        self.model = self._load_model()

    def _load_model(self) -> Optional[Any]:
        if not self.model_path.exists():
            logger.warning(f"Isolation Forest model file not found at {self.model_path}. Layer 2 will return baseline scores.")
            return None
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Successfully loaded Isolation Forest model from {self.model_path}")
            return model
        except Exception as exc:
            logger.error(f"Error loading Isolation Forest model from {self.model_path}: {exc}")
            return None

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs Isolation Forest anomaly prediction on 12 extracted features.
        Returns normalized anomaly score (0.0 to 1.0) and points (0 to 40).
        """
        if self.model is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "points": 0,
                "note": "Model file missing"
            }

        # Extract feature vector in correct ordered array shape
        if "feature_vector" in feature_dict and len(feature_dict["feature_vector"]) == 12:
            vector = feature_dict["feature_vector"]
        else:
            vector = [feature_dict.get(k, 0) for k in self.FEATURE_KEYS]

        features_array = np.array(vector).reshape(1, -1)

        try:
            # Raw decision function output (lower values indicate higher anomaly likelihood)
            decision_score = self.model.decision_function(features_array)[0]
            
            # Normalize decision score to an anomaly score between 0.0 and 1.0
            # Decision scores typically range from -0.5 (very anomalous) to +0.5 (very normal)
            raw_anomaly_score = 0.5 - decision_score
            normalized_score = float(np.clip(raw_anomaly_score, 0.0, 1.0))
            
            is_anomaly = bool(normalized_score > 0.5)
            points = round(normalized_score * 40.0, 2)

            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(normalized_score, 4),
                "points": min(points, 40.0),
                "note": "Model prediction complete"
            }
        except Exception as exc:
            logger.error(f"Error executing Isolation Forest inference: {exc}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "points": 0,
                "note": f"Inference error: {exc}"
            }


if __name__ == "__main__":
    detector = MLAnomalyDetector()
    sample_features = {
        "encoded_method": 2,
        "path_depth": 4,
        "url_length": 120,
        "query_param_count": 5,
        "query_string_length": 80,
        "payload_length": 250,
        "payload_entropy": 6.8,
        "special_char_count": 35,
        "header_count": 6,
        "auth_header_present": 0,
        "status_code": 500,
        "response_size": 4096
    }
    res = detector.predict(sample_features)
    print("\n[+] ML Anomaly Detector Test Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
