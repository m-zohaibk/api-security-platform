import os
import sys
from datetime import datetime
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger

class RiskScorer:
    """
    Risk Scoring Engine
    Combines point contributions from Layer 1 (Signature), Layer 2 (Isolation Forest ML),
    and Layer 3 (PyTorch LSTM + Autoencoder DL), normalizes the score to 0-100, and assigns severity.
    """

    MAX_RAW_POINTS = 180.0  # 90 (Signature) + 40 (ML) + 30 (LSTM) + 20 (Autoencoder)

    SEVERITY_RECOMMENDATIONS = {
        "Low": "Baseline telemetry parameters normal. Maintain routine security monitoring and header hardening.",
        "Medium": "Elevated structural anomaly or header misconfiguration detected. Audit API endpoint input parameters.",
        "High": "Significant anomaly or signature match detected. Review input validation and database query parameterization.",
        "Critical": "Critical attack pattern detected across multiple engine layers. Immediately enforce WAF filtering and remediate underlying endpoint code."
    }

    @staticmethod
    def classify_severity(score: float) -> str:
        if score >= 85.0:
            return "Critical"
        elif score >= 60.0:
            return "High"
        elif score >= 30.0:
            return "Medium"
        else:
            return "Low"

    def calculate_risk(
        self,
        signature_result: Dict[str, Any],
        ml_result: Dict[str, Any],
        dl_result: Dict[str, Any],
        endpoint_url: str = "",
        http_method: str = "GET"
    ) -> Dict[str, Any]:
        """
        Calculates combined risk score from all 3 detection layers.
        Returns detailed summary dictionary with normalized score, severity, and remediation guidance.
        """
        sig_points = float(signature_result.get("points", 0.0))
        ml_points = float(ml_result.get("points", 0.0))
        lstm_points = float(dl_result.get("lstm_points", 0.0))
        ae_points = float(dl_result.get("autoencoder_points", 0.0))

        raw_total = sig_points + ml_points + lstm_points + ae_points
        
        # Normalize raw total (0-180) to 0-100 scale
        normalized_score = round(min(100.0, (raw_total / self.MAX_RAW_POINTS) * 100.0), 2)
        severity = self.classify_severity(normalized_score)
        recommendation = self.SEVERITY_RECOMMENDATIONS[severity]

        timestamp = datetime.utcnow().isoformat() + "Z"

        result_summary = {
            "endpoint": endpoint_url,
            "method": http_method.upper(),
            "timestamp": timestamp,
            "total_score": normalized_score,
            "severity": severity,
            "points_breakdown": {
                "signature_points": sig_points,
                "ml_points": ml_points,
                "lstm_points": lstm_points,
                "autoencoder_points": ae_points,
                "raw_total_points": raw_total
            },
            "signature_result": signature_result,
            "ml_result": ml_result,
            "dl_result": dl_result,
            "recommendation": recommendation
        }

        logger.info(f"Risk Evaluation [{http_method}] {endpoint_url} -> Score: {normalized_score}/100 ({severity})")
        return result_summary


if __name__ == "__main__":
    scorer = RiskScorer()
    
    mock_sig = {"matched": True, "attack_type": "SQL_Injection", "points": 90, "pattern_matched": "1=1"}
    mock_ml = {"is_anomaly": True, "anomaly_score": 0.65, "points": 26.0}
    mock_dl = {"lstm_probability": 0.85, "lstm_points": 25.5, "autoencoder_points": 18.0}

    res = scorer.calculate_risk(mock_sig, mock_ml, mock_dl, "http://localhost:5000/api/users", "GET")
    print("\n[+] Risk Scorer Output:")
    for k, v in res.items():
        print(f"  {k}: {v}")
