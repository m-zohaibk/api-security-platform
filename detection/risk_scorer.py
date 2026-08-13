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

    MAX_SIG_POINTS = 40.0
    MAX_ML_POINTS = 25.0
    MAX_LSTM_POINTS = 15.0
    MAX_AE_POINTS = 20.0
    MAX_TOTAL_POINTS = 100.0

    SEVERITY_RECOMMENDATIONS = {
        "Low": "Baseline telemetry parameters normal. Maintain routine security monitoring and header hardening.",
        "Medium": "Elevated structural anomaly or header misconfiguration detected. Audit API endpoint input parameters.",
        "High": "Significant anomaly or signature match detected. Review input validation and database query parameterization.",
        "Critical": "Critical attack pattern detected across multiple engine layers. Immediately enforce WAF filtering and remediate underlying endpoint code."
    }

    @staticmethod
    def classify_severity(score: float) -> str:
        if score >= 85.0:
            return "CRITICAL"
        elif score >= 60.0:
            return "HIGH"
        elif score >= 30.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "NONE"

    def calculate_risk(
        self,
        signature_result: Dict[str, Any],
        ml_result: Dict[str, Any],
        dl_result: Dict[str, Any],
        endpoint_url: str = "",
        http_method: str = "GET",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Calculates recalibrated combined risk score from all 3 detection layers using Proof Multiplier.
        Section 1: Hard Response Gate (Circuit Breaker)
        Section 4: Recalibrated Scoring Formula (Raw_ML_Score * Proof_Multiplier)
        Section 5: Output Struct (is_vulnerable, risk_score, severity, proof_of_concept, telemetry_status)
        """
        telemetry = kwargs.get("telemetry_data", {}) or {}
        resp_status = telemetry.get("status_code", kwargs.get("status_code", 200))
        resp_size = telemetry.get("response_size", kwargs.get("response_size", 0))
        resp_time = telemetry.get("response_time", kwargs.get("response_time", 0.0))

        # Section 1: Hard Response Gate (Circuit Breaker)
        # Status 0 or None -> UNREACHABLE / NETWORK_DROPPED
        if resp_status in [0, None]:
            timestamp = datetime.utcnow().isoformat() + "Z"
            return {
                "endpoint": endpoint_url,
                "method": http_method.upper(),
                "timestamp": timestamp,
                "is_vulnerable": False,
                "total_score": 0.0,
                "risk_score": 0.0,
                "severity": "NONE",
                "finding_status": "UNREACHABLE / NETWORK_DROPPED",
                "proof_of_concept": "HTTP request failed or network connection dropped (Status 0/None)",
                "telemetry_status": {
                    "status_code": resp_status,
                    "response_size": resp_size,
                    "response_time": resp_time
                },
                "points_breakdown": {
                    "signature_points": 0.0,
                    "ml_points": 0.0,
                    "lstm_points": 0.0,
                    "autoencoder_points": 0.0,
                    "raw_total_points": 0.0
                },
                "signature_result": signature_result,
                "ml_result": ml_result,
                "dl_result": dl_result,
                "recommendation": self.SEVERITY_RECOMMENDATIONS["Low"]
            }

        # Status 403, 404, 429, 502, 503, 504 -> BLOCKED_OR_NOT_FOUND
        if resp_status in [403, 404, 429, 502, 503, 504] or (resp_status == 202 and resp_size == 0):
            timestamp = datetime.utcnow().isoformat() + "Z"
            status_desc = "Resource Not Found" if resp_status == 404 else "WAF / Edge Block"
            return {
                "endpoint": endpoint_url,
                "method": http_method.upper(),
                "timestamp": timestamp,
                "is_vulnerable": False,
                "total_score": 0.0,
                "risk_score": 0.0,
                "severity": "NONE",
                "finding_status": "BLOCKED_OR_NOT_FOUND",
                "proof_of_concept": f"HTTP {resp_status} {status_desc} - Request dropped or endpoint non-existent",
                "telemetry_status": {
                    "status_code": resp_status,
                    "response_size": resp_size,
                    "response_time": resp_time
                },
                "points_breakdown": {
                    "signature_points": 0.0,
                    "ml_points": 0.0,
                    "lstm_points": 0.0,
                    "autoencoder_points": 0.0,
                    "raw_total_points": 0.0
                },
                "signature_result": signature_result,
                "ml_result": ml_result,
                "dl_result": dl_result,
                "recommendation": self.SEVERITY_RECOMMENDATIONS["Low"]
            }

        # Section 4: Layer Point Calculations & Proof Multiplier
        sig_points = min(float(signature_result.get("points", 0.0)), self.MAX_SIG_POINTS)
        ml_points = min(float(ml_result.get("points", 0.0)), self.MAX_ML_POINTS)
        lstm_points = min(float(dl_result.get("lstm_points", 0.0)), self.MAX_LSTM_POINTS)
        ae_points = min(float(dl_result.get("autoencoder_points", 0.0)), self.MAX_AE_POINTS)

        raw_ml_score = sig_points + ml_points + lstm_points + ae_points
        raw_total = min(self.MAX_TOTAL_POINTS, raw_ml_score)

        # Vulnerability Proof Multiplier (Section 4)
        has_proof = signature_result.get("has_proof", False)
        payload_had_effect = kwargs.get("payload_had_effect", True)

        if has_proof:
            proof_multiplier = 1.0
        elif not payload_had_effect:
            proof_multiplier = 0.0  # Payload had zero response differential effect
        else:
            proof_multiplier = 0.0  # No response proof criteria met

        final_risk_score = round(raw_total * proof_multiplier, 2)
        severity = self.classify_severity(final_risk_score)

        is_vulnerable = has_proof and final_risk_score > 0.0
        finding_status = signature_result.get("finding_status", "Informational")
        if is_vulnerable:
            finding_status = "Confirmed"
        elif final_risk_score == 0.0:
            finding_status = "Informational"

        rec_key = severity.capitalize() if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else "Low"
        recommendation = self.SEVERITY_RECOMMENDATIONS.get(rec_key, self.SEVERITY_RECOMMENDATIONS["Low"])
        timestamp = datetime.utcnow().isoformat() + "Z"

        proof_poc = signature_result.get("proof_of_concept", "")
        if not proof_poc:
            proof_poc = "Vulnerability proof verified" if is_vulnerable else "No vulnerability proof criteria met"

        result_summary = {
            "endpoint": endpoint_url,
            "method": http_method.upper(),
            "timestamp": timestamp,
            "is_vulnerable": is_vulnerable,
            "total_score": final_risk_score,
            "risk_score": final_risk_score,
            "severity": severity,
            "finding_status": finding_status,
            "proof_of_concept": proof_poc,
            "telemetry_status": {
                "status_code": resp_status,
                "response_size": resp_size,
                "response_time": resp_time
            },
            "points_breakdown": {
                "signature_points": sig_points,
                "ml_points": ml_points,
                "lstm_points": lstm_points,
                "autoencoder_points": ae_points,
                "raw_total_points": raw_total,
                "proof_multiplier": proof_multiplier
            },
            "signature_result": signature_result,
            "ml_result": ml_result,
            "dl_result": dl_result,
            "recommendation": recommendation
        }

        logger.info(f"Risk Evaluation [{http_method}] {endpoint_url} -> Score: {final_risk_score}/100 ({severity}) [Proof: {is_vulnerable}]")
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
