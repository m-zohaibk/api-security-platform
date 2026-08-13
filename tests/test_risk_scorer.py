import pytest
from detection.risk_scorer import RiskScorer

def test_risk_scorer_calculations():
    scorer = RiskScorer()
    
    mock_sig = {"matched": True, "attack_type": "SQL_Injection", "points": 90}
    mock_ml = {"is_anomaly": True, "anomaly_score": 0.5, "points": 20.0}
    mock_dl = {"lstm_probability": 0.5, "lstm_points": 15.0, "autoencoder_points": 10.0}

    res = scorer.calculate_risk(mock_sig, mock_ml, mock_dl, "http://localhost/api", "GET")
    
    assert res["total_score"] > 0
    assert res["severity"] in ["Low", "Medium", "High", "Critical"]
    assert "recommendation" in res
    assert res["points_breakdown"]["raw_total_points"] == 135.0
    assert res["total_score"] == 75.0 # (135 / 180) * 100
    assert res["severity"] == "High"
