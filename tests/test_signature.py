import pytest
from detection.signature import SignatureDetector

def test_signature_sqli_detection():
    detector = SignatureDetector()
    
    # Confirmed SQLi Error Response
    sample_confirmed = {
        "url": "http://localhost:5000/api/users?id=1' OR 1=1 --",
        "payload": "",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"error\":\"SQLAlchemyError: syntax error at or near OR\"}"
    }
    res_conf = detector.analyze(sample_confirmed)
    assert res_conf["matched"] is True
    assert res_conf["attack_type"] == "SQL_Injection"
    assert res_conf["confidence"] == "High"
    assert res_conf["points"] == 90

    # Unconfirmed SQLi Parameter Match
    sample_unconfirmed = {
        "url": "http://localhost:5000/api/users?id=1' OR 1=1 --",
        "payload": "",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"status\":\"ok\"}"
    }
    res_unconf = detector.analyze(sample_unconfirmed)
    assert res_unconf["matched"] is True
    assert res_unconf["attack_type"] == "SQL_Injection"
    assert res_unconf["confidence"] == "Low"
    assert res_unconf["points"] == 20

def test_signature_xss_detection():
    detector = SignatureDetector()

    # Confirmed Reflected XSS Response
    sample_reflected = {
        "url": "http://localhost:5000/search",
        "payload": "<script>alert(1)</script>",
        "status_code": 200,
        "response_size": 250,
        "response_headers": {"Content-Type": "text/html"},
        "response_body": "<html><body>Search result: <script>alert(1)</script></body></html>"
    }
    res_refl = detector.analyze(sample_reflected)
    assert res_refl["matched"] is True
    assert res_refl["attack_type"] == "XSS"
    assert res_refl["confidence"] == "High"
    assert res_refl["points"] == 90

    # Unreflected XSS Request
    sample_unreflected = {
        "url": "http://localhost:5000/search",
        "payload": "<script>alert(1)</script>",
        "status_code": 200,
        "response_size": 50,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"status\":\"accepted\"}"
    }
    res_unrefl = detector.analyze(sample_unreflected)
    assert res_unrefl["matched"] is True
    assert res_unrefl["attack_type"] == "XSS"
    assert res_unrefl["confidence"] == "Low"
    assert res_unrefl["points"] == 15

def test_waf_status_code_filter():
    detector = SignatureDetector()
    sample_waf = {
        "url": "http://localhost:5000/search",
        "payload": "<script>alert(1)</script>",
        "status_code": 403,
        "response_size": 0,
        "response_headers": {},
        "response_body": ""
    }
    result = detector.analyze(sample_waf)
    assert result["matched"] is False
    assert result["attack_type"] == "Request_Filtered_WAF"
    assert result["points"] == 5

def test_signature_missing_headers():
    detector = SignatureDetector()
    sample = {
        "url": "http://localhost:5000/api/normal",
        "payload": "normal_string",
        "status_code": 200,
        "response_size": 100,
        "response_headers": {"Server": "Werkzeug"},
        "response_body": "{\"status\":\"ok\"}"
    }
    result = detector.analyze(sample)
    assert result["matched"] is True
    assert result["attack_type"] == "Security_Misconfiguration"
    assert len(result["missing_headers"]) > 0
