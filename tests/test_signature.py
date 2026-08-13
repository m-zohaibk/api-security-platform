import pytest
from detection.signature import SignatureDetector

def test_signature_sqli_detection():
    detector = SignatureDetector()
    
    # Confirmed SQLi Error Response
    sample_confirmed = {
        "url": "http://localhost:5000/api/users?id=1",
        "payload": "1' OR 1=1 --",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"error\":\"SQLAlchemyError: syntax error at or near OR\"}"
    }
    res_conf = detector.analyze(sample_confirmed)
    assert res_conf["matched"] is True
    assert res_conf["attack_type"] == "SQL_Injection"
    assert res_conf["finding_status"] == "Confirmed"
    assert res_conf["confidence"] == "High"
    assert res_conf["points"] == 40

    # Unconfirmed / Suspected SQLi Parameter Match
    sample_unconfirmed = {
        "url": "http://localhost:5000/api/users?id=1",
        "payload": "1' OR 1=1 --",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"status\":\"ok\"}"
    }
    res_unconf = detector.analyze(sample_unconfirmed)
    assert res_unconf["matched"] is True
    assert res_unconf["attack_type"] == "SQL_Injection"
    assert res_unconf["finding_status"] == "Suspected"
    assert res_unconf["confidence"] == "Low"
    assert res_unconf["points"] == 10

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
    assert res_refl["finding_status"] == "Confirmed"
    assert res_refl["confidence"] == "High"
    assert res_refl["points"] == 40

def test_waf_status_code_filter():
    detector = SignatureDetector()
    for waf_status, waf_size in [(403, 0), (429, 0), (202, 0), (502, 0), (503, 0)]:
        sample_waf = {
            "url": "http://localhost:5000/search",
            "payload": "<script>alert(1)</script>",
            "status_code": waf_status,
            "response_size": waf_size,
            "response_headers": {},
            "response_body": ""
        }
        result = detector.analyze(sample_waf)
        assert result["matched"] is False
        assert result["has_proof"] is False
        assert result["finding_status"] == "BLOCKED_OR_NOT_FOUND"
        assert result["points"] == 0

def test_network_dropped_circuit_breaker():
    detector = SignatureDetector()
    sample_zero = {
        "url": "http://localhost:5000/search",
        "payload": "<script>alert(1)</script>",
        "status_code": 0,
        "response_size": 0,
        "response_headers": {},
        "response_body": ""
    }
    result = detector.analyze(sample_zero)
    assert result["matched"] is False
    assert result["has_proof"] is False
    assert result["finding_status"] == "UNREACHABLE / NETWORK_DROPPED"
    assert result["points"] == 0

def test_404_response_filter():
    detector = SignatureDetector()
    sample_404 = {
        "url": "http://localhost:5000/nonexistent",
        "payload": "' OR 1=1 --",
        "status_code": 404,
        "response_size": 21145,
        "response_headers": {},
        "response_body": "Not found"
    }
    result = detector.analyze(sample_404)
    assert result["matched"] is False
    assert result["has_proof"] is False
    assert result["finding_status"] == "BLOCKED_OR_NOT_FOUND"
    assert result["points"] == 0

def test_bola_verification_rules():
    detector = SignatureDetector()
    
    # 404 response on numeric ID URL should NOT produce BOLA finding
    sample_404 = {
        "url": "http://localhost:5000/users/9999",
        "payload": "",
        "status_code": 404,
        "response_size": 20,
        "response_headers": {},
        "response_body": "Not found"
    }
    res_404 = detector.analyze(sample_404)
    assert res_404["attack_type"] != "BOLA_IDOR"

    # Confirmed BOLA: HTTP 200 returning sensitive user object properties
    sample_bola_confirmed = {
        "url": "http://localhost:5000/users/2",
        "payload": "",
        "status_code": 200,
        "response_size": 150,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"id\":2, \"username\":\"alice\", \"email\":\"alice@example.com\", \"role\":\"admin\"}"
    }
    res_bola = detector.analyze(sample_bola_confirmed)
    assert res_bola["matched"] is True
    assert res_bola["attack_type"] == "BOLA_IDOR"
    assert res_bola["finding_status"] == "Confirmed"
    assert res_bola["points"] == 40

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

