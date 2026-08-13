import os
import re
import sys
from typing import Dict, Any, List, Optional
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import logger
from config.settings import PAYLOADS_DIR

class SignatureDetector:
    """
    Layer 1 — Signature & Response Verification Detection Engine
    Analyzes HTTP telemetry for known attack patterns, enforces response verification gates
    (reflection checks, SQL error traces, WAF status code filtering), security header misconfigurations,
    and sensitive field leaks.
    """

    REGEX_RULES = {
        "SQL_Injection": [
            r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|HAVING)\b)",
            r"(?i)('|\"|;|\bOR\b|\bAND\b)\s*1\s*=\s*1",
            r"(?i)--\s*$",
            r"(?i)\bSLEEP\s*\(\s*\d+\s*\)",
            r"(?i)\bBENCHMARK\s*\("
        ],
        "XSS": [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)javascript\s*:",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)<iframe[^>]*>"
        ],
        "Command_Injection": [
            r";\s*(cat|ls|whoami|id|pwd|uname|netstat)\b",
            r"\|\s*(cat|ls|whoami|id|pwd|uname)\b",
            r"`.*`",
            r"\$\(.*\)"
        ],
        "BOLA_IDOR": [
            r"/users?/\d+",
            r"/accounts?/\d+",
            r"id=\d+"
        ],
        "Auth_Weakness": [
            r"(?i)bearer\s+null",
            r"(?i)bearer\s+undefined",
            r"(?i)alg\s*:\s*\"?none\"?"
        ]
    }

    SQL_ERROR_PATTERNS = [
        r"(?i)SQLAlchemyError",
        r"(?i)SyntaxError.*SQL",
        r"(?i)MySQL server version",
        r"(?i)SQLite3::SQLException",
        r"(?i)ORA-\d{5}",
        r"(?i)PostgreSQL.*ERROR",
        r"(?i)PG::SyntaxError",
        r"(?i)Microsoft OLE DB Provider for SQL Server",
        r"(?i)unclosed quotation mark after the character string"
    ]

    CMD_OUTPUT_PATTERNS = [
        r"root:x:0:0:",
        r"uid=\d+\(.*\)\s+gid=\d+",
        r"Linux\s+[\w\.-]+\s+\d+\.\d+",
        r"Windows\s+IP\s+Configuration"
    ]

    REQUIRED_SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]

    VERBOSE_ERROR_PATTERNS = [
        r"Traceback \(most recent call last\):",
        r"SyntaxError:",
        r"SQLAlchemyError",
        r"Fatal error:",
        r"Uncaught Exception",
        r"ZeroDivisionError",
        r"NullPointerException"
    ]

    SENSITIVE_DATA_PATTERNS = [
        r"(?i)[\"']?password[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)[\"']?secret_key[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)[\"']?access_token[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)[\"']?api_key[\"']?\s*[:=]\s*[\"'][^\"']+[\"']"
    ]

    def __init__(self, payloads_dir: Optional[str] = None):
        self.payloads_dir = Path(payloads_dir) if payloads_dir else Path(PAYLOADS_DIR)
        self.custom_patterns: Dict[str, List[str]] = self._load_payload_patterns()

    def _load_payload_patterns(self) -> Dict[str, List[str]]:
        patterns = {}
        if not self.payloads_dir.exists():
            return patterns

        for file_name in ["sqli.txt", "xss.txt", "cmd_injection.txt", "bola.txt", "auth.txt"]:
            file_path = self.payloads_dir / file_name
            category = file_name.replace(".txt", "")
            patterns[category] = []
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_clean = line.strip()
                        if line_clean and not line_clean.startswith("#"):
                            patterns[category].append(line_clean)
        return patterns

    def analyze(self, telemetry_data: Dict[str, Any], baseline_telemetry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyzes HTTP telemetry for known attack patterns and enforces strict Proof Verifiers.
        Enforces Hard Circuit-Breaker Gates (status 0, None, 403, 404, 429, 502, 503, 504).
        Returns telemetry proof status, proof description, points, and vulnerability classification.
        """
        url = telemetry_data.get("url", "")
        payload = telemetry_data.get("payload", "") or ""
        resp_status = telemetry_data.get("status_code", 200)
        resp_size = telemetry_data.get("response_size", 0)
        resp_time = telemetry_data.get("response_time", 0.0)
        resp_headers = telemetry_data.get("response_headers", {}) or {}
        resp_body = telemetry_data.get("response_body", "") or ""

        target_string = f"{url} {payload}"
        content_type = str(resp_headers.get("content-type", "") or resp_headers.get("Content-Type", "")).lower()

        # Hard Response Gate 1: Network / Unreachable / Status 0 or None
        if resp_status in [0, None]:
            return {
                "matched": False,
                "has_proof": False,
                "is_vulnerable": False,
                "attack_type": "Network_Error",
                "pattern_matched": "HTTP Status 0 / Network Dropped",
                "finding_status": "UNREACHABLE / NETWORK_DROPPED",
                "confidence": "None",
                "points": 0,
                "proof_of_concept": "HTTP request failed or network connection dropped (Status 0/None)",
                "missing_headers": []
            }

        # Hard Response Gate 2: WAF Block / Edge Block / 404 Not Found
        if resp_status in [403, 404, 429, 502, 503, 504] or (resp_status == 202 and resp_size == 0):
            status_desc = "Resource Not Found" if resp_status == 404 else "WAF / Edge Block"
            return {
                "matched": False,
                "has_proof": False,
                "is_vulnerable": False,
                "attack_type": "None",
                "pattern_matched": f"HTTP {resp_status} {status_desc}",
                "finding_status": "BLOCKED_OR_NOT_FOUND",
                "confidence": "None",
                "points": 0,
                "proof_of_concept": f"HTTP {resp_status} {status_desc} - Request blocked or endpoint non-existent",
                "missing_headers": []
            }

        # Check payload syntax matches for injection candidate categories
        candidate_category = None
        candidate_rule = ""
        auth_header_val = telemetry_data.get("request_headers", {}).get("Authorization", "")
        combined_probe_text = f"{target_string} {auth_header_val}"

        for category in ["SQL_Injection", "XSS", "Command_Injection", "Auth_Weakness", "BOLA_IDOR"]:
            rules = self.REGEX_RULES.get(category, [])
            for rule in rules:
                if re.search(rule, payload) or re.search(rule, combined_probe_text):
                    candidate_category = category
                    candidate_rule = rule
                    break
            if candidate_category:
                break

        has_proof = False
        proof_of_concept = ""
        matched = False
        attack_type = "None"
        pattern_matched = ""
        finding_status = "Informational"
        confidence = "Low"
        points = 0

        # Baseline Differential Comparison
        baseline_time = baseline_telemetry.get("response_time", 0.0) if baseline_telemetry else 0.0
        baseline_size = baseline_telemetry.get("response_size", 0) if baseline_telemetry else 0
        baseline_status = baseline_telemetry.get("status_code", 200) if baseline_telemetry else 200

        time_delta = max(0.0, resp_time - baseline_time)

        # Strict Proof Verifiers Criteria (Section 3)
        if candidate_category:
            attack_type = candidate_category
            pattern_matched = candidate_rule

            if candidate_category == "XSS":
                # Verbatim unescaped Reflection check in text/html or application/xml
                is_html_xml = any(ct in content_type for ct in ["text/html", "application/xml"])
                if payload and payload in resp_body and is_html_xml and resp_size > 0 and resp_status == 200:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Unescaped string reflection detected in {content_type} body"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Payload syntax matched but missing verbatim HTML/XML unescaped reflection"

            elif candidate_category == "SQL_Injection":
                # Error-based SQL trace verification OR Time-based SQLi (time_delta > 3.0s)
                matched_sql_err = next((err for err in self.SQL_ERROR_PATTERNS if re.search(err, resp_body)), None)
                if matched_sql_err:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"SQL Error signature matched: {matched_sql_err}"
                elif time_delta > 3.0:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Time-based SQLi response delay detected: {time_delta:.2f}s > 3.00s"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "SQL parameter payload syntax matched without database error or execution time delay"

            elif candidate_category == "Command_Injection":
                # Shell output signature OR Time-based delay > 3.0s
                matched_cmd_sig = next((cmd_pat for cmd_pat in self.CMD_OUTPUT_PATTERNS if re.search(cmd_pat, resp_body)), None)
                if matched_cmd_sig:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Command execution signature matched: {matched_cmd_sig}"
                elif time_delta > 3.0:
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = f"Time-based Command Injection delay detected: {time_delta:.2f}s > 3.00s"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Command payload syntax matched without shell output or execution delay"

            elif candidate_category == "Auth_Weakness":
                auth_hdr = telemetry_data.get("request_headers", {}).get("Authorization", "")
                is_jwt_alg_none = bool(re.search(r"(?i)alg\s*:\s*\"?none\"?", target_string))
                has_sensitive_data = any(re.search(pat, resp_body, re.I) for pat in [r"\"email\":", r"\"password\":", r"\"admin\":", r"\"token\":"])
                if (resp_status in [200, 201] and (has_sensitive_data or not auth_hdr or is_jwt_alg_none)):
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = "Unauthenticated access or invalid auth token returned sensitive resource telemetry"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Unverified auth parameter payload"

            elif candidate_category == "BOLA_IDOR":
                auth_header = telemetry_data.get("request_headers", {}).get("Authorization", "")
                has_sensitive_data = any(re.search(pat, resp_body, re.I) for pat in [r"\"email\":", r"\"ssn\":", r"\"password\":", r"\"role\":", r"\"token\":", r"\"username\":"])
                if resp_status in [200, 201] and (has_sensitive_data or not auth_header):
                    matched = True
                    has_proof = True
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 40
                    proof_of_concept = "Unauthorized object access returned sensitive object properties in 200 OK body"
                else:
                    matched = True
                    has_proof = False
                    finding_status = "Suspected"
                    confidence = "Low"
                    points = 10
                    proof_of_concept = "Object ID path queried without confirmed sensitive object disclosure"

        # BOLA / IDOR Proof Verification (fallback)
        if not matched and resp_status in [200, 201]:
            has_bola_pattern = any(re.search(r, combined_probe_text) for r in self.REGEX_RULES["BOLA_IDOR"])
            auth_header = telemetry_data.get("request_headers", {}).get("Authorization", "")
            has_sensitive_data = any(re.search(pat, resp_body, re.I) for pat in [r"\"email\":", r"\"ssn\":", r"\"password\":", r"\"role\":", r"\"token\":", r"\"username\":"])

            if has_bola_pattern and (has_sensitive_data or not auth_header):
                matched = True
                has_proof = True
                attack_type = "BOLA_IDOR"
                pattern_matched = "Object ID access returned sensitive user data or succeeded without authorization"
                finding_status = "Confirmed"
                confidence = "High"
                points = 40
                proof_of_concept = "Unauthorized object access returned sensitive object properties in 200 OK body"

        # Verbose Stack Traces Verification
        if not matched and resp_status not in [404, 401, 403, 429, 502, 503, 504]:
            for err_pat in self.VERBOSE_ERROR_PATTERNS:
                if re.search(err_pat, resp_body):
                    matched = True
                    has_proof = True
                    attack_type = "Verbose_Error_Exposure"
                    pattern_matched = err_pat
                    finding_status = "Confirmed"
                    confidence = "Medium"
                    points = 25
                    proof_of_concept = f"Verbose stack trace trace exposed in response: {err_pat}"
                    break

        # Sensitive Data Exposure Verification
        if not matched and resp_status not in [404, 401, 403, 429, 502, 503, 504]:
            for sens_pat in self.SENSITIVE_DATA_PATTERNS:
                if re.search(sens_pat, resp_body):
                    matched = True
                    has_proof = True
                    attack_type = "Sensitive_Data_Exposure"
                    pattern_matched = sens_pat
                    finding_status = "Confirmed"
                    confidence = "High"
                    points = 35
                    proof_of_concept = f"Sensitive credentials exposed in response: {sens_pat}"
                    break

        # Missing Security Headers Check
        missing_headers = []
        resp_headers_lower = {k.lower(): v for k, v in resp_headers.items()}
        for req_h in self.REQUIRED_SECURITY_HEADERS:
            if req_h.lower() not in resp_headers_lower:
                missing_headers.append(req_h)

        if not matched and missing_headers and resp_status not in [404, 401, 403, 406, 429, 502, 503, 504]:
            matched = True
            has_proof = False  # Header misconfigurations do not constitute injection exploit proof
            attack_type = "Security_Misconfiguration"
            pattern_matched = f"Missing headers: {', '.join(missing_headers)}"
            finding_status = "Informational"
            confidence = "Low"
            points = 10
            proof_of_concept = f"Missing security headers: {', '.join(missing_headers)}"

        return {
            "matched": matched,
            "has_proof": has_proof,
            "is_vulnerable": has_proof and points > 0,
            "attack_type": attack_type,
            "pattern_matched": pattern_matched,
            "finding_status": finding_status,
            "confidence": confidence,
            "points": min(points, 40),
            "proof_of_concept": proof_of_concept or ("No vulnerability proof criteria met" if not has_proof else "Vulnerability proof verified"),
            "missing_headers": missing_headers
        }


if __name__ == "__main__":
    detector = SignatureDetector()
    sample_data = {
        "url": "http://localhost:5000/api/users?id=1' OR 1=1 --",
        "payload": "",
        "status_code": 200,
        "response_size": 120,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": "{\"error\":\"SQLAlchemyError: syntax error at or near OR\"}"
    }
    result = detector.analyze(sample_data)
    print("\n[+] Confirmed Response Verification Test Result:")
    for k, v in result.items():
        print(f"  {k}: {v}")
