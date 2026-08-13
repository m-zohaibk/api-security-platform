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
        r"(?i)\bpassword\b\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)\bsecret_key\b\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)\baccess_token\b\s*[:=]\s*[\"'][^\"']+[\"']",
        r"(?i)\bapi_key\b\s*[:=]\s*[\"'][^\"']+[\"']"
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

    def analyze(self, telemetry_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes telemetry for Layer 1 rules with Response Verification Gates.
        Filters out WAF/Proxy blocks (403, 429, 202 0-byte) and verifies response reflection/errors.
        """
        url = telemetry_data.get("url", "")
        payload = telemetry_data.get("payload", "") or ""
        resp_status = telemetry_data.get("status_code", 200)
        resp_size = telemetry_data.get("response_size", 0)
        resp_headers = telemetry_data.get("response_headers", {}) or {}
        resp_body = telemetry_data.get("response_body", "") or ""

        target_string = f"{url} {payload}"
        content_type = str(resp_headers.get("content-type", "") or resp_headers.get("Content-Type", "")).lower()

        # Gate 1: WAF & Edge Block Filter
        if resp_status in [403, 429] or (resp_status == 202 and resp_size == 0):
            return {
                "matched": False,
                "attack_type": "Request_Filtered_WAF",
                "pattern_matched": f"HTTP {resp_status} WAF Block / Asynchronous 0-byte filter",
                "confidence": "Low",
                "points": 5,
                "missing_headers": []
            }

        matched = False
        attack_type = "None"
        pattern_matched = ""
        confidence = "Low"
        points = 0

        # Check regex attack patterns
        candidate_category = None
        candidate_rule = ""
        for category, rules in self.REGEX_RULES.items():
            for rule in rules:
                if re.search(rule, target_string):
                    candidate_category = category
                    candidate_rule = rule
                    break
            if candidate_category:
                break

        if not candidate_category:
            category_mapping = {
                "sqli": "SQL_Injection",
                "xss": "XSS",
                "cmd_injection": "Command_Injection",
                "bola": "BOLA_IDOR",
                "auth": "Auth_Weakness"
            }
            for raw_cat, pattern_list in self.custom_patterns.items():
                for pat in pattern_list:
                    if pat and pat in target_string:
                        candidate_category = category_mapping.get(raw_cat.lower(), raw_cat.upper())
                        candidate_rule = pat
                        break
                if candidate_category:
                    break

        # Gate 2: Response Verification Criteria for Candidate Attack Payload Match
        if candidate_category:
            matched = True
            attack_type = candidate_category
            pattern_matched = candidate_rule

            if candidate_category == "XSS":
                # Verbatim unescaped Reflection check in HTML body
                if payload and payload in resp_body and "text/html" in content_type and resp_size > 0:
                    confidence = "High"
                    points = 90
                else:
                    confidence = "Low"
                    points = 15  # Unverified payload syntax match

            elif candidate_category == "SQL_Injection":
                # Error-based SQL trace verification in response body
                sql_error_found = any(re.search(err, resp_body) for err in self.SQL_ERROR_PATTERNS)
                if sql_error_found:
                    confidence = "High"
                    points = 90
                else:
                    confidence = "Low"
                    points = 20  # Unverified SQL parameter match

            elif candidate_category == "Command_Injection":
                cmd_out_found = any(re.search(cmd_pat, resp_body) for cmd_pat in self.CMD_OUTPUT_PATTERNS)
                if cmd_out_found:
                    confidence = "High"
                    points = 90
                else:
                    confidence = "Low"
                    points = 20

            elif candidate_category in ["BOLA_IDOR", "Auth_Weakness"]:
                if resp_status in [200, 201]:
                    confidence = "Medium"
                    points = 60
                else:
                    confidence = "Low"
                    points = 20

        # Check for verbose stack traces in response body if not matched
        if not matched:
            for err_pat in self.VERBOSE_ERROR_PATTERNS:
                if re.search(err_pat, resp_body):
                    matched = True
                    attack_type = "Verbose_Error_Exposure"
                    pattern_matched = err_pat
                    confidence = "Medium"
                    points = 65
                    break

        # Check for sensitive data exposure
        if not matched:
            for sens_pat in self.SENSITIVE_DATA_PATTERNS:
                if re.search(sens_pat, resp_body):
                    matched = True
                    attack_type = "Sensitive_Data_Exposure"
                    pattern_matched = sens_pat
                    confidence = "High"
                    points = 85
                    break

        # Check missing security headers
        missing_headers = []
        resp_headers_lower = {k.lower(): v for k, v in resp_headers.items()}
        for req_h in self.REQUIRED_SECURITY_HEADERS:
            if req_h.lower() not in resp_headers_lower:
                missing_headers.append(req_h)

        if not matched and missing_headers:
            matched = True
            attack_type = "Security_Misconfiguration"
            pattern_matched = f"Missing headers: {', '.join(missing_headers)}"
            confidence = "Low"
            points = 25

        return {
            "matched": matched,
            "attack_type": attack_type,
            "pattern_matched": pattern_matched,
            "confidence": confidence,
            "points": min(points, 90),
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
