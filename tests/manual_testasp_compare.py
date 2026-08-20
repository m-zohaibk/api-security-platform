import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

BASE_URL = "http://testasp.vulnweb.com"
ENDPOINTS = [
    "http://testasp.vulnweb.com",
    "http://testasp.vulnweb.com/Templatize.asp?item=html/about.html",
    "http://testasp.vulnweb.com/Default.asp",
    "http://testasp.vulnweb.com/Search.asp",
    "http://testasp.vulnweb.com/Login.asp?RetURL=%2FSearch%2Easp%3F",
]
REQUIRED_HEADERS = [
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
]
QUEUE = [
    ("SQL_Injection", "POST", '{"username": "admin\' OR 1=1 --", "password": "pass"}', {"Content-Type": "application/json"}),
    ("SQL_Injection_GET", "GET", "' OR 1=1 --", {}),
    ("Cross_Site_Scripting", "POST", "<script>alert('xss')</script>", {}),
    ("Command_Injection", "GET", "; cat /etc/passwd", {}),
    ("Broken_Authentication", "GET", "", {"Authorization": "Bearer null"}),
    ("BOLA_IDOR_1", "GET", "id=1", {}),
    ("BOLA_IDOR_2", "GET", "id=2", {}),
    ("BOLA_IDOR_3", "GET", "id=3", {}),
    ("BOLA_IDOR_999", "GET", "id=999", {}),
    ("Baseline_Inspection", "GET", "", {}),
]
SQL_ERRORS = [r"SQLAlchemyError", r"SQLite3::SQLException", r"syntax error", r"SQL server"]
CMD_OUTPUT = [r"root:x:0:0:", r"uid=\d+\(.*\)\s+gid=\d+"]
SENSITIVE = [r'"email"\s*:', r'"ssn"\s*:', r'"password"\s*:', r'"role"\s*:', r'"token"\s*:', r'"username"\s*:']


def request(client, method, url, payload, headers, endpoint):
    if "Search.asp" in endpoint and method == "GET":
        return client.get(url, params={"tfSearch": payload}, headers=headers)
    if "Login.asp" in endpoint and method == "POST":
        return client.post(url, data={"tfUName": payload, "tfUPass": ""}, headers=headers)
    if method == "GET":
        return client.get(url, params={"q": payload} if payload else None, headers=headers)
    try:
        parsed = json.loads(payload) if payload else None
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        return client.request(method, url, json=parsed, headers=headers)
    return client.request(method, url, content=payload, headers=headers)


def origin_path_url(endpoint, suffix):
    parsed = urlsplit(endpoint)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return origin.rstrip("/") + suffix


def evidence(category, payload, response, baseline, request_headers):
    body = response.text or ""
    content_type = response.headers.get("content-type", "").lower()
    delta = max(0.0, response.elapsed.total_seconds() - baseline.elapsed.total_seconds())
    if category.startswith("BOLA"):
        return response.status_code in (200, 201) and not request_headers.get("Authorization") and any(re.search(p, body, re.I) for p in SENSITIVE)
    if category == "Cross_Site_Scripting":
        return response.status_code == 200 and payload in body and any(t in content_type for t in ("text/html", "application/xml"))
    if category.startswith("SQL_Injection"):
        return any(re.search(p, body, re.I) for p in SQL_ERRORS) or delta > 3.0
    if category == "Command_Injection":
        return any(re.search(p, body, re.I) for p in CMD_OUTPUT) or delta > 3.0
    if category == "Broken_Authentication":
        return response.status_code in (200, 201) and "Bearer null" in request_headers.get("Authorization", "") and any(re.search(p, body, re.I) for p in SENSITIVE)
    return False


def main():
    rows = []
    with httpx.Client(timeout=12, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-ManualVerification/1.0"}) as client:
        for endpoint in ENDPOINTS:
            try:
                baseline = client.get(endpoint)
                baseline_status = baseline.status_code
                baseline_size = len(baseline.content)
                missing = [h for h in REQUIRED_HEADERS if h not in {k.lower() for k in baseline.headers}]
            except httpx.HTTPError:
                baseline = None
                baseline_status = 0
                baseline_size = 0
                missing = []
            confirmed_categories = []
            max_score = 0.0
            transport_errors = 0
            for category, method, payload, headers in QUEUE:
                test_url = endpoint
                if category.startswith("BOLA"):
                    suffix = "/users/v1/" + category.rsplit("_", 1)[-1]
                    test_url = origin_path_url(endpoint, suffix)
                try:
                    response = request(client, method, test_url, payload, headers, endpoint)
                    proof = evidence(category, payload, response, baseline, headers)
                    status = response.status_code
                    error = None
                except httpx.HTTPError as exc:
                    proof = False
                    status = 0
                    error = str(exc)
                if proof:
                    confirmed_categories.append(category)
                    max_score = max(max_score, 14.0)  # one confirmed layer: 40 * 0.35
                if status == 0:
                    error = error or "connection reset"
                    transport_errors += 1
                # Keep transport outcomes in the evidence record without
                # turning them into confirmed vulnerabilities.
            manual_score = max_score if max_score else (3.5 if missing else 0.0)
            rows.append({
                "endpoint": endpoint,
                "baseline_status": baseline_status,
                "baseline_size": baseline_size,
                "missing_security_headers": missing,
                "confirmed_categories": confirmed_categories,
                "manual_confirmed": bool(confirmed_categories),
                "manual_score": manual_score,
                "transport_errors": transport_errors,
            })
    result = {
        "target": BASE_URL,
        "endpoint_count": len(rows),
        "manual_confirmed_count": sum(1 for r in rows if r["manual_confirmed"]),
        "manual_max_score": max(r["manual_score"] for r in rows),
        "rows": rows,
    }
    Path("/home/ubuntu/api-security-platform/tests/testasp_manual_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
