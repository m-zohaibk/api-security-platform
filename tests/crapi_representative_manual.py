import json
import time
from pathlib import Path
import httpx

BASE = "http://crapi.apisec.ai"


def request(client, method, path, **kwargs):
    started = time.perf_counter()
    try:
        response = client.request(method, BASE + path, **kwargs)
        return {
            "status": response.status_code,
            "elapsed": round(time.perf_counter() - started, 4),
            "size": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "body_preview": response.text[:400],
            "headers": {k.lower(): v for k, v in response.headers.items()},
            "error": None,
        }
    except httpx.HTTPError as exc:
        return {"status": 0, "elapsed": round(time.perf_counter() - started, 4), "size": 0, "content_type": "", "body_preview": "", "headers": {}, "error": str(exc)}


def main():
    with httpx.Client(timeout=45, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-IndependentVerification/1.0"}) as client:
        health = request(client, "GET", "/health")
        public_api = request(client, "GET", "/api/Feedbacks")
        public_api_probe = request(client, "GET", "/api/Feedbacks", params={"q": "' OR 1=1 --"})
        graphql = request(client, "POST", "/graphql", json={"query": "{ __schema { queryType { fields { name } } } }"})
        identity_baseline = request(client, "POST", "/identity/api/auth/login", json={"email": "nobody-test@example.com", "password": "definitely-not-a-real-password"})
        identity_probe = request(client, "POST", "/identity/api/auth/login", json={"email": "nobody-test@example.com", "password": "x' OR '1'='1"})
    result = {
        "health": health,
        "public_api": public_api,
        "public_api_probe": public_api_probe,
        "public_api_probe_delta": {"status_changed": public_api["status"] != public_api_probe["status"], "size_delta": public_api_probe["size"] - public_api["size"]},
        "graphql": graphql,
        "identity_baseline": identity_baseline,
        "identity_probe": identity_probe,
        "identity_probe_delta": {"status_changed": identity_baseline["status"] != identity_probe["status"], "size_delta": identity_probe["size"] - identity_baseline["size"], "time_delta": round(identity_probe["elapsed"] - identity_baseline["elapsed"], 4)},
    }
    Path("tests/crapi_representative_manual_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
