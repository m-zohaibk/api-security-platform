import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.discovery import EndpointDiscovery


def main():
    endpoints = EndpointDiscovery("http://crapi.apisec.ai", timeout=10, max_depth=2).discover()
    safe = []
    excluded = []
    for endpoint in endpoints:
        url = endpoint.get("url", "")
        path = url.split("?", 1)[0].lower()
        method = endpoint.get("method", "GET").upper()
        # Exclude state-changing or credential-related paths from active testing.
        if method not in {"GET", "HEAD", "OPTIONS"} or any(token in path for token in ("/login", "/signup", "/register", "/forgot", "/password", "/refresh", "/delete", "/remove", "/create", "/update", "/verify")):
            excluded.append(endpoint)
        else:
            safe.append(endpoint)
    result = {"all_discovered": endpoints, "safe_read_only": safe, "excluded": excluded}
    Path("tests/crapi_discovery_inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"all_count": len(endpoints), "safe_count": len(safe), "excluded_count": len(excluded), "safe": safe, "excluded": excluded}, indent=2))


if __name__ == "__main__":
    main()
