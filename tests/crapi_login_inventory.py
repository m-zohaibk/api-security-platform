import json
from pathlib import Path
import httpx

BASE = "http://crapi.apisec.ai"


def main():
    result = {"base": BASE, "openapi": None, "login_page": None}
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-PassiveInspection/1.0"}) as client:
        for path in ["/openapi.json", "/api/openapi.json", "/api/swagger.json"]:
            response = client.get(BASE + path)
            if response.status_code == 200 and "json" in response.headers.get("content-type", "").lower():
                try:
                    spec = response.json()
                except ValueError:
                    continue
                if isinstance(spec, dict) and ("paths" in spec or "openapi" in spec or "swagger" in spec):
                    result["openapi"] = {"path": path, "status": response.status_code, "paths": spec.get("paths", {})}
                    break
        login = client.get(BASE + "/login")
        result["login_page"] = {"status": login.status_code, "content_type": login.headers.get("content-type", ""), "size": len(login.content)}
    Path("tests/crapi_login_inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
