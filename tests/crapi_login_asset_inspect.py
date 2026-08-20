import json
import re
from pathlib import Path
from urllib.parse import urljoin
import httpx

BASE = "http://crapi.apisec.ai"


def main():
    findings = {"assets": [], "login_context": []}
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-PassiveInspection/1.0"}) as client:
        html = client.get(BASE + "/login").text
        assets = sorted(set(re.findall(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)', html)))
        for asset in assets:
            url = urljoin(BASE + "/login", asset)
            text = client.get(url).text
            findings["assets"].append({"url": url, "size": len(text)})
            for match in re.finditer(r".{0,180}(?:login|Login|/identity|/auth).{0,260}", text):
                findings["login_context"].append(match.group(0))
    Path("tests/crapi_login_asset_context.json").write_text(json.dumps(findings, indent=2) + "\n")
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
