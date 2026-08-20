import json
from pathlib import Path
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

BASE = "https://pentest-ground.com:4280/"
ENDPOINTS = [
    "",
    "instructions.php",
    "setup.php",
    "vulnerabilities/brute/",
    "vulnerabilities/exec/",
    "vulnerabilities/csrf/",
    "vulnerabilities/fi/?page=include.php",
    "vulnerabilities/upload/",
    "vulnerabilities/captcha/",
    "vulnerabilities/sqli/",
    "vulnerabilities/sqli_blind/",
    "vulnerabilities/weak_id/",
    "vulnerabilities/xss_d/",
    "vulnerabilities/xss_r/",
    "vulnerabilities/xss_s/",
    "vulnerabilities/csp/",
    "vulnerabilities/javascript/",
    "vulnerabilities/open_redirect/",
    "security.php",
]


def main():
    rows = []
    with httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-Inventory/1.0"}) as client:
        for path in ENDPOINTS:
            url = urljoin(BASE, path)
            try:
                response = client.get(url)
                soup = BeautifulSoup(response.text, "html.parser")
                forms = []
                for form in soup.find_all("form"):
                    fields = []
                    for element in form.find_all(["input", "textarea", "select"]):
                        if element.get("name"):
                            fields.append({"name": element.get("name"), "type": element.get("type", element.name), "value": element.get("value", "")})
                    forms.append({"method": form.get("method", "GET").upper(), "action": urljoin(str(response.url), form.get("action", "")), "fields": fields})
                rows.append({"url": str(response.url), "status": response.status_code, "size": len(response.content), "title": soup.title.get_text(" ", strip=True) if soup.title else "", "forms": forms})
            except httpx.HTTPError as exc:
                rows.append({"url": url, "status": 0, "error": str(exc), "forms": []})
    Path("tests/dvwa_module_inventory.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
