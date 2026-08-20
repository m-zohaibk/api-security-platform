import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.discovery import EndpointDiscovery


def main():
    endpoints = EndpointDiscovery("https://pentest-ground.com:4280", timeout=10, max_depth=0).discover()
    for endpoint in endpoints:
        path = endpoint.get("url", "").lower()
        if any(name in path for name in ("/exec/", "/sqli/", "/xss_d/", "/xss_r/", "/xss_s/")):
            print(json.dumps(endpoint, sort_keys=True))


if __name__ == "__main__":
    main()
