import os
import sys
import glob
import json
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.response_parser import ResponseParser
from config.logging_config import logger
from config.settings import DATASETS_DIR, BASE_DIR

class SelfDataGenerator:
    """
    Sends request traffic to a target API environment (such as VAmPI or localhost),
    captures telemetry data, extracts 12 numerical features, and saves labeled dataset scans.
    """

    TEST_ROUTES = [
        {"path": "/users/v1", "method": "GET", "label": 0},
        {"path": "/users/v1/1", "method": "GET", "label": 0},
        {"path": "/users/v1/debug", "method": "GET", "label": 1},
        {"path": "/users/v1/register", "method": "POST", "body": '{"username":"test_user","password":"password123"}', "label": 0},
        {"path": "/users/v1/login", "method": "POST", "body": '{"username":"admin","password":"admin_password"}', "label": 0},
        {"path": "/users/v1/login", "method": "POST", "body": '{"username":"\' OR 1=1 --","password":"123"}', "label": 1},
        {"path": "/users/v1/1", "method": "DELETE", "label": 1},
        {"path": "/createdb", "method": "GET", "label": 0}
    ]

    def __init__(self, target_base_url: str = "http://localhost:5001", output_dir: str = None):
        self.target_base_url = target_base_url.rstrip("/")
        self.output_dir = Path(output_dir) if output_dir else Path(DATASETS_DIR) / "self_generated"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.parser = ResponseParser()
        self.payloads = self.load_payloads()

    def load_payloads(self) -> Dict[str, List[str]]:
        payloads: Dict[str, List[str]] = {}
        payload_files = glob.glob(str(Path(BASE_DIR) / "payloads" / "*.txt"))
        for file_path in payload_files:
            attack_type = os.path.basename(file_path).replace(".txt", "")
            with open(file_path, "r") as f:
                # Read lines, strip whitespace, and filter out comments and empty lines
                payload_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                payloads[attack_type] = payload_list
        logger.info(f"Loaded {sum(len(p) for p in payloads.values())} payloads from {len(payload_files)} files.")
        return payloads

    def generate_scans(self) -> pd.DataFrame:
        logger.info(f"Connecting to target API environment at {self.target_base_url} to capture telemetry data...")
        print(f"\n[+] Generating self-captured telemetry data from: {self.target_base_url}")

        collected_features = []

        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            # Existing baseline requests
            for route_info in self.TEST_ROUTES:
                target_url = f"{self.target_base_url}{route_info['path']}"
                method = route_info["method"]
                body = route_info.get("body", "")
                label = route_info["label"]

                try:
                    if method == "POST":
                        resp = client.post(target_url, content=body, headers={"Content-Type": "application/json"})
                    elif method == "DELETE":
                        resp = client.delete(target_url)
                    else:
                        resp = client.get(target_url)

                    resp_data = {
                        "method": method, "url": target_url, "payload": body,
                        "status_code": resp.status_code, "response_size": len(resp.content),
                        "response_body": resp.text, "request_headers": dict(resp.request.headers)
                    }
                except httpx.RequestError as exc:
                    logger.warning(f"Unable to reach {target_url}: {exc}. Using simulated telemetry frame.")
                    resp_data = {
                        "method": method, "url": target_url, "payload": body,
                        "status_code": 500, "response_size": 0, "response_body": "",
                        "request_headers": {"User-Agent": "SelfDataGenerator"}
                    }

                features = self.parser.extract_features(resp_data)
                features["label"] = label
                collected_features.append(features)

            # Requests with payloads from files
            for attack_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    # Target POST endpoints that are good candidates for injection
                    for path in ["/users/v1/login", "/users/v1/register"]:
                        target_url = f"{self.target_base_url}{path}"
                        
                        # Inject payload into username field
                        body_user = json.dumps({"username": payload, "password": "password123"})
                        # Inject payload into password field
                        body_pass = json.dumps({"username": "testuser", "password": payload})

                        for body in [body_user, body_pass]:
                            try:
                                resp = client.post(target_url, content=body, headers={"Content-Type": "application/json"})
                                resp_data = {
                                    "method": "POST", "url": target_url, "payload": body,
                                    "status_code": resp.status_code, "response_size": len(resp.content),
                                    "response_body": resp.text, "request_headers": dict(resp.request.headers)
                                }
                            except httpx.RequestError as exc:
                                logger.warning(f"Unable to reach {target_url} with payload: {exc}.")
                                resp_data = {
                                    "method": "POST", "url": target_url, "payload": body,
                                    "status_code": 500, "response_size": 0, "response_body": "",
                                    "request_headers": {"User-Agent": "SelfDataGenerator"}
                                }

                            features = self.parser.extract_features(resp_data)
                            features["label"] = 1  # All payloads from files are considered malicious
                            collected_features.append(features)

        df = pd.DataFrame(collected_features)
        
        # Save output file
        output_file = self.output_dir / "vampi_scans.csv"
        df.to_csv(output_file, index=False)

        print(f"\n[+] Saved {len(df)} self-generated telemetry scans to: {output_file}")
        print(f"    Normal Samples  : {len(df[df['label'] == 0])}")
        print(f"    Anomalous Samples: {len(df[df['label'] == 1])}")

        return df


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5001"
    generator = SelfDataGenerator(target_base_url=target)
    generator.generate_scans()
