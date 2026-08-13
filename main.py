import argparse
import sys
import os
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.logging_config import logger
from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.signature import SignatureDetector
from detection.ml_model import MLAnomalyDetector
from detection.deep_learning import DeepLearningDetector
from detection.risk_scorer import RiskScorer
from database.db import init_db, SessionLocal, save_scan_session, save_endpoint, save_finding, complete_scan_session
from database.models import ScanSession, Endpoint, Finding, Report

def run_pipeline(target_url: str):
    print("\n" + "="*65)
    print("      API SECURITY & ANOMALY DETECTION PLATFORM")
    print("="*65)
    print(f" Target Base URL : {target_url}\n")

    # Initialize Database
    init_db()

    # 1. Endpoint Discovery
    logger.info("Initializing Endpoint Discovery...")
    discoverer = EndpointDiscovery(base_url=target_url)
    discovered_endpoints = discoverer.discover()

    if not discovered_endpoints:
        print("[!] No endpoints discovered. Performing target base URL analysis.")
        discovered_endpoints = [{"url": target_url, "method": "GET"}]

    # 2. Instantiate Engines & Detectors
    request_engine = RequestEngine()
    response_parser = ResponseParser()
    signature_detector = SignatureDetector()
    ml_detector = MLAnomalyDetector()
    dl_detector = DeepLearningDetector()
    risk_scorer = RiskScorer()

    # Save Session
    session_obj = save_scan_session(target_url=target_url, total_endpoints=len(discovered_endpoints))
    vulnerability_count = 0
    total_scores = []

    try:
        active_test_queue = [
            {"type": "SQL_Injection", "payload": "{\"username\": \"admin' OR 1=1 --\", \"password\": \"pass\"}", "method": "POST", "headers": {"Content-Type": "application/json"}},
            {"type": "SQL_Injection_GET", "payload": "' OR 1=1 --", "method": "GET"},
            {"type": "Cross_Site_Scripting", "payload": "<script>alert('xss')</script>", "method": "POST"},
            {"type": "Command_Injection", "payload": "; cat /etc/passwd", "method": "GET"},
            {"type": "Broken_Authentication", "payload": "", "method": "GET", "headers": {"Authorization": "Bearer null"}},
            {"type": "BOLA_IDOR", "payload": "", "method": "GET", "path_suffix": "/1"},
            {"type": "Baseline_Inspection", "payload": "", "method": "GET"}
        ]

        for idx, ep_info in enumerate(discovered_endpoints, start=1):
            base_ep_url = ep_info["url"]
            default_method = ep_info["method"]

            print(f"\n[{idx}/{len(discovered_endpoints)}] Testing Endpoint: [{default_method}] {base_ep_url}")

            # Baseline request
            baseline_req = request_engine.send_request(default_method, base_ep_url)
            baseline_telemetry = {
                "status_code": baseline_req.get("status_code", 200),
                "response_size": baseline_req.get("response_size", 0),
                "response_time": baseline_req.get("response_time", 0.0)
            }

            for test_item in active_test_queue:
                path_suffix = test_item.get("path_suffix", "")
                if path_suffix:
                    if base_ep_url.rstrip("/").endswith(path_suffix.strip("/")):
                        test_url = base_ep_url
                    else:
                        test_url = base_ep_url.rstrip("/") + path_suffix
                else:
                    test_url = base_ep_url

                test_method = test_item.get("method", default_method)
                payload_str = test_item.get("payload", "")
                custom_headers = test_item.get("headers", None)

                # Send Request Telemetry
                req_data = request_engine.send_request(test_method, test_url, payload=payload_str, custom_headers=custom_headers)
                features = response_parser.extract_features(req_data)

                # Layer 1 - Signature Detection & Proof Verification
                sig_res = signature_detector.analyze(req_data, baseline_telemetry=baseline_telemetry)

                # Layer 2 - ML Anomaly Detection (Isolation Forest)
                ml_res = ml_detector.predict(features)

                # Layer 3 - Deep Learning (PyTorch LSTM + Autoencoder)
                dl_res = dl_detector.analyze(payload_str, features)

                # Risk Scoring Calculation
                risk_summary = risk_scorer.calculate_risk(
                    signature_result=sig_res,
                    ml_result=ml_res,
                    dl_result=dl_res,
                    endpoint_url=test_url,
                    http_method=test_method,
                    payload_had_effect=req_data.get("payload_had_effect", True),
                    telemetry_data=req_data
                )

                score = risk_summary["total_score"]
                severity = risk_summary["severity"]
                total_scores.append(score)

                # Print Console Breakdown
                print(f"  [{test_item['type']}] -> Layer 1: {sig_res['points']} pts | ML: {ml_res['points']} pts | DL: {dl_res['total_layer3_points']} pts | SCORE: {score} [{severity}]")

                # Persist Result to SQLite Database
                ep_obj = save_endpoint(session_id=session_obj.id, url=test_url, method=test_method)

                attack_name = sig_res.get("attack_type", "None") if sig_res.get("is_vulnerable") or score > 0.0 else "None"
                if sig_res.get("is_vulnerable") or score > 0.0:
                    vulnerability_count += 1

                save_finding(
                    session_id=session_obj.id,
                    endpoint_id=ep_obj.id,
                    attack_type=attack_name,
                    severity=severity,
                    risk_score=score,
                    finding_status=risk_summary.get("finding_status", "Informational"),
                    signature_triggered=sig_res.get("proof_of_concept") or sig_res.get("pattern_matched", ""),
                    ml_score=ml_res.get("points", 0.0),
                    lstm_score=dl_res.get("lstm_points", 0.0),
                    autoencoder_score=dl_res.get("autoencoder_points", 0.0),
                    recommendation=risk_summary.get("recommendation", ""),
                    request_payload=payload_str,
                    response_status=req_data.get("status_code", 200),
                    response_size=req_data.get("response_size", 0),
                    response_time=req_data.get("response_time", 0.0)
                )

        overall_score = round(max(total_scores), 2) if total_scores else 0.0
        complete_scan_session(
            session_id=session_obj.id,
            overall_risk_score=overall_score,
            overall_severity=RiskScorer.classify_severity(overall_score),
            total_vulnerabilities=vulnerability_count
        )

        print("\n" + "="*65)
        print(" SCAN PIPELINE COMPLETED SUCCESSFULLY")
        print(" All inspection records persisted to database.")
        print(" Launch web dashboard via `python main.py --dashboard` to view reports.")
        print("="*65 + "\n")

    except Exception as exc:
        logger.error(f"Error during scan pipeline execution: {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered API Security & Anomaly Detection Platform"
    )
    parser.add_argument(
        "--url",
        type=str,
        help="Target API base URL to inspect"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch Flask web dashboard"
    )
    args = parser.parse_args()

    if args.dashboard:
        logger.info("Launching Web Dashboard...")
        from dashboard.app import create_app
        from config.settings import FLASK_PORT, FLASK_DEBUG
        app = create_app()
        app.run(port=FLASK_PORT, debug=FLASK_DEBUG)

    elif args.url:
        run_pipeline(args.url)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
