import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.signature import SignatureDetector
from detection.risk_scorer import RiskScorer


SECURITY_HEADERS = {
    "Content-Type": "application/json",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, headers=None):
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        for key, value in (headers or SECURITY_HEADERS).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        if self.path == "/openapi.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "paths": {"/api/users/{id}": {"get": {}}, "/health": {"get": {}}}}))
        elif self.path.startswith("/api/users/admin") or self.path == "/health":
            self._send(200, json.dumps({"status": "ok"}))
        else:
            self._send(404, "Not found", {"Content-Type": "text/plain"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        self._send(200, raw.decode("utf-8"), SECURITY_HEADERS)

    def log_message(self, *_args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        engine = RequestEngine(timeout=3)
        post = engine.send_request("POST", f"{base}/echo", json_payload={})
        print("POST_EMPTY_JSON_BODY", post["response_body"])

        discovery = EndpointDiscovery(base, timeout=3, max_depth=0)
        endpoints = discovery.discover()
        print("OPENAPI_ENDPOINTS", json.dumps(endpoints, sort_keys=True))

        parser = ResponseParser()
        features = parser.extract_features({"method": "GET", "url": f"{base}/health", "payload": "", "status_code": 200, "response_size": 16, "response_body": '{"status":"ok"}', "request_headers": {}})
        print("FEATURE_VECTOR_LENGTH", len(features["feature_vector"]))

        detector = SignatureDetector()
        bola = detector.analyze({"url": f"{base}/users/2", "payload": "", "status_code": 200, "response_size": 15, "response_headers": SECURITY_HEADERS, "response_body": '{"status":"ok"}', "request_headers": {}})
        print("BOLA_CLEAN_RESPONSE", json.dumps(bola, sort_keys=True))

        scorer = RiskScorer()
        suspected = scorer.calculate_risk({"matched": True, "has_proof": False, "is_vulnerable": False, "points": 10, "finding_status": "Suspected"}, {"is_anomaly": False, "points": 0}, {"lstm_points": 0, "autoencoder_points": 0}, f"{base}/health", "GET", telemetry_data={"status_code": 200, "response_size": 15, "response_time": 0.01})
        print("SUSPECTED_RISK", json.dumps(suspected, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
