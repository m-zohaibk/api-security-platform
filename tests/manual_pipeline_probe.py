import contextlib
import io
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class CleanApiHandler(BaseHTTPRequestHandler):
    security_headers = {
        "Content-Type": "application/json",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000",
    }

    def send_json(self, status, body):
        encoded = body.encode("utf-8")
        self.send_response(status)
        for key, value in self.security_headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/openapi.json":
            self.send_json(200, '{"openapi":"3.0.0","paths":{"/health":{"get":{}}}}')
        elif self.path == "/health":
            self.send_json(200, '{"status":"ok"}')
        else:
            self.send_json(404, '{"error":"not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_json(200, '{"status":"ok"}')

    def log_message(self, *_args):
        pass


def main():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tmp, 'scan.sqlite')}"
        server = ThreadingHTTPServer(("127.0.0.1", 0), CleanApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            from main import run_pipeline
            from database.db import SessionLocal
            from database.models import Finding, ScanSession

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                run_pipeline(base_url)

            db = SessionLocal()
            try:
                session = db.query(ScanSession).order_by(ScanSession.id.desc()).first()
                findings = db.query(Finding).filter(Finding.session_id == session.id).all()
                status_counts = {}
                for finding in findings:
                    status_counts[finding.finding_status] = status_counts.get(finding.finding_status, 0) + 1
                result = {
                    "target": base_url,
                    "endpoints_found": session.total_endpoints_found,
                    "vulnerabilities_found": session.total_vulnerabilities_found,
                    "overall_score": session.overall_risk_score,
                    "finding_count": len(findings),
                    "finding_status_counts": status_counts,
                    "confirmed_finding_count": sum(1 for finding in findings if finding.finding_status == "Confirmed"),
                }
            finally:
                db.close()
            print("PIPELINE_RESULT", json.dumps(result, sort_keys=True))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
