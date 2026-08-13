import os
import sys
from flask import Blueprint, render_template, request, jsonify, redirect, url_for

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import joinedload
from database.db import (
    save_scan_session, save_endpoint, save_finding, complete_scan_session,
    get_all_sessions, get_session_findings, get_finding_by_id, delete_session, SessionLocal
)
from database.models import ScanSession, Finding, Endpoint
from core.discovery import EndpointDiscovery
from core.request_engine import RequestEngine
from core.response_parser import ResponseParser
from detection.signature import SignatureDetector
from detection.ml_model import MLAnomalyDetector
from detection.deep_learning import DeepLearningDetector
from detection.risk_scorer import RiskScorer

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    recent_sessions = get_all_sessions()[:5]
    return render_template("index.html", recent_sessions=recent_sessions)

@dashboard_bp.route("/scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("target_url")
    if not target_url:
        return redirect(url_for("dashboard.index"))

    # Selected Inspection Modules — default all to True if not explicitly parameterized
    has_explicit_modules = any(k.startswith("module_") for k in request.form.keys())
    if has_explicit_modules:
        module_sqli = request.form.get("module_sqli") == "on"
        module_xss = request.form.get("module_xss") == "on"
        module_bola = request.form.get("module_bola") == "on"
        module_auth = request.form.get("module_auth") == "on"
        module_cmd = request.form.get("module_cmd") == "on"
    else:
        module_sqli = True
        module_xss = True
        module_bola = True
        module_auth = True
        module_cmd = True

    # Active Scan Engine Pipeline Execution
    discoverer = EndpointDiscovery(base_url=target_url)
    discovered_endpoints = discoverer.discover()
    if not discovered_endpoints:
        discovered_endpoints = [{"url": target_url, "method": "GET"}]

    request_engine = RequestEngine()
    response_parser = ResponseParser()
    signature_detector = SignatureDetector()
    ml_detector = MLAnomalyDetector()
    dl_detector = DeepLearningDetector()
    risk_scorer = RiskScorer()

    # Save Session
    session_obj = save_scan_session(target_url=target_url, total_endpoints=len(discovered_endpoints))

    total_risk_scores = []
    vulnerability_count = 0

    # Build active test payloads based on selected modules
    active_test_queue = []
    
    if module_sqli:
        active_test_queue.append({"type": "SQL_Injection", "payload": "{\"username\": \"admin' OR 1=1 --\", \"password\": \"pass\"}", "method": "POST", "headers": {"Content-Type": "application/json"}})
        active_test_queue.append({"type": "SQL_Injection_GET", "payload": "' OR 1=1 --", "method": "GET"})
    if module_xss:
        active_test_queue.append({"type": "Cross_Site_Scripting", "payload": "<script>alert('xss')</script>", "method": "POST"})
    if module_cmd:
        active_test_queue.append({"type": "Command_Injection", "payload": "; cat /etc/passwd", "method": "GET"})
    if module_auth:
        active_test_queue.append({"type": "Broken_Authentication", "payload": "", "method": "GET", "headers": {"Authorization": "Bearer null"}})
    if module_bola:
        active_test_queue.append({"type": "BOLA_IDOR", "payload": "", "method": "GET", "path_suffix": "/1"})

    # Fallback to standard baseline if no module selected
    if not active_test_queue:
        active_test_queue.append({"type": "Baseline_Inspection", "payload": "", "method": "GET"})

    for ep_info in discovered_endpoints:
        base_ep_url = ep_info["url"]
        default_method = ep_info["method"]

        ep_obj = save_endpoint(session_id=session_obj.id, url=base_ep_url, method=default_method)

        # Baseline request — get normal response parameters
        baseline_req = request_engine.send_request(default_method, base_ep_url)
        baseline_size = baseline_req.get("response_size", 0)
        baseline_status = baseline_req.get("status_code", 200)
        baseline_time = baseline_req.get("response_time", 0.0)
        baseline_telemetry = {
            "status_code": baseline_status,
            "response_size": baseline_size,
            "response_time": baseline_time
        }

        for test_item in active_test_queue:
            # Handle path suffix safely for BOLA testing
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

            # Dispatch HTTP Request with payload
            req_data = request_engine.send_request(test_method, test_url, payload=payload_str, custom_headers=custom_headers)

            # Skip if response is identical to baseline
            current_size = req_data.get("response_size", 0)
            current_status = req_data.get("status_code", 200)

            if (current_size == baseline_size 
                and current_status == baseline_status
                and current_size > 0
                and test_item["type"] not in ["Baseline_Inspection"]):
                req_data["payload_had_effect"] = False
            else:
                req_data["payload_had_effect"] = True

            features = response_parser.extract_features(req_data)

            # Detection Layers
            sig_res = signature_detector.analyze(req_data, baseline_telemetry=baseline_telemetry)
            ml_res = ml_detector.predict(features)
            dl_res = dl_detector.analyze(payload_str, features)

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
            total_risk_scores.append(score)

            attack_name = test_item["type"] if sig_res.get("is_vulnerable") or score > 0.0 else sig_res.get("attack_type", "None")

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

    # Update session overall totals and end time
    overall_score = round(max(total_risk_scores), 2) if total_risk_scores else 0.0
    complete_scan_session(
        session_id=session_obj.id,
        overall_risk_score=overall_score,
        overall_severity=RiskScorer.classify_severity(overall_score),
        total_vulnerabilities=vulnerability_count
    )

    return redirect(url_for("dashboard.results", session_id=session_obj.id))

@dashboard_bp.route("/results/<int:session_id>")
def results(session_id):
    db = SessionLocal()
    try:
        session_data = db.query(ScanSession).options(joinedload(ScanSession.endpoints), joinedload(ScanSession.findings)).filter(ScanSession.id == session_id).first()
        if not session_data:
            return "Session not found", 404

        findings = get_session_findings(session_id)
        
        # Categorize stats for Chart.js
        severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        attack_counts = {}

        for f in findings:
            sev = f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            att = f.attack_type
            attack_counts[att] = attack_counts.get(att, 0) + 1

        return render_template(
            "results.html",
            session_data=session_data,
            findings=findings,
            severity_counts=severity_counts,
            attack_counts=attack_counts
        )
    finally:
        db.close()

@dashboard_bp.route("/history")
def history():
    sessions = get_all_sessions()
    return render_template("history.html", sessions=sessions)

@dashboard_bp.route("/finding/<int:finding_id>")
def finding_detail(finding_id):
    finding = get_finding_by_id(finding_id)
    return render_template("report.html", finding=finding)

@dashboard_bp.route("/export/<int:session_id>")
def export_report(session_id):
    fmt = request.args.get("format", "pdf").lower()
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if not session_obj:
            return "Session not found", 404
        
        session_data = {
            "id": session_obj.id,
            "target_url": session_obj.target_url,
            "scan_start_time": session_obj.scan_start_time,
            "overall_risk_score": session_obj.overall_risk_score,
            "overall_severity": session_obj.overall_severity,
            "total_endpoints_found": session_obj.total_endpoints_found,
            "total_vulnerabilities_found": session_obj.total_vulnerabilities_found
        }

        endpoints_list = [{"url": ep.url, "method": ep.method} for ep in session_obj.endpoints]
        findings = get_session_findings(session_id)
        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "url": f.endpoint.url if f.endpoint else session_obj.target_url,
                "attack_type": f.attack_type,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "signature_triggered": f.signature_triggered,
                "ml_score": f.ml_score,
                "lstm_score": f.lstm_score,
                "autoencoder_score": f.autoencoder_score,
                "recommendation": f.recommendation,
                "response_status": f.response_status,
                "response_size": f.response_size,
                "response_time": f.response_time
            })

        from reports.pdf_generator import PDFReportGenerator
        from reports.json_exporter import JSONReportExporter
        from reports.html_exporter import HTMLReportExporter
        from flask import send_file

        if fmt == "json":
            exporter = JSONReportExporter()
            out_file = exporter.export(session_data, endpoints_list, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.json")
        elif fmt == "html":
            exporter = HTMLReportExporter()
            out_file = exporter.export(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.html")
        else:
            generator = PDFReportGenerator()
            out_file = generator.generate(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.pdf")

    finally:
        db.close()

@dashboard_bp.route("/delete_scan/<int:session_id>", methods=["POST"])
def delete_scan(session_id):
    delete_session(session_id)
    return redirect(url_for("dashboard.history"))

# ---------------------------------------------------------
# REST API Endpoints for Programmatic Client Access
# ---------------------------------------------------------

@dashboard_bp.route("/api/sessions", methods=["GET"])
def api_list_sessions():
    sessions = get_all_sessions()
    sessions_data = []
    for s in sessions:
        sessions_data.append({
            "id": s.id,
            "target_url": s.target_url,
            "scan_start_time": s.scan_start_time.isoformat() if s.scan_start_time else None,
            "scan_end_time": s.scan_end_time.isoformat() if s.scan_end_time else None,
            "overall_risk_score": s.overall_risk_score,
            "overall_severity": s.overall_severity,
            "total_endpoints_found": s.total_endpoints_found,
            "total_vulnerabilities_found": s.total_vulnerabilities_found
        })
    return jsonify({"status": "success", "sessions": sessions_data}), 200


@dashboard_bp.route("/api/sessions/<int:session_id>", methods=["GET"])
def api_get_session(session_id):
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if not session_obj:
            return jsonify({"status": "error", "message": "Session not found"}), 404

        findings = get_session_findings(session_id)
        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "url": f.endpoint.url if f.endpoint else session_obj.target_url,
                "attack_type": f.attack_type,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "finding_status": f.finding_status,
                "signature_triggered": f.signature_triggered,
                "ml_score": f.ml_score,
                "lstm_score": f.lstm_score,
                "autoencoder_score": f.autoencoder_score,
                "recommendation": f.recommendation,
                "response_status": f.response_status,
                "response_size": f.response_size,
                "response_time": f.response_time
            })

        endpoints_data = [{"url": ep.url, "method": ep.method} for ep in session_obj.endpoints]

        return jsonify({
            "status": "success",
            "session": {
                "id": session_obj.id,
                "target_url": session_obj.target_url,
                "scan_start_time": session_obj.scan_start_time.isoformat() if session_obj.scan_start_time else None,
                "scan_end_time": session_obj.scan_end_time.isoformat() if session_obj.scan_end_time else None,
                "overall_risk_score": session_obj.overall_risk_score,
                "overall_severity": session_obj.overall_severity,
                "total_endpoints_found": session_obj.total_endpoints_found,
                "total_vulnerabilities_found": session_obj.total_vulnerabilities_found
            },
            "endpoints": endpoints_data,
            "findings": findings_data
        }), 200
    finally:
        db.close()


@dashboard_bp.route("/api/sessions/<int:session_id>", methods=["DELETE"])
def api_delete_session(session_id):
    success = delete_session(session_id)
    if success:
        return jsonify({"status": "success", "message": f"Session {session_id} deleted"}), 200
    return jsonify({"status": "error", "message": "Session not found"}), 404


@dashboard_bp.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    req_json = request.get_json(silent=True) or {}
    target_url = req_json.get("target_url") or request.form.get("target_url")
    if not target_url:
        return jsonify({"status": "error", "message": "target_url is required"}), 400

    # Active Scan Engine Pipeline Execution
    discoverer = EndpointDiscovery(base_url=target_url)
    discovered_endpoints = discoverer.discover()
    if not discovered_endpoints:
        discovered_endpoints = [{"url": target_url, "method": "GET"}]

    request_engine = RequestEngine()
    response_parser = ResponseParser()
    signature_detector = SignatureDetector()
    ml_detector = MLAnomalyDetector()
    dl_detector = DeepLearningDetector()
    risk_scorer = RiskScorer()

    session_obj = save_scan_session(target_url=target_url, total_endpoints=len(discovered_endpoints))

    total_risk_scores = []
    vulnerability_count = 0

    active_test_queue = [
        {"type": "SQL_Injection", "payload": "{\"username\": \"admin' OR 1=1 --\", \"password\": \"pass\"}", "method": "POST", "headers": {"Content-Type": "application/json"}},
        {"type": "SQL_Injection_GET", "payload": "' OR 1=1 --", "method": "GET"},
        {"type": "Cross_Site_Scripting", "payload": "<script>alert('xss')</script>", "method": "POST"},
        {"type": "Command_Injection", "payload": "; cat /etc/passwd", "method": "GET"},
        {"type": "Broken_Authentication", "payload": "", "method": "GET", "headers": {"Authorization": "Bearer null"}},
        {"type": "BOLA_IDOR", "payload": "", "method": "GET", "path_suffix": "/1"},
        {"type": "Baseline_Inspection", "payload": "", "method": "GET"}
    ]

    for ep_info in discovered_endpoints:
        base_ep_url = ep_info["url"]
        default_method = ep_info["method"]
        ep_obj = save_endpoint(session_id=session_obj.id, url=base_ep_url, method=default_method)

        baseline_req = request_engine.send_request(default_method, base_ep_url)
        baseline_size = baseline_req.get("response_size", 0)
        baseline_status = baseline_req.get("status_code", 200)
        baseline_time = baseline_req.get("response_time", 0.0)
        baseline_telemetry = {
            "status_code": baseline_status,
            "response_size": baseline_size,
            "response_time": baseline_time
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

            req_data = request_engine.send_request(test_method, test_url, payload=payload_str, custom_headers=custom_headers)
            features = response_parser.extract_features(req_data)

            sig_res = signature_detector.analyze(req_data, baseline_telemetry=baseline_telemetry)
            ml_res = ml_detector.predict(features)
            dl_res = dl_detector.analyze(payload_str, features)

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
            total_risk_scores.append(score)

            attack_name = test_item["type"] if sig_res.get("is_vulnerable") or score > 0.0 else sig_res.get("attack_type", "None")
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

    overall_score = round(max(total_risk_scores), 2) if total_risk_scores else 0.0
    complete_scan_session(
        session_id=session_obj.id,
        overall_risk_score=overall_score,
        overall_severity=RiskScorer.classify_severity(overall_score),
        total_vulnerabilities=vulnerability_count
    )

    return jsonify({
        "status": "success",
        "session_id": session_obj.id,
        "target_url": target_url,
        "overall_risk_score": overall_score,
        "overall_severity": RiskScorer.classify_severity(overall_score),
        "total_vulnerabilities": vulnerability_count,
        "results_url": f"/results/{session_obj.id}"
    }), 200

