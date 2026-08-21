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
from main import run_pipeline

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.context_processor
def inject_recent_sessions():
    return dict(recent_sessions=get_all_sessions()[:5])

@dashboard_bp.route("/")
def index():
    recent_sessions = get_all_sessions()[:5]
    return render_template("index.html", recent_sessions=recent_sessions)

@dashboard_bp.route("/scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("target_url")
    if not target_url:
        return redirect(url_for("dashboard.index"))

    session_id = run_pipeline(target_url, return_session_id=True)
    if not isinstance(session_id, int):
        return "Scan failed", 500
    return redirect(url_for("dashboard.results", session_id=session_id))

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
                "method": f.endpoint.method if f.endpoint else "GET",
                "attack_type": f.attack_type,
                "finding_status": f.finding_status,
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
        from reports.sarif_exporter import SARIFReportExporter
        from flask import send_file

        if fmt == "json":
            exporter = JSONReportExporter()
            out_file = exporter.export(session_data, endpoints_list, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.json")
        elif fmt == "html":
            exporter = HTMLReportExporter()
            out_file = exporter.export(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.html")
        elif fmt == "sarif":
            exporter = SARIFReportExporter()
            out_file = exporter.export(session_data, findings_data)
            return send_file(out_file, as_attachment=True, download_name=f"scan_report_{session_id}.sarif")
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

    session_id = run_pipeline(target_url, return_session_id=True)
    if not isinstance(session_id, int):
        return jsonify({"status": "error", "message": "scan failed"}), 500

    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        return jsonify({
            "status": "success",
            "session_id": session_id,
            "target_url": target_url,
            "overall_risk_score": session_obj.overall_risk_score if session_obj else None,
            "overall_severity": session_obj.overall_severity if session_obj else None,
            "total_vulnerabilities": session_obj.total_vulnerabilities_found if session_obj else None,
            "results_url": url_for("dashboard.results", session_id=session_id),
            "sarif_url": url_for("dashboard.export_report", session_id=session_id, format="sarif"),
        }), 200
    finally:
        db.close()
