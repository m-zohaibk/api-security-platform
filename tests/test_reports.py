import os
import pytest
from pathlib import Path
from reports.pdf_generator import PDFReportGenerator
from reports.json_exporter import JSONReportExporter
from reports.html_exporter import HTMLReportExporter

def test_pdf_report_generation():
    generator = PDFReportGenerator()
    dummy_session = {
        "id": 999,
        "target_url": "http://example-target.org",
        "overall_risk_score": 55.5,
        "overall_severity": "Medium",
        "total_endpoints_found": 2,
        "total_vulnerabilities_found": 1
    }
    dummy_findings = [{
        "url": "http://example-target.org/api",
        "attack_type": "Security_Misconfiguration",
        "severity": "Medium",
        "risk_score": 55.5,
        "recommendation": "Enforce strict CSP and frame options."
    }]

    file_path = generator.generate(dummy_session, dummy_findings)
    assert os.path.exists(file_path)
    assert file_path.endswith(".pdf")

def test_json_report_export():
    exporter = JSONReportExporter()
    dummy_session = {"id": 999, "target_url": "http://example-target.org", "overall_risk_score": 55.5, "overall_severity": "Medium"}
    dummy_eps = [{"url": "http://example-target.org/api", "method": "GET"}]
    dummy_findings = [{"attack_type": "Security_Misconfiguration", "risk_score": 55.5}]

    file_path = exporter.export(dummy_session, dummy_eps, dummy_findings)
    assert os.path.exists(file_path)
    assert file_path.endswith(".json")

def test_html_report_export():
    exporter = HTMLReportExporter()
    dummy_session = {"id": 999, "target_url": "http://example-target.org", "overall_risk_score": 55.5, "overall_severity": "Medium"}
    dummy_findings = [{"url": "http://example-target.org/api", "attack_type": "Security_Misconfiguration", "severity": "Medium", "risk_score": 55.5, "recommendation": "Check CSP headers."}]

    file_path = exporter.export(dummy_session, dummy_findings)
    assert os.path.exists(file_path)
    assert file_path.endswith(".html")
