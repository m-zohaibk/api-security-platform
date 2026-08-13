import pytest
from dashboard.app import create_app

def test_dashboard_routes():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response_index = client.get("/")
    assert response_index.status_code == 200
    assert b"API Telemetry" in response_index.data

    response_history = client.get("/history")
    assert response_history.status_code == 200
    assert b"Inspection Scan History" in response_history.data
