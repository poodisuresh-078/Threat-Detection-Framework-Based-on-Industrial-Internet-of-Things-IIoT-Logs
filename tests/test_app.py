"""
Integration Tests for Flask Web Application Routes & Security Controls
Verifies Dashboard, CSV Upload, Sample Loader, Logs View, Threats Management,
Reports, CSV Export, and API Endpoints.
"""

import os
import io
import pytest
from app import app
import database


@pytest.fixture
def client(tmp_path):
    """Configures a temporary SQLite database and provides a Flask test client."""
    test_db = str(tmp_path / "test_flask_security.db")
    app.config["TESTING"] = True
    app.config["DATABASE_PATH"] = test_db
    app.config["WTF_CSRF_ENABLED"] = False

    # Initialize database
    database.init_db(test_db)

    with app.test_client() as client:
        yield client


def test_dashboard_route_empty_state(client):
    """Test dashboard loads with status 200 on an empty database."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Total Logs Analyzed" in response.data
    assert b"Threat Risk Distribution" in response.data


def test_load_sample_data_route(client):
    """Test one-click load sample data route populates DB and redirects."""
    response = client.get("/load-sample", follow_redirects=True)
    assert response.status_code == 200
    assert b"Loaded 130 sample IIoT logs" in response.data


def test_upload_get_page(client):
    """Test upload page displays upload form and CSV guidelines."""
    response = client.get("/upload")
    assert response.status_code == 200
    assert b"Upload Industrial Log File" in response.data
    assert b"Required CSV Schema" in response.data


def test_upload_post_valid_csv(client):
    """Test uploading a valid CSV file performs analysis and persists records."""
    valid_csv_content = (
        "timestamp,device_id,source_ip,event_type,failed_logins,network_traffic,status\n"
        "2026-03-10 12:00:00,PLC-01,192.168.1.10,telemetry_read,0,45.0,success\n"
        "2026-03-10 12:01:00,HMI-02,198.51.100.45,brute_force_login,8,120.0,failed\n"
    )
    data = {
        "log_file": (io.BytesIO(valid_csv_content.encode("utf-8")), "test_logs.csv")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Successfully analyzed" in response.data


def test_upload_post_invalid_file_extension(client):
    """Test rejecting non-CSV file uploads."""
    data = {
        "log_file": (io.BytesIO(b"malicious script content"), "script.exe")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Only CSV files" in response.data


def test_upload_post_missing_columns(client):
    """Test handling CSV missing required schema columns."""
    invalid_csv = "timestamp,device_id\n2026-03-10,PLC-01\n"
    data = {
        "log_file": (io.BytesIO(invalid_csv.encode("utf-8")), "missing_cols.csv")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Missing required column" in response.data


def test_upload_post_empty_file(client):
    """Test handling completely empty CSV file upload."""
    data = {
        "log_file": (io.BytesIO(b""), "empty.csv")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"empty" in response.data.lower()


def test_logs_view_filtering(client):
    """Test logs view with and without risk level filter."""
    # First load sample
    client.get("/load-sample", follow_redirects=True)

    # View all
    res_all = client.get("/logs")
    assert res_all.status_code == 200
    assert b"Telemetry &amp; Security Logs" in res_all.data

    # View Critical only
    res_crit = client.get("/logs?risk=Critical")
    assert res_crit.status_code == 200
    assert b"Critical" in res_crit.data


def test_threats_view_filtering(client):
    """Test threats management view with risk and search queries."""
    client.get("/load-sample", follow_redirects=True)

    # All threats
    res = client.get("/threats")
    assert res.status_code == 200
    assert b"Flagged Threat Alerts" in res.data

    # Filter by risk
    res_crit = client.get("/threats?risk=Critical")
    assert res_crit.status_code == 200

    # Search by device ID
    res_search = client.get("/threats?search=HMI")
    assert res_search.status_code == 200


def test_reports_view(client):
    """Test reports view calculates analytics and displays charts."""
    client.get("/load-sample", follow_redirects=True)
    response = client.get("/reports")
    assert response.status_code == 200
    assert b"Executive Threat Summary" in response.data
    assert b"Top 5 Targeted Industrial Devices" in response.data
    assert b"Top 5 Suspicious Source IPs" in response.data


def test_export_threats_csv(client):
    """Test CSV export generates a valid CSV attachment."""
    client.get("/load-sample", follow_redirects=True)
    response = client.get("/export")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers.get("Content-Disposition", "")
    assert b"device_id" in response.data
    assert b"detection_reason" in response.data


def test_api_stats_endpoint(client):
    """Test JSON API endpoint returns correct status and structure."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["status"] == "success"
    assert "total_logs" in json_data["data"]

