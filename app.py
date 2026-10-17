"""
Industrial Internet of Things (IIoT) Threat Detection Web Application
Main Flask application entry point managing routing, file uploads,
threat dashboard, log viewing, report generation, and CSV export.
"""

import os
import io
import csv
import uuid
from datetime import datetime
from typing import Optional

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    Response,
    jsonify,
    abort,
)
from werkzeug.utils import secure_filename
import pandas as pd

import database
import detection

# Initialize Flask application
app = Flask(__name__)

# Application Configuration
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY", "iiot-threat-sentinel-dev-secret-key-2026"
)
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
)  # 16 MB limit
app.config["DATABASE_PATH"] = os.environ.get("DATABASE_PATH", "iiot_security.db")

ALLOWED_EXTENSIONS = {"csv"}


def allowed_file(filename: str) -> bool:
    """Checks if the uploaded file has a permitted .csv extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def ensure_db_ready():
    """Ensures database tables are initialized before handling requests."""
    # Run once per app startup
    if not getattr(app, "_db_initialized", False):
        database.init_db(app.config["DATABASE_PATH"])
        app._db_initialized = True


# =========================================================================
# Web Application Routes
# =========================================================================

@app.route("/")
def dashboard():
    """
    Dashboard Route:
    Renders top-level summary metrics, Chart.js visualization cards,
    and recent suspicious threat activity table.
    """
    try:
        metrics = database.get_dashboard_metrics(app.config["DATABASE_PATH"])
        return render_template("index.html", metrics=metrics)
    except Exception as exc:
        flash(f"Error loading dashboard metrics: {str(exc)}", "danger")
        return render_template("index.html", metrics={})


@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    """
    CSV Upload Route:
    GET: Displays drag-and-drop CSV upload form and schema specification.
    POST: Ingests, validates, analyzes, and persists uploaded IIoT logs.
    """
    if request.method == "POST":
        # 1. Check for file presence
        if "log_file" not in request.files:
            flash("No file part detected in request. Please choose a CSV file.", "warning")
            return redirect(request.url)

        file = request.files["log_file"]

        if not file or file.filename == "":
            flash("No file selected. Please select an IIoT CSV log file to upload.", "warning")
            return redirect(request.url)

        # 2. Check filename and extension
        if not allowed_file(file.filename):
            flash("Invalid file type. Only CSV files (.csv) are accepted.", "danger")
            return redirect(request.url)

        safe_name = secure_filename(file.filename) or "uploaded_logs.csv"

        # 3. Read and parse CSV safely
        try:
            # Read directly into Pandas
            df = pd.read_csv(file)
        except pd.errors.EmptyDataError:
            flash("The uploaded CSV file is completely empty. Please provide logs.", "danger")
            return redirect(request.url)
        except pd.errors.ParserError as parse_err:
            flash(f"Malformed CSV formatting: {str(parse_err)}", "danger")
            return redirect(request.url)
        except UnicodeDecodeError:
            flash("File encoding error. Please ensure the CSV is UTF-8 encoded.", "danger")
            return redirect(request.url)
        except Exception as read_err:
            flash(f"Error reading CSV file: {str(read_err)}", "danger")
            return redirect(request.url)

        # 4. Run Threat Detection Engine (Validation, Rules, Isolation Forest)
        try:
            analyzed_df, stats = detection.analyze_logs(df)
        except ValueError as val_err:
            flash(f"CSV Validation Error: {str(val_err)}", "danger")
            return redirect(request.url)
        except Exception as det_err:
            flash(f"Threat analysis failed: {str(det_err)}", "danger")
            return redirect(request.url)

        # 5. Save results into SQLite Database
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        try:
            database.save_analysis_results(
                batch_id=batch_id,
                filename=safe_name,
                df=analyzed_df,
                stats=stats,
                db_path=app.config["DATABASE_PATH"],
            )
            flash(
                f"Successfully analyzed {stats['total_logs']} logs from '{safe_name}'! "
                f"Identified {stats['suspicious_events']} suspicious events "
                f"({stats['critical_alerts']} Critical, {stats['high_risk_alerts']} High).",
                "success",
            )
            return redirect(url_for("threats_view"))
        except Exception as db_err:
            flash(f"Database storage error: {str(db_err)}", "danger")
            return redirect(request.url)

    return render_template("upload.html")


@app.route("/load-sample")
def load_sample_data():
    """
    Convenience route for examiners and demo evaluation:
    Loads bundled `sample_logs.csv` directly into the database.
    """
    sample_file = os.path.join(os.path.dirname(__file__), "sample_logs.csv")
    if not os.path.exists(sample_file):
        flash("Sample dataset file (sample_logs.csv) not found on server.", "danger")
        return redirect(url_for("dashboard"))

    try:
        df = pd.read_csv(sample_file)
        analyzed_df, stats = detection.analyze_logs(df)
        batch_id = f"sample_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        database.save_analysis_results(
            batch_id=batch_id,
            filename="sample_logs.csv",
            df=analyzed_df,
            stats=stats,
            db_path=app.config["DATABASE_PATH"],
        )
        flash(
            f"Loaded {stats['total_logs']} sample IIoT logs! "
            f"Detected {stats['suspicious_events']} potential threat events "
            f"({stats['critical_alerts']} Critical, {stats['high_risk_alerts']} High, {stats['medium_risk_alerts']} Medium).",
            "success",
        )
        return redirect(url_for("dashboard"))
    except Exception as exc:
        flash(f"Failed to load sample dataset: {str(exc)}", "danger")
        return redirect(url_for("dashboard"))


@app.route("/logs")
def logs_view():
    """
    All Logs View:
    Displays ingested IIoT telemetry logs with filtering by risk level
    and search capabilities across device ID, IP, and event type.
    """
    risk_filter = request.args.get("risk", "All").strip()
    search_query = request.args.get("search", "").strip()

    try:
        logs, total_count = database.get_all_logs(
            db_path=app.config["DATABASE_PATH"],
            risk_level=risk_filter if risk_filter != "All" else None,
            search=search_query if search_query else None,
            limit=500,
        )
        return render_template(
            "logs.html",
            logs=logs,
            total_count=total_count,
            selected_risk=risk_filter,
            search_query=search_query,
        )
    except Exception as exc:
        flash(f"Error fetching logs: {str(exc)}", "danger")
        return render_template("logs.html", logs=[], total_count=0, selected_risk="All")


@app.route("/threats")
def threats_view():
    """
    Threat Management View:
    Displays flagged threats and alerts with risk-level filters,
    search by Device ID / Source IP, and detection reason breakdown.
    """
    risk_filter = request.args.get("risk", "All").strip()
    search_query = request.args.get("search", "").strip()

    try:
        threats = database.get_all_threats(
            db_path=app.config["DATABASE_PATH"],
            risk_level=risk_filter if risk_filter != "All" else None,
            search=search_query if search_query else None,
            limit=500,
        )
        return render_template(
            "threats.html",
            threats=threats,
            selected_risk=risk_filter,
            search_query=search_query,
        )
    except Exception as exc:
        flash(f"Error fetching threat records: {str(exc)}", "danger")
        return render_template("threats.html", threats=[], selected_risk="All")


@app.route("/reports")
def reports_view():
    """
    Reports & Analytics View:
    Generates summary threat statistics, severity distributions,
    top targeted device rankings, and hostile source IP breakdowns.
    """
    try:
        reports = database.get_reports_data(app.config["DATABASE_PATH"])
        return render_template("reports.html", reports=reports)
    except Exception as exc:
        flash(f"Error generating reports: {str(exc)}", "danger")
        return render_template("reports.html", reports={})


@app.route("/export")
def export_threats_csv():
    """
    Export Route:
    Generates and streams a safe CSV file containing all flagged suspicious logs.
    Includes spreadsheet formula injection mitigation.
    """
    try:
        threats = database.get_threats_for_export(app.config["DATABASE_PATH"])

        output = io.StringIO()
        fieldnames = [
            "timestamp",
            "device_id",
            "source_ip",
            "event_type",
            "failed_logins",
            "network_traffic",
            "status",
            "risk_level",
            "detection_reason",
            "ml_anomaly_score",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()

        for threat in threats:
            writer.writerow({k: threat.get(k, "") for k in fieldnames})

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"iiot_threat_report_{timestamp_str}.csv"

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as exc:
        flash(f"CSV Export failed: {str(exc)}", "danger")
        return redirect(url_for("reports_view"))


@app.route("/api/stats")
def api_stats():
    """
    JSON API endpoint returning current threat metrics and distributions.
    Useful for external tooling or asynchronous chart refreshes.
    """
    try:
        metrics = database.get_dashboard_metrics(app.config["DATABASE_PATH"])
        return jsonify({"status": "success", "data": metrics})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


# =========================================================================
# Error Handlers
# =========================================================================

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("Uploaded file exceeds the maximum permitted size limit of 16 MB.", "danger")
    return redirect(url_for("upload_page"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("index.html", metrics=database.get_dashboard_metrics(app.config["DATABASE_PATH"])), 404


@app.errorhandler(500)
def internal_server_error(error):
    flash("An unexpected internal server error occurred.", "danger")
    return redirect(url_for("dashboard"))


# =========================================================================
# Application Entry Point
# =========================================================================

if __name__ == "__main__":
    # Ensure database tables exist
    database.init_db(app.config["DATABASE_PATH"])

    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    print("=" * 65)
    print(" IIoT Threat Detection Framework - Web Application Started")
    print(f" URL: http://{host}:{port}")
    print(" Machine Learning Engine: Scikit-learn Isolation Forest")
    print(" Database: SQLite Parameterized Store")
    print("=" * 65)

    app.run(host=host, port=port, debug=debug)

