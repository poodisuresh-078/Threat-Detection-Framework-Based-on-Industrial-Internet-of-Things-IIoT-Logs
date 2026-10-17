"""
SQLite Database Layer for IIoT Threat Detection Framework
Provides parameterized queries, schema initialization, threat persistence,
and analytics retrieval for the dashboard and reports.
"""

import os
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd

from contextlib import contextmanager

DEFAULT_DB_PATH = os.environ.get("DATABASE_PATH", "iiot_security.db")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a connection to the SQLite database with Row factory.
    """
    path = db_path or os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db(db_path: Optional[str] = None):
    """
    Context manager that yields an active database connection and guarantees
    proper commit/rollback and connection closure.
    """
    conn = get_db_connection(db_path)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes the SQLite database tables and indexes if they do not already exist.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # 1. IIoT Ingested Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iiot_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                device_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                network_traffic REAL NOT NULL DEFAULT 0.0,
                status TEXT NOT NULL,
                is_suspicious INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'Normal',
                detection_reason TEXT,
                ml_anomaly_score REAL DEFAULT 0.0,
                rule_flagged INTEGER DEFAULT 0,
                ml_flagged INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. Threat Alerts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                batch_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                device_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                network_traffic REAL NOT NULL DEFAULT 0.0,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                detection_reason TEXT NOT NULL,
                ml_anomaly_score REAL DEFAULT 0.0,
                rule_flagged INTEGER DEFAULT 0,
                ml_flagged INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES iiot_logs (id) ON DELETE CASCADE
            );
        """)

        # 3. Analysis Batch History Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                total_records INTEGER NOT NULL DEFAULT 0,
                normal_records INTEGER NOT NULL DEFAULT 0,
                suspicious_records INTEGER NOT NULL DEFAULT 0,
                low_risk_count INTEGER NOT NULL DEFAULT 0,
                medium_risk_count INTEGER NOT NULL DEFAULT 0,
                high_risk_count INTEGER NOT NULL DEFAULT 0,
                critical_risk_count INTEGER NOT NULL DEFAULT 0,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Indexes for rapid filtering and lookup
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_batch ON iiot_logs(batch_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_device ON iiot_logs(device_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON iiot_logs(source_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_risk ON iiot_logs(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_risk ON threat_alerts(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_device ON threat_alerts(device_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_ip ON threat_alerts(source_ip);")

        conn.commit()


def save_analysis_results(
    batch_id: str,
    filename: str,
    df: pd.DataFrame,
    stats: Dict[str, Any],
    db_path: Optional[str] = None,
) -> None:
    """
    Saves an analyzed batch of logs, extracted threat alerts, and batch metadata
    into SQLite within an atomic transaction.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # 1. Insert Batch Metadata
        cursor.execute(
            """
            INSERT INTO analysis_history (
                batch_id, filename, total_records, normal_records,
                suspicious_records, low_risk_count, medium_risk_count,
                high_risk_count, critical_risk_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                batch_id,
                filename,
                stats.get("total_logs", 0),
                stats.get("normal_events", 0),
                stats.get("suspicious_events", 0),
                stats.get("low_risk_alerts", 0),
                stats.get("medium_risk_alerts", 0),
                stats.get("high_risk_alerts", 0),
                stats.get("critical_alerts", 0),
            ),
        )

        # 2. Insert Log Records and Threat Alerts
        insert_log_sql = """
            INSERT INTO iiot_logs (
                batch_id, timestamp, device_id, source_ip, event_type,
                failed_logins, network_traffic, status, is_suspicious,
                risk_level, detection_reason, ml_anomaly_score,
                rule_flagged, ml_flagged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        insert_alert_sql = """
            INSERT INTO threat_alerts (
                log_id, batch_id, timestamp, device_id, source_ip,
                event_type, failed_logins, network_traffic, status,
                risk_level, detection_reason, ml_anomaly_score,
                rule_flagged, ml_flagged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        for _, row in df.iterrows():
            is_suspicious = int(row.get("is_suspicious", 0))
            cursor.execute(
                insert_log_sql,
                (
                    batch_id,
                    str(row.get("timestamp", "")),
                    str(row.get("device_id", "")),
                    str(row.get("source_ip", "")),
                    str(row.get("event_type", "")),
                    int(row.get("failed_logins", 0)),
                    float(row.get("network_traffic", 0.0)),
                    str(row.get("status", "")),
                    is_suspicious,
                    str(row.get("risk_level", "Normal")),
                    str(row.get("detection_reason", "")),
                    float(row.get("ml_anomaly_score", 0.0)),
                    int(row.get("rule_flagged", 0)),
                    int(row.get("ml_flagged", 0)),
                ),
            )
            log_id = cursor.lastrowid

            if is_suspicious == 1:
                cursor.execute(
                    insert_alert_sql,
                    (
                        log_id,
                        batch_id,
                        str(row.get("timestamp", "")),
                        str(row.get("device_id", "")),
                        str(row.get("source_ip", "")),
                        str(row.get("event_type", "")),
                        int(row.get("failed_logins", 0)),
                        float(row.get("network_traffic", 0.0)),
                        str(row.get("status", "")),
                        str(row.get("risk_level", "Low")),
                        str(row.get("detection_reason", "")),
                        float(row.get("ml_anomaly_score", 0.0)),
                        int(row.get("rule_flagged", 0)),
                        int(row.get("ml_flagged", 0)),
                    ),
                )

        conn.commit()


def get_dashboard_metrics(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes aggregated security metrics and threat breakdown for the dashboard.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # Cumulative counters
        cursor.execute("SELECT COUNT(*) FROM iiot_logs;")
        total_logs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM iiot_logs WHERE is_suspicious = 0;")
        normal_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_alerts;")
        suspicious_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_alerts WHERE risk_level = 'Critical';")
        critical_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_alerts WHERE risk_level = 'High';")
        high_risk_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_alerts WHERE risk_level = 'Medium';")
        medium_risk_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_alerts WHERE risk_level = 'Low';")
        low_risk_alerts = cursor.fetchone()[0]

        # Recent suspicious activities (latest 8)
        cursor.execute("""
            SELECT id, timestamp, device_id, source_ip, event_type,
                   failed_logins, network_traffic, status, risk_level,
                   detection_reason
            FROM threat_alerts
            ORDER BY id DESC
            LIMIT 8;
        """)
        recent_threats = [dict(row) for row in cursor.fetchall()]

        # Latest batches
        cursor.execute("""
            SELECT batch_id, filename, total_records, suspicious_records, analyzed_at
            FROM analysis_history
            ORDER BY id DESC
            LIMIT 5;
        """)
        recent_batches = [dict(row) for row in cursor.fetchall()]

        return {
            "total_logs": total_logs,
            "normal_events": normal_events,
            "suspicious_events": suspicious_events,
            "critical_alerts": critical_alerts,
            "high_risk_alerts": high_risk_alerts,
            "medium_risk_alerts": medium_risk_alerts,
            "low_risk_alerts": low_risk_alerts,
            "recent_threats": recent_threats,
            "recent_batches": recent_batches,
        }


def get_all_logs(
    db_path: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Retrieves analyzed logs with optional risk filtering and search.
    Returns (records, total_matching_count).
    """
    conditions: List[str] = []
    params: List[Any] = []

    if risk_level and risk_level.lower() != "all":
        conditions.append("risk_level = ?")
        params.append(risk_level)

    if search and search.strip():
        term = f"%{search.strip()}%"
        conditions.append("(device_id LIKE ? OR source_ip LIKE ? OR event_type LIKE ?)")
        params.extend([term, term, term])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # Count total
        count_sql = f"SELECT COUNT(*) FROM iiot_logs {where_clause};"
        cursor.execute(count_sql, params)
        total_count = cursor.fetchone()[0]

        # Fetch page
        query_sql = f"""
            SELECT id, timestamp, device_id, source_ip, event_type,
                   failed_logins, network_traffic, status, is_suspicious,
                   risk_level, detection_reason, ml_anomaly_score
            FROM iiot_logs
            {where_clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
        """
        cursor.execute(query_sql, params + [limit, offset])
        records = [dict(row) for row in cursor.fetchall()]

        return records, total_count


def get_all_threats(
    db_path: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 300,
) -> List[Dict[str, Any]]:
    """
    Retrieves threat alerts with optional risk filtering and search.
    """
    conditions: List[str] = []
    params: List[Any] = []

    if risk_level and risk_level.lower() != "all":
        conditions.append("risk_level = ?")
        params.append(risk_level)

    if search and search.strip():
        term = f"%{search.strip()}%"
        conditions.append("(device_id LIKE ? OR source_ip LIKE ? OR event_type LIKE ?)")
        params.extend([term, term, term])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_db(db_path) as conn:
        cursor = conn.cursor()
        query_sql = f"""
            SELECT id, timestamp, device_id, source_ip, event_type,
                   failed_logins, network_traffic, status, risk_level,
                   detection_reason, ml_anomaly_score, rule_flagged, ml_flagged
            FROM threat_alerts
            {where_clause}
            ORDER BY id DESC
            LIMIT ?;
        """
        cursor.execute(query_sql, params + [limit])
        return [dict(row) for row in cursor.fetchall()]


def get_reports_data(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Gathers detailed statistics for the Reports & Visualizations view.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # Overall counts
        cursor.execute("SELECT COUNT(*) FROM iiot_logs;")
        total_logs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM iiot_logs WHERE is_suspicious = 0;")
        normal_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM threat_alerts;")
        suspicious_events = cursor.fetchone()[0]

        # Risk distribution
        cursor.execute("""
            SELECT risk_level, COUNT(*) as cnt
            FROM threat_alerts
            GROUP BY risk_level;
        """)
        risk_dist = {row["risk_level"]: row["cnt"] for row in cursor.fetchall()}

        # Top 5 Targeted Devices
        cursor.execute("""
            SELECT device_id, COUNT(*) as alert_count
            FROM threat_alerts
            GROUP BY device_id
            ORDER BY alert_count DESC
            LIMIT 5;
        """)
        top_devices = [dict(row) for row in cursor.fetchall()]

        # Top 5 Hostile/Suspicious Source IPs
        cursor.execute("""
            SELECT source_ip, COUNT(*) as alert_count
            FROM threat_alerts
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT 5;
        """)
        top_ips = [dict(row) for row in cursor.fetchall()]

        # Threat Event Types distribution
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM threat_alerts
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 6;
        """)
        threat_events = [dict(row) for row in cursor.fetchall()]

        return {
            "total_logs": total_logs,
            "normal_events": normal_events,
            "suspicious_events": suspicious_events,
            "critical_count": risk_dist.get("Critical", 0),
            "high_count": risk_dist.get("High", 0),
            "medium_count": risk_dist.get("Medium", 0),
            "low_count": risk_dist.get("Low", 0),
            "top_devices": top_devices,
            "top_ips": top_ips,
            "threat_events": threat_events,
        }


def get_threats_for_export(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves all suspicious log records for CSV export with safe string values.
    Mitigates spreadsheet formula injection by sanitizing formulas starting with =, +, -, @.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, device_id, source_ip, event_type,
                   failed_logins, network_traffic, status, risk_level,
                   detection_reason, ml_anomaly_score
            FROM threat_alerts
            ORDER BY id ASC;
        """)
        rows = [dict(r) for r in cursor.fetchall()]

    sanitized_rows: List[Dict[str, Any]] = []
    formula_chars = ("=", "+", "-", "@", "\t", "\r")

    for row in rows:
        cleaned_row = {}
        for k, v in row.items():
            if isinstance(v, str):
                cleaned_v = v.strip()
                # If value begins with dangerous spreadsheet formula character, prefix with single-quote
                if cleaned_v and cleaned_v[0] in formula_chars:
                    cleaned_v = f"'{cleaned_v}"
                cleaned_row[k] = cleaned_v
            else:
                cleaned_row[k] = v
        sanitized_rows.append(cleaned_row)

    return sanitized_rows


def clear_all_data(db_path: Optional[str] = None) -> None:
    """
    Clears all records from iiot_logs, threat_alerts, and analysis_history.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_alerts;")
        cursor.execute("DELETE FROM iiot_logs;")
        cursor.execute("DELETE FROM analysis_history;")
        conn.commit()
