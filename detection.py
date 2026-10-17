"""
Threat Detection Engine for Industrial Internet of Things (IIoT) Logs
Combines rule-based cybersecurity heuristics with unsupervised Machine Learning
(Scikit-Learn Isolation Forest) to identify anomalies, suspicious behaviors, and attacks.
"""

from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Required CSV Columns for IIoT log ingestion
REQUIRED_COLUMNS: List[str] = [
    "timestamp",
    "device_id",
    "source_ip",
    "event_type",
    "failed_logins",
    "network_traffic",
    "status",
]

# Suspicious IP prefixes or ranges (e.g. testnets, simulators, known threat actors)
SUSPICIOUS_IP_PREFIXES: Tuple[str, ...] = (
    "198.51.100.",  # RFC 5737 TEST-NET-2 (Simulated external adversary)
    "203.0.113.",   # RFC 5737 TEST-NET-3 (Simulated attack relay)
    "192.0.2.",     # RFC 5737 TEST-NET-1 (Simulated adversary)
    "45.33.32.",    # External untrusted scanner network
    "185.220.101.", # Known malicious exit / brute-force node
    "0.0.0.0",      # Invalid / spoofed route
)

# High-risk and abnormal event types
CRITICAL_EVENT_TYPES: set = {
    "unauthorized_firmware_update",
    "buffer_overflow_attempt",
    "ddos_packet_flood",
    "command_injection",
    "unauthorized_modbus_write",
    "privilege_escalation",
    "data_exfiltration_burst",
}

SUSPICIOUS_EVENT_TYPES: set = {
    "port_scan",
    "ssh_bruteforce",
    "brute_force_login",
    "connection_hijack",
    "dos_flood",
}

CRITICAL_OPERATIONS: set = {
    "actuator_command",
    "valve_actuation",
    "firmware_verify",
    "pump_speed_adjust",
    "gateway_sync",
}


def validate_log_dataframe(df: pd.DataFrame) -> Tuple[bool, str, pd.DataFrame]:
    """
    Validates the structure, columns, and content of an uploaded IIoT log DataFrame.

    Returns:
        Tuple of (is_valid: bool, error_message: str, cleaned_df: pd.DataFrame)
    """
    if df is None or not isinstance(df, pd.DataFrame):
        return False, "Input data must be a valid Pandas DataFrame.", pd.DataFrame()

    if df.empty or len(df) == 0:
        return False, "Uploaded log file is empty. Please provide a CSV with records.", pd.DataFrame()

    # Clean column names (strip whitespace and convert to lowercase)
    df = df.copy()
    df.columns = [str(col).strip().lower() for col in df.columns]

    # Verify required columns
    missing_columns = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_columns:
        return (
            False,
            f"Missing required column(s): {', '.join(missing_columns)}. "
            f"Expected columns: {', '.join(REQUIRED_COLUMNS)}",
            pd.DataFrame(),
        )

    # Clean and sanitize data types
    # Safe numeric conversion
    df["failed_logins"] = pd.to_numeric(df["failed_logins"], errors="coerce").fillna(0).astype(int)
    # Ensure no negative failed logins
    df["failed_logins"] = df["failed_logins"].apply(lambda x: max(0, int(x)))

    df["network_traffic"] = pd.to_numeric(df["network_traffic"], errors="coerce").fillna(0.0).astype(float)
    # Ensure no negative network traffic
    df["network_traffic"] = df["network_traffic"].apply(lambda x: max(0.0, float(x)))

    # String fields clean-up
    for str_col in ["timestamp", "device_id", "source_ip", "event_type", "status"]:
        df[str_col] = df[str_col].fillna("unknown").astype(str).str.strip()

    return True, "", df


def evaluate_rule_based_threats(row: pd.Series) -> Tuple[str, List[str]]:
    """
    Applies deterministic cyber threat detection rules to an IIoT log entry.

    Rules:
    1. Repeated failed logins (Brute-force / Credential Stuffing)
    2. Unusually high network traffic (DDoS / Data Exfiltration)
    3. Suspicious source IP address (External / Rogue nodes)
    4. Abnormal device activity (Malicious event types)
    5. Unusual connection events (Port scans, SSH floods)
    6. Failed or unexpected critical device operations

    Returns:
        Tuple of (rule_level: str, rule_reasons: List[str])
        rule_level is one of: 'None', 'Low', 'Medium', 'High', 'Critical'
    """
    reasons: List[str] = []
    severity_scores: List[int] = []  # 0=None, 1=Low, 2=Med, 3=High, 4=Critical

    failed_logins = int(row.get("failed_logins", 0))
    network_traffic = float(row.get("network_traffic", 0.0))
    source_ip = str(row.get("source_ip", ""))
    event_type = str(row.get("event_type", "")).lower()
    status = str(row.get("status", "")).lower()

    # Rule 1: Repeated failed logins
    if failed_logins >= 8:
        severity_scores.append(4)
        reasons.append(f"Severe brute-force attack detected ({failed_logins} failed logins)")
    elif failed_logins >= 5:
        severity_scores.append(3)
        reasons.append(f"Repeated failed logins detected ({failed_logins} attempts)")
    elif failed_logins >= 3:
        severity_scores.append(2)
        reasons.append(f"Elevated failed login threshold reached ({failed_logins} attempts)")
    elif failed_logins in (1, 2) and status in ("failed", "rejected"):
        severity_scores.append(1)
        reasons.append(f"Failed authentication attempt ({failed_logins} attempt(s))")

    # Rule 2: Unusually high network traffic
    if network_traffic >= 20000.0:
        severity_scores.append(4)
        reasons.append(f"Massive network traffic spike ({network_traffic:,.1f} KB) - Possible Volumetric DDoS / Exfiltration")
    elif network_traffic >= 5000.0:
        severity_scores.append(3)
        reasons.append(f"Unusually high network traffic ({network_traffic:,.1f} KB) - Abnormal bandwidth consumption")
    elif network_traffic >= 1500.0:
        severity_scores.append(2)
        reasons.append(f"Elevated network traffic volume ({network_traffic:,.1f} KB)")

    # Rule 3: Suspicious source IP address
    if any(source_ip.startswith(prefix) for prefix in SUSPICIOUS_IP_PREFIXES):
        # Check if external untrusted network
        severity_scores.append(3)
        reasons.append(f"Untrusted or hostile source IP address flagged ({source_ip})")

    # Rule 4: Abnormal device activity (Severe attack payloads)
    if event_type in CRITICAL_EVENT_TYPES:
        severity_scores.append(4)
        reasons.append(f"Critical industrial exploit event type detected ({event_type})")

    # Rule 5: Unusual connection events
    if event_type in SUSPICIOUS_EVENT_TYPES:
        severity_scores.append(3)
        reasons.append(f"Suspicious network connection behavior detected ({event_type})")

    # Rule 6: Failed or unexpected critical device operations
    if status in ("failed", "error", "timeout", "rejected") and event_type in CRITICAL_OPERATIONS:
        severity_scores.append(2)
        reasons.append(f"Unexpected operational failure on critical device operation ({event_type} ended with status '{status}')")

    if not severity_scores:
        return "None", []

    max_severity = max(severity_scores)
    # Escalate if multiple moderate/high triggers fire together
    if max_severity >= 4 or (severity_scores.count(3) >= 2):
        level = "Critical"
    elif max_severity == 3 or (severity_scores.count(2) >= 2):
        level = "High"
    elif max_severity == 2:
        level = "Medium"
    else:
        level = "Low"

    return level, reasons


def run_isolation_forest(
    df: pd.DataFrame, contamination: float = 0.1, random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, str]:
    """
    Fits Scikit-Learn Isolation Forest on quantitative IIoT telemetry features
    (network_traffic and failed_logins).

    Returns:
        Tuple of:
            predictions (np.ndarray): 1 for inlier, -1 for outlier/anomaly
            anomaly_scores (np.ndarray): continuous score from decision_function
            status_message (str): Information regarding training execution
    """
    n_samples = len(df)
    if n_samples < 10:
        # Avoid fitting on insufficient datasets
        return (
            np.ones(n_samples, dtype=int),
            np.zeros(n_samples, dtype=float),
            "Dataset has fewer than 10 records. Machine learning anomaly detection skipped.",
        )

    # Feature matrix: network_traffic and failed_logins
    features = df[["network_traffic", "failed_logins"]].copy()

    # Check for zero variance (all values identical)
    if features["network_traffic"].std() == 0 and features["failed_logins"].std() == 0:
        return (
            np.ones(n_samples, dtype=int),
            np.zeros(n_samples, dtype=float),
            "Feature variance is zero. Machine learning anomaly detection skipped.",
        )

    try:
        model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        model.fit(features)
        predictions = model.predict(features)
        anomaly_scores = model.decision_function(features)
        return (
            predictions,
            anomaly_scores,
            f"Isolation Forest successfully trained on {n_samples} records.",
        )
    except Exception as exc:
        return (
            np.ones(n_samples, dtype=int),
            np.zeros(n_samples, dtype=float),
            f"ML model error: {str(exc)}. Falling back to rule-based detection.",
        )


def combine_detection_results(
    rule_level: str,
    rule_reasons: List[str],
    ml_is_anomaly: bool,
    ml_score: float,
) -> Tuple[bool, str, str]:
    """
    Fuses deterministic rule-based triggers and Isolation Forest anomaly predictions
    to produce a final risk classification and an informative explanation.

    Returns:
        Tuple of (is_suspicious: bool, risk_level: str, final_reason: str)
        risk_level is one of: 'Normal', 'Low', 'Medium', 'High', 'Critical'
    """
    all_reasons: List[str] = []

    for r in rule_reasons:
        all_reasons.append(f"[Rule] {r}")

    if ml_is_anomaly:
        all_reasons.append(
            f"[ML Anomaly] Isolation Forest flagged unusual pattern (score: {ml_score:.3f})"
        )

    # Determine consolidated risk level
    if rule_level == "Critical":
        risk_level = "Critical"
    elif rule_level == "High":
        if ml_is_anomaly:
            risk_level = "Critical"  # Severe rule verified by ML anomaly
        else:
            risk_level = "High"
    elif rule_level == "Medium":
        if ml_is_anomaly:
            risk_level = "High"
        else:
            risk_level = "Medium"
    elif rule_level == "Low":
        if ml_is_anomaly:
            risk_level = "Medium"
        else:
            risk_level = "Low"
    else:  # rule_level == "None"
        if ml_is_anomaly:
            # Significant anomaly without explicit matching rule
            risk_level = "Medium"
        else:
            risk_level = "Normal"

    is_suspicious = risk_level != "Normal"

    if is_suspicious:
        final_reason = "; ".join(all_reasons)
    else:
        final_reason = "[Normal] All parameters within expected industrial baseline thresholds."

    return is_suspicious, risk_level, final_reason


def analyze_logs(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Primary pipeline function:
    1. Validates input DataFrame.
    2. Runs rule-based detection per record.
    3. Fits and scores with Isolation Forest.
    4. Combines results and assigns risk levels.
    5. Computes overall batch statistics.

    Returns:
        Tuple of (analyzed_df: pd.DataFrame, stats: Dict[str, Any])
    """
    is_valid, err_msg, cleaned_df = validate_log_dataframe(df)
    if not is_valid:
        raise ValueError(err_msg)

    analyzed = cleaned_df.copy()

    # 1. Rule-based analysis
    rule_results = [evaluate_rule_based_threats(row) for _, row in analyzed.iterrows()]
    rule_levels = [res[0] for res in rule_results]
    rule_reasons_list = [res[1] for res in rule_results]

    # 2. Machine Learning Anomaly Detection
    ml_preds, ml_scores, ml_status = run_isolation_forest(analyzed)
    ml_anomalies = ml_preds == -1

    # 3. Combine results
    is_suspicious_list: List[int] = []
    risk_level_list: List[str] = []
    reasons_list: List[str] = []
    rule_flagged_list: List[int] = []
    ml_flagged_list: List[int] = []

    for idx in range(len(analyzed)):
        r_level = rule_levels[idx]
        r_reasons = rule_reasons_list[idx]
        m_anomaly = bool(ml_anomalies[idx])
        m_score = float(ml_scores[idx])

        suspicious, risk, reason = combine_detection_results(
            r_level, r_reasons, m_anomaly, m_score
        )

        is_suspicious_list.append(1 if suspicious else 0)
        risk_level_list.append(risk)
        reasons_list.append(reason)
        rule_flagged_list.append(1 if r_level != "None" else 0)
        ml_flagged_list.append(1 if m_anomaly else 0)

    analyzed["is_suspicious"] = is_suspicious_list
    analyzed["risk_level"] = risk_level_list
    analyzed["detection_reason"] = reasons_list
    analyzed["ml_anomaly_score"] = [round(float(s), 4) for s in ml_scores]
    analyzed["rule_flagged"] = rule_flagged_list
    analyzed["ml_flagged"] = ml_flagged_list

    # Compute summary statistics
    total_logs = len(analyzed)
    suspicious_count = int(analyzed["is_suspicious"].sum())
    normal_count = total_logs - suspicious_count

    stats = {
        "total_logs": total_logs,
        "normal_events": normal_count,
        "suspicious_events": suspicious_count,
        "critical_alerts": int((analyzed["risk_level"] == "Critical").sum()),
        "high_risk_alerts": int((analyzed["risk_level"] == "High").sum()),
        "medium_risk_alerts": int((analyzed["risk_level"] == "Medium").sum()),
        "low_risk_alerts": int((analyzed["risk_level"] == "Low").sum()),
        "ml_status": ml_status,
    }

    return analyzed, stats

