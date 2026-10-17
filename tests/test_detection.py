"""
Unit Tests for IIoT Threat Detection Engine
Tests input validation, rule-based detection, Scikit-learn Isolation Forest,
edge cases (empty datasets, missing columns), and combined threat classification.
"""

import pytest
import numpy as np
import pandas as pd

from detection import (
    REQUIRED_COLUMNS,
    validate_log_dataframe,
    evaluate_rule_based_threats,
    run_isolation_forest,
    combine_detection_results,
    analyze_logs,
)


@pytest.fixture
def base_valid_record():
    return {
        "timestamp": "2026-03-10 10:00:00",
        "device_id": "PLC-TEST-01",
        "source_ip": "192.168.1.50",
        "event_type": "telemetry_read",
        "failed_logins": 0,
        "network_traffic": 45.0,
        "status": "success",
    }


@pytest.fixture
def synthetic_normal_dataset(base_valid_record):
    """Generates a dataset of 25 normal baseline industrial telemetry logs."""
    rows = []
    for i in range(25):
        rec = base_valid_record.copy()
        rec["timestamp"] = f"2026-03-10 10:{i:02d}:00"
        rec["network_traffic"] = 30.0 + (i * 2.5)  # Normal variation 30 - 90 KB
        rows.append(rec)
    return pd.DataFrame(rows)


# =========================================================================
# 1. Input Validation Tests
# =========================================================================

def test_missing_required_columns():
    """Verify that DataFrames missing required columns are rejected with descriptive error."""
    invalid_df = pd.DataFrame({
        "timestamp": ["2026-03-10 10:00:00"],
        "device_id": ["PLC-01"],
        # Missing source_ip, event_type, failed_logins, network_traffic, status
    })
    is_valid, err_msg, _ = validate_log_dataframe(invalid_df)
    assert not is_valid
    assert "Missing required column" in err_msg
    assert "source_ip" in err_msg


def test_empty_dataset_validation():
    """Verify that an empty DataFrame triggers an explicit validation failure."""
    empty_df = pd.DataFrame()
    is_valid, err_msg, _ = validate_log_dataframe(empty_df)
    assert not is_valid
    assert "empty" in err_msg.lower()

    # Also test empty with correct columns
    empty_with_cols = pd.DataFrame(columns=REQUIRED_COLUMNS)
    is_valid2, err_msg2, _ = validate_log_dataframe(empty_with_cols)
    assert not is_valid2
    assert "empty" in err_msg2.lower()


def test_missing_values_and_type_coercion():
    """Verify that missing/malformed numeric fields are coerced safely without crashing."""
    dirty_df = pd.DataFrame([{
        "timestamp": "2026-03-10 10:00:00",
        "device_id": "PLC-DIRTY-01",
        "source_ip": "192.168.1.10",
        "event_type": "telemetry_read",
        "failed_logins": "invalid_number",  # malformed string
        "network_traffic": None,             # None value
        "status": "success",
    }])
    is_valid, err_msg, cleaned_df = validate_log_dataframe(dirty_df)
    assert is_valid
    assert err_msg == ""
    assert cleaned_df["failed_logins"].iloc[0] == 0
    assert cleaned_df["network_traffic"].iloc[0] == 0.0


# =========================================================================
# 2. Rule-Based Threat Detection Tests
# =========================================================================

def test_rule_normal_log(base_valid_record):
    """Verify that normal operational events trigger no rule warnings."""
    level, reasons = evaluate_rule_based_threats(pd.Series(base_valid_record))
    assert level == "None"
    assert len(reasons) == 0


def test_rule_repeated_failed_logins(base_valid_record):
    """Verify detection of repeated failed login attempts (brute force)."""
    # 3 failed logins: Medium
    rec_med = base_valid_record.copy()
    rec_med["failed_logins"] = 3
    rec_med["status"] = "failed"
    level_med, reasons_med = evaluate_rule_based_threats(pd.Series(rec_med))
    assert level_med == "Medium"
    assert any("3 attempts" in r for r in reasons_med)

    # 5 failed logins: High
    rec_high = base_valid_record.copy()
    rec_high["failed_logins"] = 5
    rec_high["status"] = "failed"
    level_high, reasons_high = evaluate_rule_based_threats(pd.Series(rec_high))
    assert level_high == "High"
    assert any("5 attempts" in r for r in reasons_high)

    # 8+ failed logins: Critical
    rec_crit = base_valid_record.copy()
    rec_crit["failed_logins"] = 10
    rec_crit["status"] = "rejected"
    level_crit, reasons_crit = evaluate_rule_based_threats(pd.Series(rec_crit))
    assert level_crit == "Critical"
    assert any("brute-force" in r.lower() for r in reasons_crit)


def test_rule_high_network_traffic(base_valid_record):
    """Verify detection of abnormal network traffic volume spikes."""
    # Elevated traffic: 2,500 KB -> Medium
    rec_med = base_valid_record.copy()
    rec_med["network_traffic"] = 2500.0
    level_med, reasons_med = evaluate_rule_based_threats(pd.Series(rec_med))
    assert level_med == "Medium"
    assert any("traffic" in r.lower() for r in reasons_med)

    # High traffic: 7,500 KB -> High
    rec_high = base_valid_record.copy()
    rec_high["network_traffic"] = 7500.0
    level_high, reasons_high = evaluate_rule_based_threats(pd.Series(rec_high))
    assert level_high == "High"
    assert any("abnormal bandwidth" in r.lower() for r in reasons_high)

    # Massive volumetric spike: 50,000 KB -> Critical
    rec_crit = base_valid_record.copy()
    rec_crit["network_traffic"] = 50000.0
    level_crit, reasons_crit = evaluate_rule_based_threats(pd.Series(rec_crit))
    assert level_crit == "Critical"
    assert any("DDoS" in r or "Exfiltration" in r for r in reasons_crit)


def test_rule_suspicious_source_ips(base_valid_record):
    """Verify that known threat simulator and untrusted external IPs trigger alerts."""
    for bad_ip in ["198.51.100.22", "203.0.113.88", "185.220.101.4"]:
        rec = base_valid_record.copy()
        rec["source_ip"] = bad_ip
        level, reasons = evaluate_rule_based_threats(pd.Series(rec))
        assert level in ("High", "Critical", "Medium")
        assert any("hostile" in r.lower() or "untrusted" in r.lower() for r in reasons)


def test_rule_critical_event_types(base_valid_record):
    """Verify detection of malicious event types (e.g. firmware tampering, buffer overflow)."""
    malicious_events = [
        "unauthorized_firmware_update",
        "buffer_overflow_attempt",
        "ddos_packet_flood",
        "command_injection",
        "unauthorized_modbus_write",
    ]
    for evt in malicious_events:
        rec = base_valid_record.copy()
        rec["event_type"] = evt
        level, reasons = evaluate_rule_based_threats(pd.Series(rec))
        assert level in ("High", "Critical")
        assert any("exploit" in r.lower() or evt in r for r in reasons)


def test_rule_suspicious_connection_events(base_valid_record):
    """Verify detection of scanning and unauthorized connection events."""
    scan_events = ["port_scan", "ssh_bruteforce", "connection_hijack"]
    for evt in scan_events:
        rec = base_valid_record.copy()
        rec["event_type"] = evt
        level, reasons = evaluate_rule_based_threats(pd.Series(rec))
        assert level in ("High", "Medium", "Critical")
        assert any("suspicious network connection" in r.lower() for r in reasons)


def test_rule_failed_critical_operations(base_valid_record):
    """Verify that failure or timeout of sensitive industrial operations is flagged."""
    rec = base_valid_record.copy()
    rec["event_type"] = "valve_actuation"
    rec["status"] = "error"
    level, reasons = evaluate_rule_based_threats(pd.Series(rec))
    assert level == "Medium"
    assert any("operational failure" in r.lower() for r in reasons)


# =========================================================================
# 3. Isolation Forest Machine Learning Tests
# =========================================================================

def test_isolation_forest_insufficient_samples():
    """Verify that Isolation Forest safely skips execution when samples < 10."""
    small_df = pd.DataFrame([
        {"network_traffic": 50.0, "failed_logins": 0},
        {"network_traffic": 60.0, "failed_logins": 0},
    ])
    preds, scores, msg = run_isolation_forest(small_df)
    assert len(preds) == 2
    assert (preds == 1).all()  # Default inliers
    assert "fewer than 10 records" in msg


def test_isolation_forest_zero_variance():
    """Verify that Isolation Forest handles zero variance without errors."""
    identical_df = pd.DataFrame([
        {"network_traffic": 50.0, "failed_logins": 0} for _ in range(15)
    ])
    preds, scores, msg = run_isolation_forest(identical_df)
    assert len(preds) == 15
    assert (preds == 1).all()
    assert "variance is zero" in msg


def test_isolation_forest_valid_dataset(synthetic_normal_dataset):
    """Verify that Isolation Forest successfully trains on valid dataset and detects outliers."""
    # Add a prominent anomaly to the dataset
    anomaly_row = {
        "timestamp": "2026-03-10 10:30:00",
        "device_id": "PLC-TEST-01",
        "source_ip": "192.168.1.50",
        "event_type": "telemetry_read",
        "failed_logins": 12,
        "network_traffic": 95000.0,
        "status": "success",
    }
    df = pd.concat([synthetic_normal_dataset, pd.DataFrame([anomaly_row])], ignore_index=True)

    preds, scores, msg = run_isolation_forest(df, contamination=0.1)
    assert len(preds) == len(df)
    assert "successfully trained" in msg
    # The extreme anomaly should be detected as an outlier (-1)
    assert preds[-1] == -1


# =========================================================================
# 4. Composite Risk Level and Pipeline Tests
# =========================================================================

def test_risk_level_classification():
    """Verify correct composite risk level hierarchy."""
    # Critical rule -> Critical
    _, risk1, _ = combine_detection_results("Critical", ["Critical trigger"], False, 0.1)
    assert risk1 == "Critical"

    # High rule + ML Anomaly -> Critical
    _, risk2, _ = combine_detection_results("High", ["High trigger"], True, -0.2)
    assert risk2 == "Critical"

    # High rule alone -> High
    _, risk3, _ = combine_detection_results("High", ["High trigger"], False, 0.1)
    assert risk3 == "High"

    # Medium rule + ML Anomaly -> High
    _, risk4, _ = combine_detection_results("Medium", ["Medium trigger"], True, -0.15)
    assert risk4 == "High"

    # Medium rule alone -> Medium
    _, risk5, _ = combine_detection_results("Medium", ["Medium trigger"], False, 0.1)
    assert risk5 == "Medium"

    # ML Anomaly alone (rule level None) -> Medium
    _, risk6, _ = combine_detection_results("None", [], True, -0.18)
    assert risk6 == "Medium"

    # Normal log (no rule, ML normal) -> Normal
    is_susp, risk7, _ = combine_detection_results("None", [], False, 0.15)
    assert not is_susp
    assert risk7 == "Normal"


def test_full_analyze_logs_pipeline(synthetic_normal_dataset):
    """Verify end-to-end analyze_logs execution and statistics computation."""
    # Add an injected threat
    threat_row = {
        "timestamp": "2026-03-10 10:45:00",
        "device_id": "HMI-PANEL-01",
        "source_ip": "198.51.100.45",
        "event_type": "brute_force_login",
        "failed_logins": 8,
        "network_traffic": 65000.0,
        "status": "failed",
    }
    df = pd.concat([synthetic_normal_dataset, pd.DataFrame([threat_row])], ignore_index=True)

    analyzed, stats = analyze_logs(df)

    assert len(analyzed) == 26
    assert stats["total_logs"] == 26
    assert stats["suspicious_events"] >= 1
    assert stats["critical_alerts"] >= 1
    assert "is_suspicious" in analyzed.columns
    assert "risk_level" in analyzed.columns
    assert "detection_reason" in analyzed.columns
    assert "ml_anomaly_score" in analyzed.columns

    # Verify detection reason formatting
    threat_entry = analyzed.iloc[-1]
    assert threat_entry["is_suspicious"] == 1
    assert "Rule" in threat_entry["detection_reason"]

