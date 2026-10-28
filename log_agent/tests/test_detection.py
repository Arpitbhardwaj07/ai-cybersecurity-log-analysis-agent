"""Unit tests for deterministic Stage A detection rules and CSV validation."""

import os
import tempfile
from datetime import datetime, timezone
import pandas as pd
import pytest

from generate_logs import generate_logs
from src.detection import (
    BURST_COUNT_THRESHOLD,
    BURST_WINDOW_MINUTES,
    deduplicate_findings,
    detect_findings,
    validate_logs,
)
from src.schemas import Finding


@pytest.fixture(scope="module")
def sample_dataset():
    """Generate a temporary dataset for detection testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "test_logs.csv")
        gt_path = os.path.join(tmpdir, "test_gt.json")
        generate_logs(csv_path, gt_path, seed=42)
        df = pd.read_csv(csv_path)
        yield df


def test_validation_missing_columns():
    """Verify validate_logs raises ValueError when columns are missing."""
    df_missing = pd.DataFrame({
        "timestamp": ["2026-10-15T12:00:00Z"],
        "source_ip": ["192.168.1.1"],
        "username": ["alice"],
    })
    with pytest.raises(ValueError, match="missing required columns"):
        validate_logs(df_missing)


def test_validation_invalid_timestamp():
    """Verify validate_logs raises ValueError on unparseable timestamps."""
    df_invalid_time = pd.DataFrame({
        "timestamp": ["not-a-timestamp"],
        "source_ip": ["192.168.1.1"],
        "username": ["alice"],
        "event_type": ["login_failed"],
        "status": ["failure"],
        "host": ["auth-srv"],
    })
    with pytest.raises(ValueError, match="Invalid timestamp format"):
        validate_logs(df_invalid_time)


def test_validation_invalid_ip():
    """Verify validate_logs raises ValueError on invalid IP format."""
    df_invalid_ip = pd.DataFrame({
        "timestamp": ["2026-10-15T12:00:00Z"],
        "source_ip": ["999.999.999.999"],
        "username": ["alice"],
        "event_type": ["login_failed"],
        "status": ["failure"],
        "host": ["auth-srv"],
    })
    with pytest.raises(ValueError, match="Malformed or invalid IP address"):
        validate_logs(df_invalid_ip)


def test_validation_invalid_event_type():
    """Verify validate_logs raises ValueError on unsupported event_type."""
    df_invalid_event = pd.DataFrame({
        "timestamp": ["2026-10-15T12:00:00Z"],
        "source_ip": ["192.168.1.1"],
        "username": ["alice"],
        "event_type": ["privilege_escalation"],
        "status": ["success"],
        "host": ["auth-srv"],
    })
    with pytest.raises(ValueError, match="Invalid event_type found"):
        validate_logs(df_invalid_event)


def test_detection_rules_against_scenarios(sample_dataset):
    """Verify detection identifies all five scenarios from the generated dataset."""
    findings = detect_findings(sample_dataset)
    assert len(findings) >= 5

    rules_triggered = {f.rule for f in findings}
    assert "failed_then_success" in rules_triggered
    assert "password_spraying" in rules_triggered
    assert "off_hours_login" in rules_triggered
    assert "multi_ip_account" in rules_triggered

    # Verify Scenario 1 (Brute force IP 198.51.100.45)
    s1_find = next((f for f in findings if f.ip == "198.51.100.45"), None)
    assert s1_find is not None
    assert s1_find.rule == "failed_then_success"
    assert s1_find.severity_score >= 80

    # Verify Scenario 2 (Password Spraying IP 203.0.113.88)
    s2_find = next((f for f in findings if f.ip == "203.0.113.88"), None)
    assert s2_find is not None
    assert s2_find.rule == "password_spraying"
    assert s2_find.severity_score >= 80

    # Verify Scenario 3 (Off-hours admin.carol)
    s3_find = next((f for f in findings if f.username == "admin.carol" and f.rule == "off_hours_login"), None)
    assert s3_find is not None
    assert s3_find.severity_score >= 70

    # Verify Scenario 4 (Multi IP user executive.dan)
    s4_find = next((f for f in findings if f.username == "executive.dan" and f.rule == "multi_ip_account"), None)
    assert s4_find is not None
    assert s4_find.severity_score >= 80

    # Verify Scenario 5 (Benign noisy user charlie.brown)
    s5_find = next((f for f in findings if f.username == "charlie.brown"), None)
    assert s5_find is not None
    assert s5_find.metadata.get("is_private_ip") is True


def test_deduplication_overlapping_findings():
    """Verify deduplicate_findings collapses overlapping bursts into single finding."""
    f1 = Finding(
        id="f1",
        rule="failed_login_burst",
        severity_score=60.0,
        ip="198.51.100.45",
        username="user1",
        start_time="2026-10-15T12:00:00Z",
        end_time="2026-10-15T12:08:00Z",
        description="Burst 1",
        metadata={"failed_login_count": 15},
    )
    f2 = Finding(
        id="f2",
        rule="failed_then_success",
        severity_score=85.0,
        ip="198.51.100.45",
        username="user1",
        start_time="2026-10-15T12:05:00Z",
        end_time="2026-10-15T12:12:00Z",
        description="Burst followed by success",
        metadata={"success_occurred": True},
    )

    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 1
    assert merged[0].rule == "failed_then_success"
    assert merged[0].severity_score == 85.0
    assert merged[0].metadata["success_occurred"] is True
    assert merged[0].metadata["failed_login_count"] == 15

