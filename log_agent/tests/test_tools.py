"""Unit tests for deterministic investigation tools and error handling."""

import os
import tempfile
import pandas as pd
import pytest

from generate_logs import generate_logs
from src.tools import (
    TOOL_REGISTRY,
    check_success_after_failures,
    get_activity_for_ip,
    get_activity_for_user,
    get_failed_logins,
    get_ip_reputation,
    get_time_pattern,
    load_logs,
)


@pytest.fixture(scope="module", autouse=True)
def setup_logs():
    """Load sample logs into tools memory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "test_logs.csv")
        gt_path = os.path.join(tmpdir, "test_gt.json")
        generate_logs(csv_path, gt_path, seed=42)
        load_logs(csv_path)
        yield


def test_tool_registry_completeness():
    """Verify all required tools are present in TOOL_REGISTRY."""
    expected_tools = {
        "get_failed_logins",
        "get_activity_for_ip",
        "get_activity_for_user",
        "check_success_after_failures",
        "get_ip_reputation",
        "get_time_pattern",
    }
    assert expected_tools.issubset(set(TOOL_REGISTRY.keys()))


def test_get_failed_logins_shape_and_limit():
    """Verify get_failed_logins returns compact dictionary with max 10 sample rows."""
    res = get_failed_logins(ip="198.51.100.45")
    assert res["status"] == "success"
    assert res["total_failed_logins"] >= 50
    assert "sample_events" in res
    assert len(res["sample_events"]) <= 10
    assert "first_failure" in res
    assert "last_failure" in res


def test_get_failed_logins_error_handling():
    """Verify get_failed_logins returns error dict on invalid parameters."""
    res_no_args = get_failed_logins()
    assert "error" in res_no_args
    assert res_no_args["status"] == "failed"

    res_invalid_ip = get_failed_logins(ip="invalid.ip.format")
    assert "error" in res_invalid_ip
    assert res_invalid_ip["status"] == "failed"


def test_get_activity_for_ip():
    """Verify get_activity_for_ip output structure and max 10 rows."""
    res = get_activity_for_ip(ip="203.0.113.88")
    assert res["status"] == "success"
    assert res["is_private"] is False
    assert res["total_events"] > 0
    assert len(res["sample_events"]) <= 10
    assert "event_breakdown" in res

    # Test error handling
    err_res = get_activity_for_ip(ip="999.999.999.999")
    assert "error" in err_res


def test_get_activity_for_user():
    """Verify get_activity_for_user output structure and baseline."""
    res = get_activity_for_user(user="admin.carol")
    assert res["status"] == "success"
    assert res["total_events"] > 0
    assert "distinct_ips_count" in res
    assert len(res["sample_events"]) <= 10

    # Test empty username error
    err_res = get_activity_for_user(user="")
    assert "error" in err_res


def test_check_success_after_failures():
    """Verify check_success_after_failures accurately identifies post-burst success."""
    # Scenario 1 IP has failures then success
    res_s1 = check_success_after_failures(ip="198.51.100.45")
    assert res_s1["status"] == "success"
    assert res_s1["success_found"] is True
    assert res_s1["seconds_after_last_failure"] is not None

    # Scenario 2 IP has NO successes
    res_s2 = check_success_after_failures(ip="203.0.113.88")
    assert res_s2["status"] == "success"
    assert res_s2["success_found"] is False


def test_get_ip_reputation():
    """Verify get_ip_reputation correctly classifies private, public, and blocklisted IPs."""
    # Private IP
    res_priv = get_ip_reputation(ip="10.0.1.25")
    assert res_priv["status"] == "success"
    assert res_priv["is_private"] is True
    assert res_priv["reputation"] == "Internal Private"

    # Blocklisted public IP
    res_block = get_ip_reputation(ip="198.51.100.45")
    assert res_block["status"] == "success"
    assert res_block["is_private"] is False
    assert res_block["is_blocklisted"] is True
    assert res_block["reputation"] == "Known Malicious"

    # Clean public IP (neutral)
    res_clean = get_ip_reputation(ip="8.8.8.8")
    assert res_clean["status"] == "success"
    assert res_clean["is_private"] is False
    assert res_clean["is_blocklisted"] is False
    assert "Public" in res_clean["reputation"]

    # Invalid IP
    res_bad = get_ip_reputation(ip="not-an-ip")
    assert "error" in res_bad


def test_get_time_pattern():
    """Verify get_time_pattern evaluates business hours distribution."""
    res = get_time_pattern(entity_type="user", entity_value="admin.carol")
    assert res["status"] == "success"
    assert "business_hours_ratio" in res
    assert 0.0 <= res["business_hours_ratio"] <= 1.0
    assert "hourly_distribution" in res

    # Invalid entity_type
    res_bad_type = get_time_pattern(entity_type="database", entity_value="admin.carol")
    assert "error" in res_bad_type

