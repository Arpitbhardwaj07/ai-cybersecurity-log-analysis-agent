"""Unit tests for the synthetic security log generator."""

import json
import os
import tempfile
import pandas as pd
import pytest

from generate_logs import generate_logs


def test_generator_determinism():
    """Verify that running generate_logs with the same seed produces identical outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv1 = os.path.join(tmpdir, "logs1.csv")
        gt1 = os.path.join(tmpdir, "gt1.json")
        csv2 = os.path.join(tmpdir, "logs2.csv")
        gt2 = os.path.join(tmpdir, "gt2.json")

        n1, _, _ = generate_logs(csv1, gt1, seed=42)
        n2, _, _ = generate_logs(csv2, gt2, seed=42)

        assert n1 == n2
        with open(csv1, "r", encoding="utf-8") as f1, open(csv2, "r", encoding="utf-8") as f2:
            assert f1.read() == f2.read()

        with open(gt1, "r", encoding="utf-8") as f1, open(gt2, "r", encoding="utf-8") as f2:
            assert json.load(f1) == json.load(f2)


def test_generator_row_count_and_columns():
    """Verify log row count is within 5,000-10,000 range and has all required columns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "logs.csv")
        gt_path = os.path.join(tmpdir, "gt.json")

        total, _, _ = generate_logs(csv_path, gt_path, seed=42)
        assert 5000 <= total <= 10000

        df = pd.read_csv(csv_path)
        required_cols = {"timestamp", "source_ip", "username", "event_type", "status", "host"}
        assert required_cols.issubset(set(df.columns))
        assert len(df) == total


def test_ground_truth_structure_and_scenarios():
    """Verify ground_truth.json has valid structure, metadata, and all five scenarios."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "logs.csv")
        gt_path = os.path.join(tmpdir, "gt.json")

        generate_logs(csv_path, gt_path, seed=42)

        with open(gt_path, "r", encoding="utf-8") as f:
            gt = json.load(f)

        assert "scenarios" in gt
        assert "dataset_metadata" in gt

        scenarios = gt["scenarios"]
        assert len(scenarios) == 5

        scenario_names = [s["name"] for s in scenarios]
        assert "scenario_1_brute_force" in scenario_names
        assert "scenario_2_password_spraying" in scenario_names
        assert "scenario_3_off_hours_admin" in scenario_names
        assert "scenario_4_credential_stuffing_distributed" in scenario_names
        assert "scenario_5_benign_noisy_user" in scenario_names

        for s in scenarios:
            assert "name" in s
            assert "is_malicious" in s
            assert "expected_attack_type" in s
            assert "involved_ips" in s
            assert "involved_usernames" in s

