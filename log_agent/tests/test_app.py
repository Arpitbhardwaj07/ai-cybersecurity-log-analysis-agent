"""Integration test verifying end-to-end application workflow, analysis, and report export."""

import os
import pandas as pd
import pytest

from generate_logs import generate_logs
from src.agent import investigate_all_findings
from src.detection import detect_findings, validate_logs
from src.report import build_plain_text_report
from src.schemas import RunSummary
from src.tools import load_logs


def test_complete_application_workflow():
    """Verify complete application workflow: data load, validation, detection, investigation, report generation."""
    # 1. Verify sample dataset exists or generate
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    csv_path = os.path.join(data_dir, "logs.csv")
    gt_path = os.path.join(data_dir, "ground_truth.json")

    if not os.path.exists(csv_path) or not os.path.exists(gt_path):
        generate_logs(csv_path, gt_path)

    # 2. Ingest & Validate CSV
    df = pd.read_csv(csv_path)
    is_valid, err = validate_logs(df)
    assert is_valid is True
    assert err is None
    assert len(df) >= 5000

    # 3. Load logs into tools memory
    load_logs(df)

    # 4. Stage A Detection
    candidate_findings = detect_findings(df)
    assert len(candidate_findings) >= 5
    # Verify candidate findings are sorted by severity descending
    for i in range(len(candidate_findings) - 1):
        assert candidate_findings[i].severity_score >= candidate_findings[i + 1].severity_score

    # 5. Stage B Agent Investigation (Mock Mode)
    summary: RunSummary = investigate_all_findings(
        findings=candidate_findings, max_findings=10, provider="mock"
    )
    assert summary.investigated_findings == len(candidate_findings[:10])
    assert summary.risk_counts["Critical"] >= 1
    assert summary.risk_counts["High"] >= 1
    assert summary.risk_counts["Low"] >= 1

    # 6. Report Generation
    report_text = build_plain_text_report(summary)
    assert "CYBERSECURITY LOG ANALYSIS & THREAT REPORT" in report_text
    assert "EXECUTIVE SUMMARY" in report_text
    assert "RISK LEVEL BREAKDOWN" in report_text
    assert "DETAILED FINDING ASSESSMENTS" in report_text
    assert "Investigation Tool Trace" in report_text
    assert "END OF REPORT" in report_text

    # Verify each investigated finding has its details in the report
    for rep in summary.finding_reports:
        assert rep.title in report_text
        assert rep.risk_level.upper() in report_text
        assert rep.attack_type_hypothesis in report_text

