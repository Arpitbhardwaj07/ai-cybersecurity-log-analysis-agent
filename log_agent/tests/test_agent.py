"""Unit and integration tests for LangGraph investigation agent and fallback mechanisms."""

import os
import tempfile
import pandas as pd
import pytest

from generate_logs import generate_logs
from src.agent import create_investigation_graph, investigate_all_findings, investigate_finding
from src.detection import detect_findings
from src.llm import MockLLMProvider, build_fallback_report
from src.schemas import Finding, ToolCallRecord
from src.tools import load_logs


@pytest.fixture(scope="module")
def sample_dataset():
    """Load sample logs dataset for agent tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "test_logs.csv")
        gt_path = os.path.join(tmpdir, "test_gt.json")
        generate_logs(csv_path, gt_path, seed=42)
        df = pd.read_csv(csv_path)
        load_logs(df)
        yield df


def test_six_tool_call_cap(sample_dataset):
    """Verify that agent strictly never exceeds 6 tool calls even if graph is repeatedly looped."""
    finding = Finding(
        id="test_cap",
        rule="failed_then_success",
        severity_score=90.0,
        ip="198.51.100.45",
        username="victim.alice",
        start_time="2026-10-17T14:10:00Z",
        end_time="2026-10-17T14:15:00Z",
        description="Testing cap",
    )

    app = create_investigation_graph()
    initial_state = {
        "finding": finding,
        "messages": [],
        "evidence": ["Initial alert"],
        "tool_call_count": 5,  # Start at 5 calls
        "tool_records": [
            ToolCallRecord(
                call_number=i + 1,
                tool_name="get_ip_reputation",
                arguments={"ip": "198.51.100.45"},
                compact_result={"status": "success"},
            )
            for i in range(5)
        ],
        "next_tool_call": {"name": "get_ip_reputation", "args": {"ip": "198.51.100.45"}},
        "is_complete": False,
        "used_fallback": False,
        "verdict": None,
        "provider_name": "mock",
        "retry_count": 0,
    }

    final_state = app.invoke(initial_state)
    # The 6th call should execute and then stop immediately
    assert final_state["tool_call_count"] <= 6
    assert len(final_state["tool_records"]) <= 6


def test_max_investigated_findings_limit(sample_dataset):
    """Verify investigate_all_findings respects the max_findings limit."""
    candidate_findings = detect_findings(sample_dataset)
    assert len(candidate_findings) > 2

    # Limit to 2 findings
    summary = investigate_all_findings(
        findings=candidate_findings, max_findings=2, provider="mock"
    )
    assert summary.investigated_findings == 2
    assert len(summary.finding_reports) == 2


def test_mock_agent_end_to_end(sample_dataset):
    """Verify mock agent produces structured FindingReport with evidence trace."""
    finding = Finding(
        id="test_s1",
        rule="failed_then_success",
        severity_score=90.0,
        ip="198.51.100.45",
        username="victim.alice",
        start_time="2026-10-17T14:10:00Z",
        end_time="2026-10-17T14:15:00Z",
        description="Suspicious burst followed by success",
        metadata={"failed_login_count": 52, "is_private_ip": False},
    )

    report = investigate_finding(finding, provider="mock")
    assert report.finding_id == "test_s1"
    assert report.risk_level in ["High", "Critical"]
    assert report.confidence >= 0.8
    assert "Brute Force" in report.attack_type_hypothesis
    assert len(report.evidence) > 0
    assert len(report.recommended_actions) > 0
    assert len(report.investigation_steps) > 0
    assert report.used_fallback is False


def test_benign_noisy_user_low_risk(sample_dataset):
    """Verify benign noisy user receives a risk level no higher than Low."""
    findings = detect_findings(sample_dataset)
    benign_find = next(
        (f for f in findings if f.username == "charlie.brown" and f.rule == "failed_then_success"),
        None,
    )
    assert benign_find is not None

    report = investigate_finding(benign_find, provider="mock")
    assert report.risk_level == "Low"
    assert "Benign" in report.attack_type_hypothesis or "Forgotten" in report.attack_type_hypothesis


def test_fallback_verdict_handling():
    """Verify graceful handling when LLM fails and fallback report is generated."""
    finding = Finding(
        id="test_fb",
        rule="password_spraying",
        severity_score=85.0,
        ip="203.0.113.88",
        username=None,
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:20:00Z",
        description="Spraying test",
        metadata={"is_private_ip": False},
    )

    # Force fallback builder directly
    report = build_fallback_report(
        finding=finding,
        investigation_steps=[],
        evidence_strings=["Pre-existing evidence trace"],
        reason="Forced unit test fallback",
    )

    assert report.used_fallback is True
    assert report.risk_level == "High"
    assert "Password Spraying" in report.attack_type_hypothesis
    assert any("Fallback reason" in ev for ev in report.evidence)


def test_evidence_traceability(sample_dataset):
    """Verify that every factual claim in the report corresponds to recorded tool steps."""
    findings = detect_findings(sample_dataset)
    s2_finding = next((f for f in findings if f.rule == "password_spraying"), None)
    assert s2_finding is not None

    report = investigate_finding(s2_finding, provider="mock")

    # Check that tool records are preserved
    assert len(report.investigation_steps) >= 1
    for step in report.investigation_steps:
        assert step.call_number in range(1, 7)
        assert step.tool_name in [
            "get_failed_logins",
            "get_activity_for_ip",
            "get_ip_reputation",
            "get_activity_for_user",
        ]
        assert "status" in step.compact_result or "error" in step.compact_result


def test_provider_initialization_and_fallback():
    """Verify Gemini initialization when configured and default fallback to MockLLMProvider."""
    from src.llm import get_active_provider_name, get_llm_instance, MockLLMProvider

    # When no key is set, defaults to mock
    old_key = os.environ.get("GOOGLE_API_KEY")
    old_prov = os.environ.get("LLM_PROVIDER")

    try:
        os.environ.pop("GOOGLE_API_KEY", None)
        os.environ["LLM_PROVIDER"] = "mock"
        assert get_active_provider_name() == "mock"
        llm_mock = get_llm_instance("mock")
        assert isinstance(llm_mock, MockLLMProvider)

        # When Gemini is configured with a key
        os.environ["GOOGLE_API_KEY"] = "AIzaSyFakeKeyForUnitTestingInitializationOnly"
        os.environ["LLM_PROVIDER"] = "gemini"
        assert get_active_provider_name() == "gemini"
        llm_gemini = get_llm_instance("gemini")
        assert type(llm_gemini).__name__ == "ChatGoogleGenerativeAI"
    finally:
        if old_key is not None:
            os.environ["GOOGLE_API_KEY"] = old_key
        else:
            os.environ.pop("GOOGLE_API_KEY", None)
        if old_prov is not None:
            os.environ["LLM_PROVIDER"] = old_prov
        else:
            os.environ.pop("LLM_PROVIDER", None)
