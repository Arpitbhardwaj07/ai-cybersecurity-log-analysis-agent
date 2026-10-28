"""Plain-text threat intelligence report builder for security log investigations."""

import json
from typing import List
from src.schemas import FindingReport, RunSummary


def build_plain_text_report(summary: RunSummary) -> str:
    """Generate a clean, structured plain-text threat report from a RunSummary."""
    lines: List[str] = []

    lines.append("=" * 76)
    lines.append("             CYBERSECURITY LOG ANALYSIS & THREAT REPORT             ")
    lines.append("=" * 76)
    lines.append(f"Execution Timestamp: {summary.execution_timestamp}")
    lines.append(f"Total Candidate Findings Detected: {summary.total_findings}")
    lines.append(f"Findings Investigated by Agent:    {summary.investigated_findings}")
    lines.append("-" * 76)
    lines.append("RISK LEVEL BREAKDOWN:")
    for risk in ["Critical", "High", "Medium", "Low"]:
        count = summary.risk_counts.get(risk, 0)
        lines.append(f"  * {risk:8s}: {count}")
    lines.append("=" * 76)
    lines.append("")

    # Executive Summary section
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 76)
    crit_count = summary.risk_counts.get("Critical", 0)
    high_count = summary.risk_counts.get("High", 0)
    med_count = summary.risk_counts.get("Medium", 0)
    low_count = summary.risk_counts.get("Low", 0)

    if crit_count > 0 or high_count > 0:
        lines.append(
            f"Alert: {crit_count + high_count} priority threat(s) detected requiring prompt response. "
            f"The investigation confirmed high-confidence malicious patterns, including potential brute-force "
            f"compromise, distributed credential abuse, or unauthorized access attempts."
        )
    else:
        lines.append(
            "Overall security posture is stable. Candidate alerts were investigated and determined "
            "to represent either benign noise or low-severity events with no signs of active breach."
        )
    lines.append(
        f"A total of {summary.investigated_findings} high-severity findings were deeply analyzed "
        f"using deterministic audit tools and SOC reasoning workflows."
    )
    lines.append("")

    # Detailed Findings
    lines.append("DETAILED FINDING ASSESSMENTS")
    lines.append("-" * 76)

    if not summary.finding_reports:
        lines.append("No findings were investigated in this run.")
        lines.append("")
    else:
        for idx, rep in enumerate(summary.finding_reports, start=1):
            lines.append(f"[{idx}] Finding ID: {rep.finding_id} - {rep.title}")
            lines.append(f"    Risk Level:        {rep.risk_level.upper()}")
            lines.append(f"    Confidence:        {round(rep.confidence * 100, 1)}%")
            lines.append(f"    Attack Hypothesis: {rep.attack_type_hypothesis}")
            lines.append(f"    Original Rule:     {rep.rule} (Initial Severity: {rep.severity_score})")
            lines.append(f"    Used Fallback:     {'Yes' if rep.used_fallback else 'No'}")
            lines.append("")

            lines.append("    Supporting Evidence:")
            if rep.evidence:
                for ev in rep.evidence:
                    lines.append(f"      - {ev}")
            else:
                lines.append("      - No specific evidence recorded.")
            lines.append("")

            lines.append("    Recommended Defensive Actions:")
            if rep.recommended_actions:
                for a_idx, act in enumerate(rep.recommended_actions, start=1):
                    lines.append(f"      {a_idx}. {act}")
            else:
                lines.append("      1. Continue routine monitoring.")
            lines.append("")

            lines.append(f"    Investigation Tool Trace ({len(rep.investigation_steps)} tool calls):")
            if rep.investigation_steps:
                for step in rep.investigation_steps:
                    args_str = json.dumps(step.arguments, sort_keys=True)
                    res_str = json.dumps(step.compact_result, sort_keys=True)
                    lines.append(f"      Step #{step.call_number}: {step.tool_name}({args_str})")
                    lines.append(f"        -> Result: {res_str}")
            else:
                lines.append("      No tool calls were made.")

            lines.append("-" * 76)
            lines.append("")

    lines.append("=" * 76)
    lines.append("                           END OF REPORT                            ")
    lines.append("=" * 76)

    return "\n".join(lines)
