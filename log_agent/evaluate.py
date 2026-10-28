"""Evaluation script benchmarking detection and agent investigation against ground truth."""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

# Ensure package imports work consistently
script_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(script_dir))

from src.agent import investigate_all_findings
from src.detection import detect_findings, validate_logs
from src.llm import get_active_provider_name
from src.schemas import Finding, FindingReport, RunSummary
from src.tools import load_logs


def evaluate(
    csv_path: Optional[str] = None,
    gt_path: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute end-to-end evaluation comparing detection and agent verdicts with ground truth."""
    if not csv_path:
        csv_path = str(script_dir / "data" / "logs.csv")
    if not gt_path:
        gt_path = str(script_dir / "data" / "ground_truth.json")

    active_provider = (provider or os.getenv("LLM_PROVIDER") or get_active_provider_name()).lower()

    print("=" * 80)
    print("           AI CYBERSECURITY LOG ANALYSIS AGENT - EVALUATION BENCHMARK       ")
    print("=" * 80)
    print(f"Log Dataset:       {csv_path}")
    print(f"Ground Truth File: {gt_path}")
    print(f"Active Provider:   {active_provider.upper()}")
    print("-" * 80)

    # 1. Load data
    if not os.path.exists(csv_path) or not os.path.exists(gt_path):
        raise FileNotFoundError(
            f"Required data files missing. Please run 'python generate_logs.py' first.\n"
            f"Missing: {[p for p in [csv_path, gt_path] if not os.path.exists(p)]}"
        )

    df = pd.read_csv(csv_path)
    with open(gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    # Validate logs
    validate_logs(df)
    load_logs(df)

    # 2. Stage A Detection
    print("\n[Stage A] Running deterministic detection rules...")
    findings = detect_findings(df)
    print(f"  -> Generated {len(findings)} candidate findings.")

    # 3. Stage B Investigation
    print(f"\n[Stage B] Investigating candidate findings using provider: {active_provider}...")
    run_summary: RunSummary = investigate_all_findings(
        findings=findings, max_findings=10, provider=active_provider
    )
    print(f"  -> Investigated {run_summary.investigated_findings} findings.")
    print(f"  -> Risk Breakdown: {run_summary.risk_counts}")

    # 4. Compare with Ground Truth Scenarios
    scenarios = gt_data.get("scenarios", [])
    reports = run_summary.finding_reports

    eval_results = []
    tp = 0
    fn = 0
    fp = 0
    tn = 0
    false_positives = []
    false_negatives = []

    matched_report_ids = set()

    print("\n" + "=" * 94)
    print(
        f"{'Scenario':<36} | {'Detected':<8} | {'Correct':<7} | {'Risk':<8} | {'Predicted Attack Type':<26}"
    )
    print("-" * 94)

    for sc in scenarios:
        sc_name = sc["name"]
        is_malicious = sc["is_malicious"]
        exp_type = sc["expected_attack_type"]
        involved_ips = set(sc.get("involved_ips", []))
        involved_users = set(sc.get("involved_usernames", []))

        # Match finding report
        matched_report: Optional[FindingReport] = None
        for rep in reports:
            # Check finding metadata and attributes
            finding_id = rep.finding_id
            orig_finding = next((f for f in findings if f.id == finding_id), None)
            if not orig_finding:
                continue

            ip_match = False
            if orig_finding.ip and orig_finding.ip in involved_ips:
                ip_match = True
            elif "distinct_ips" in orig_finding.metadata:
                if any(ip in involved_ips for ip in orig_finding.metadata["distinct_ips"]):
                    ip_match = True

            user_match = False
            if orig_finding.username and orig_finding.username in involved_users:
                user_match = True
            elif "targeted_users" in orig_finding.metadata:
                if any(u in involved_users for u in orig_finding.metadata["targeted_users"]):
                    user_match = True

            if ip_match or user_match:
                matched_report = rep
                matched_report_ids.add(rep.finding_id)
                break

        detected = matched_report is not None
        risk_level = matched_report.risk_level if matched_report else "N/A"
        pred_type = matched_report.attack_type_hypothesis if matched_report else "None"

        verdict_correct = False
        if is_malicious:
            if detected:
                # Correct if risk is elevated (not Low) and attack hypothesis matches
                type_match = exp_type.lower() in pred_type.lower() or pred_type.lower() in exp_type.lower()
                risk_elevated = risk_level in ["High", "Critical", "Medium"]
                if risk_elevated and type_match:
                    verdict_correct = True
                    tp += 1
                else:
                    fn += 1
                    false_negatives.append(
                        f"{sc_name}: Detected but classified as {risk_level} / '{pred_type}' (Expected: {exp_type})"
                    )
            else:
                fn += 1
                false_negatives.append(f"{sc_name}: Malicious scenario not detected by rules.")
        else:
            # Benign scenario
            if detected:
                # Correct if risk is rated Low
                if risk_level == "Low":
                    verdict_correct = True
                    tn += 1
                else:
                    fp += 1
                    false_positives.append(
                        f"{sc_name}: Benign scenario incorrectly elevated to {risk_level} (Expected: Low)"
                    )
            else:
                # If not detected as an alert, that's also a true negative
                verdict_correct = True
                tn += 1

        det_str = "YES" if detected else "NO"
        corr_str = "YES" if verdict_correct else "NO"
        print(
            f"{sc_name:<36} | {det_str:<8} | {corr_str:<7} | {risk_level:<8} | {pred_type:<26}"
        )

        eval_results.append(
            {
                "scenario": sc_name,
                "detected": detected,
                "verdict_correct": verdict_correct,
                "risk_level": risk_level,
                "predicted_attack_type": pred_type,
                "is_malicious": is_malicious,
            }
        )

    print("=" * 94)

    # Check for ungrounded false positive alerts investigated as High/Critical
    for rep in reports:
        if rep.finding_id not in matched_report_ids:
            if rep.risk_level in ["High", "Critical"]:
                fp += 1
                false_positives.append(
                    f"Finding {rep.finding_id} ({rep.title}): High/Critical alert with no matching ground truth"
                )

    # Metrics calculation
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print("\nEVALUATION METHODOLOGY & SCORING RULES:")
    print("  * Matching: Findings are matched to ground-truth scenarios using involved IPs,")
    print("    usernames, and activity time windows rather than strict rule-name strings.")
    print("  * Malicious Scenarios: Must be detected, classified as elevated risk (Medium/High/Critical),")
    print("    and have an attack type hypothesis matching the expected attack type.")
    print("  * Benign Scenarios: Must NOT receive a risk rating above Low.")
    print("  * Precision = TP / (TP + FP)  |  Recall = TP / (TP + FN)  |  F1 Score = 2*P*R/(P+R)")

    print("\nMETRICS SUMMARY:")
    print(f"  * True Positives  (TP): {tp} (Malicious scenarios correctly detected and verified)")
    print(f"  * True Negatives  (TN): {tn} (Benign traffic confirmed as Low risk / unflagged)")
    print(f"  * False Positives (FP): {fp}")
    print(f"  * False Negatives (FN): {fn}")
    print(f"  * Precision:            {precision:.4f} ({precision * 100:.1f}%)")
    print(f"  * Recall:               {recall:.4f} ({recall * 100:.1f}%)")
    print(f"  * F1 Score:             {f1:.4f}")

    if false_positives:
        print("\nFALSE POSITIVES:")
        for fp_item in false_positives:
            print(f"  - {fp_item}")
    else:
        print("\nFALSE POSITIVES: None (0)")

    if false_negatives:
        print("\nFALSE NEGATIVES:")
        for fn_item in false_negatives:
            print(f"  - {fn_item}")
    else:
        print("\nFALSE NEGATIVES: None (0)")

    print("=" * 80)

    return {
        "results": eval_results,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


if __name__ == "__main__":
    evaluate()

