"""Streamlit Web Application for AI Cybersecurity Log Analysis Agent."""

import io
import os
import sys
from pathlib import Path
import pandas as pd
import streamlit as st

# Configure root path for reliable module imports
app_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(app_dir))

from generate_logs import generate_logs
from src.agent import investigate_all_findings
from src.detection import detect_findings, validate_logs
from src.llm import get_active_provider_name
from src.report import build_plain_text_report
from src.tools import load_logs

st.set_page_config(
    page_title="AI Cybersecurity Log Analysis Agent",
    page_icon="🛡️",
    layout="wide",
)

# -------------------------------------------------------------
# Sidebar: Configuration and Sample Data
# -------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Agent Configuration")
    active_prov = get_active_provider_name()
    st.info(f"**Active LLM Provider:** `{active_prov.upper()}`")

    st.markdown("---")
    st.subheader("📁 Sample Security Dataset")
    if st.button("Use Sample Data", use_container_width=True):
        sample_csv = app_dir / "data" / "logs.csv"
        sample_gt = app_dir / "data" / "ground_truth.json"

        if not sample_csv.exists() or not sample_gt.exists():
            with st.spinner("Generating sample log dataset (5,000+ records)..."):
                generate_logs(str(sample_csv), str(sample_gt))

        df_sample = pd.read_csv(sample_csv)
        st.session_state["loaded_df"] = df_sample
        st.session_state["dataset_source"] = "Sample Data (data/logs.csv)"
        st.session_state.pop("run_summary", None)
        st.success("Sample data loaded successfully!")

    st.markdown("---")
    st.markdown(
        """
        **Investigation Capabilities:**
        - Stage A: Deterministic Pandas Rules
        - Stage B: LangGraph SOC Agent
        - Traceable Tool Execution Trace
        - Hard limit: 6 tool calls / finding
        - Max 10 prioritized findings
        """
    )

# -------------------------------------------------------------
# Main Application Header
# -------------------------------------------------------------
st.title("🛡️ AI Cybersecurity Log Analysis Agent")
st.markdown(
    "Automated SOC log investigation platform. Upload authentication logs to detect suspicious "
    "patterns, investigate anomalies with agentic tools, and generate comprehensive threat reports."
)

# -------------------------------------------------------------
# CSV File Upload & Ingestion
# -------------------------------------------------------------
uploaded_file = st.file_uploader("Upload Authentication Log CSV", type=["csv"])

if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file)
        # Validate CSV schema and data integrity
        validate_logs(raw_df)
        st.session_state["loaded_df"] = raw_df
        st.session_state["dataset_source"] = f"Uploaded File ({uploaded_file.name})"
        st.session_state.pop("run_summary", None)
        st.success("Uploaded CSV passed all validation checks!")
    except Exception as e:
        st.error(f"Validation Failed: {str(e)}")
        st.session_state.pop("loaded_df", None)

current_df = st.session_state.get("loaded_df")

if current_df is not None:
    st.markdown(f"**Current Dataset:** `{st.session_state.get('dataset_source', 'Active Logs')}`")

    # ---------------------------------------------------------
    # Basic Dataset Metrics
    # ---------------------------------------------------------
    col1, col2, col3, col4, col5 = st.columns(5)
    total_rows = len(current_df)
    unique_ips = current_df["source_ip"].nunique()
    unique_users = current_df["username"].nunique()
    login_fails = (current_df["event_type"] == "login_failed").sum()
    login_succs = (current_df["event_type"] == "login_success").sum()

    time_min = current_df["timestamp"].min()[:19]
    time_max = current_df["timestamp"].max()[:19]

    col1.metric("Total Events", f"{total_rows:,}")
    col2.metric("Date Range", f"{time_min.split('T')[0]} to {time_max.split('T')[0]}")
    col3.metric("Unique IPs", unique_ips)
    col4.metric("Unique Users", unique_users)
    col5.metric("Failures vs Success", f"{login_fails} / {login_succs}")

    with st.expander("🔍 Preview Log Entries (First 10 rows)", expanded=False):
        st.dataframe(current_df.head(10), use_container_width=True)

    # ---------------------------------------------------------
    # Stage A & Stage B Analysis Execution
    # ---------------------------------------------------------
    st.markdown("---")
    st.subheader("⚡ Threat Investigation")

    if st.button("🚀 Run Analysis", type="primary", use_container_width=True):
        load_logs(current_df)

        with st.spinner("Executing Stage A: Detecting candidate findings..."):
            candidate_findings = detect_findings(current_df)

        if not candidate_findings:
            st.info("No suspicious candidate findings detected in this dataset.")
        else:
            st.write(
                f"Detected **{len(candidate_findings)}** candidate alerts. Investigating top {min(10, len(candidate_findings))} by severity score..."
            )

            progress_bar = st.progress(0.0)
            status_text = st.empty()

            # Run investigation with progress updates
            top_findings = sorted(candidate_findings, key=lambda f: f.severity_score, reverse=True)[:10]
            summary = investigate_all_findings(
                findings=candidate_findings,
                max_findings=10,
                provider=active_prov,
            )
            progress_bar.progress(1.0)
            status_text.text("Investigation complete!")

            st.session_state["run_summary"] = summary

# -------------------------------------------------------------
# Results Presentation
# -------------------------------------------------------------
summary_res = st.session_state.get("run_summary")

if summary_res is not None:
    st.markdown("---")
    st.header("📊 Investigation Findings & Threat Assessment")

    # Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Investigated Findings", summary_res.investigated_findings)
    m2.metric("Critical Risk", summary_res.risk_counts.get("Critical", 0))
    m3.metric("High Risk", summary_res.risk_counts.get("High", 0))
    m4.metric("Medium Risk", summary_res.risk_counts.get("Medium", 0))
    m5.metric("Low Risk", summary_res.risk_counts.get("Low", 0))

    st.markdown("### Investigated Threat Findings")

    risk_icons = {
        "Critical": "🚨",
        "High": "🔴",
        "Medium": "🟡",
        "Low": "🟢",
    }

    for idx, rep in enumerate(summary_res.finding_reports, start=1):
        icon = risk_icons.get(rep.risk_level, "⚪")
        fallback_badge = " [Deterministic Fallback]" if rep.used_fallback else ""
        label = f"{icon} [{rep.risk_level.upper()}] {rep.title} (Confidence: {int(rep.confidence * 100)}%){fallback_badge}"

        with st.expander(label, expanded=(idx == 1)):
            c_left, c_right = st.columns([1, 1])

            with c_left:
                st.markdown(f"**Finding ID:** `{rep.finding_id}`")
                st.markdown(f"**Hypothesized Attack:** `{rep.attack_type_hypothesis}`")
                st.markdown(f"**Trigger Rule:** `{rep.rule}` (Severity: {rep.severity_score})")
                st.markdown(f"**Fallback Used:** `{rep.used_fallback}`")

                st.markdown("**Evidence Trace:**")
                for ev in rep.evidence:
                    st.markdown(f"- {ev}")

            with c_right:
                st.markdown("**Recommended Defensive Actions:**")
                for a_idx, action in enumerate(rep.recommended_actions, 1):
                    st.markdown(f"**{a_idx}.** {action}")

            st.markdown("---")
            st.markdown(f"**Agent Investigation Tool Calls ({len(rep.investigation_steps)} calls):**")
            if rep.investigation_steps:
                tool_data = []
                for s in rep.investigation_steps:
                    tool_data.append(
                        {
                            "Step": s.call_number,
                            "Tool": s.tool_name,
                            "Arguments": str(s.arguments),
                            "Result Summary": str(s.compact_result)[:150],
                        }
                    )
                st.table(pd.DataFrame(tool_data))
            else:
                st.caption("No tools were called.")

    # ---------------------------------------------------------
    # Download Plain-Text Threat Report
    # ---------------------------------------------------------
    st.markdown("---")
    report_text = build_plain_text_report(summary_res)

    st.download_button(
        label="📥 Download Complete Plain-Text Threat Report",
        data=report_text,
        file_name="cybersecurity_threat_report.txt",
        mime="text/plain",
        use_container_width=True,
    )

