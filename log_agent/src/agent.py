"""LangGraph-based SOC Analyst agent for investigating candidate security findings."""

import json
from typing import Any, Dict, List, Literal, Optional, TypedDict
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

from src.llm import (
    SYSTEM_PROMPT,
    MockLLMProvider,
    build_fallback_report,
    get_active_provider_name,
    get_llm_instance,
)
from src.schemas import Finding, FindingReport, RunSummary, ToolCallRecord
from src.tools import TOOL_REGISTRY


class AgentState(TypedDict):
    """Investigation state for a single candidate finding."""

    finding: Finding
    messages: List[BaseMessage]
    evidence: List[str]
    tool_call_count: int
    tool_records: List[ToolCallRecord]
    next_tool_call: Optional[Dict[str, Any]]
    is_complete: bool
    used_fallback: bool
    verdict: Optional[FindingReport]
    provider_name: str
    retry_count: int


def create_investigation_graph():
    """Build and compile the LangGraph workflow for finding investigation."""

    def investigate_node(state: AgentState) -> Dict[str, Any]:
        """Agent node: Determines the next tool to invoke or signals completion."""
        # Enforce hard limit of 6 tool calls
        if state["tool_call_count"] >= 6:
            return {
                "is_complete": True,
                "next_tool_call": None,
            }

        finding = state["finding"]
        provider_name = state["provider_name"]
        llm = get_llm_instance(provider_name)

        # Mock provider path
        if isinstance(llm, MockLLMProvider):
            executed_tool_names = [r.tool_name for r in state["tool_records"]]
            plan = llm.plan_next_tool(
                finding=finding,
                call_count=state["tool_call_count"],
                executed_tools=executed_tool_names,
            )
            if plan:
                tool_name, tool_args = plan
                return {
                    "next_tool_call": {"name": tool_name, "args": tool_args},
                    "is_complete": False,
                }
            else:
                return {
                    "is_complete": True,
                    "next_tool_call": None,
                }

        # Live LLM provider path (Gemini / Ollama)
        try:
            # Construct prompt for the LLM
            history_text = "\n".join(state["evidence"]) if state["evidence"] else "None yet."
            prompt = (
                f"Candidate Finding: ID={finding.id}, Rule={finding.rule}, Severity={finding.severity_score}\n"
                f"Description: {finding.description}\n"
                f"Involved IP: {finding.ip}, Username: {finding.username}\n"
                f"Time Window: {finding.start_time} to {finding.end_time}\n"
                f"Finding Metadata: {json.dumps(finding.metadata)}\n\n"
                f"Evidence collected so far:\n{history_text}\n\n"
                f"Tool calls remaining: {6 - state['tool_call_count']}.\n"
                f"Choose the next tool to call, or output 'COMPLETE' if you have gathered sufficient evidence to conclude."
            )

            # Check if LLM supports structured tool binding or text response
            available_tool_names = list(TOOL_REGISTRY.keys())
            system_msg = SystemMessage(
                content=f"{SYSTEM_PROMPT}\nAvailable tools: {available_tool_names}."
            )
            human_msg = HumanMessage(content=prompt)

            response = llm.invoke([system_msg, human_msg])
            resp_text = response.content if hasattr(response, "content") else str(response)

            # Check if model invoked tool calls through LangChain tool_calls attribute
            if hasattr(response, "tool_calls") and response.tool_calls:
                tc = response.tool_calls[0]
                return {
                    "next_tool_call": {"name": tc.get("name"), "args": tc.get("args", {})},
                    "is_complete": False,
                }

            # If text indicates completion
            if "COMPLETE" in str(resp_text).upper():
                return {"is_complete": True, "next_tool_call": None}

            # Attempt simple tool-call fallback parsing if text returned JSON
            try:
                parsed = json.loads(str(resp_text))
                if "tool" in parsed and parsed["tool"] in TOOL_REGISTRY:
                    return {
                        "next_tool_call": {
                            "name": parsed["tool"],
                            "args": parsed.get("args", {}),
                        },
                        "is_complete": False,
                    }
            except Exception:
                pass

            return {"is_complete": True, "next_tool_call": None}

        except Exception as e:
            # On model error, retry once or set fallback
            if state["retry_count"] < 1:
                return {"retry_count": state["retry_count"] + 1}
            return {
                "is_complete": True,
                "used_fallback": True,
                "next_tool_call": None,
            }

    def run_tool_node(state: AgentState) -> Dict[str, Any]:
        """Tool execution node: executes tool, enforces limits, and records compact evidence."""
        count = state["tool_call_count"] + 1
        tool_call = state.get("next_tool_call") or {}
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("args", {})

        new_tool_records = list(state["tool_records"])
        new_evidence = list(state["evidence"])

        # Check if tool is in registry
        if tool_name not in TOOL_REGISTRY:
            compact_res = {
                "error": f"Tool '{tool_name}' is not in authorized TOOL_REGISTRY.",
                "status": "failed",
            }
            new_tool_records.append(
                ToolCallRecord(
                    call_number=count,
                    tool_name=str(tool_name),
                    arguments=tool_args if isinstance(tool_args, dict) else {},
                    compact_result=compact_res,
                )
            )
            new_evidence.append(
                f"Step #{count}: Tool '{tool_name}' failed validation (unauthorized tool name)."
            )
            return {
                "tool_call_count": count,
                "tool_records": new_tool_records,
                "evidence": new_evidence,
                "next_tool_call": None,
            }

        # Execute registered tool safely
        tool_func = TOOL_REGISTRY[tool_name]
        try:
            if isinstance(tool_args, dict):
                raw_res = tool_func(**tool_args)
            else:
                raw_res = {"error": "Invalid arguments format", "status": "failed"}
        except Exception as ex:
            raw_res = {"error": f"Execution exception: {str(ex)}", "status": "failed"}

        # Compact summary of the result
        compact_res = raw_res if isinstance(raw_res, dict) else {"result": str(raw_res)}

        # Format human-readable evidence line
        evidence_summary = _format_evidence_line(count, tool_name, tool_args, compact_res)
        new_evidence.append(evidence_summary)

        new_tool_records.append(
            ToolCallRecord(
                call_number=count,
                tool_name=tool_name,
                arguments=tool_args if isinstance(tool_args, dict) else {},
                compact_result=compact_res,
            )
        )

        return {
            "tool_call_count": count,
            "tool_records": new_tool_records,
            "evidence": new_evidence,
            "next_tool_call": None,
        }

    def assess_node(state: AgentState) -> Dict[str, Any]:
        """Assess node: checks whether to loop back or terminate."""
        if state["tool_call_count"] >= 6 or state["is_complete"]:
            return {"is_complete": True}
        return {}

    def finalize_node(state: AgentState) -> Dict[str, Any]:
        """Finalize node: produces the structured FindingReport."""
        finding = state["finding"]
        provider_name = state["provider_name"]
        llm = get_llm_instance(provider_name)

        if state["used_fallback"] or not isinstance(llm, MockLLMProvider):
            if state["used_fallback"]:
                report = build_fallback_report(
                    finding=finding,
                    investigation_steps=state["tool_records"],
                    evidence_strings=state["evidence"],
                    reason="Model error or fallback triggered",
                )
                return {"verdict": report}

            # Live model structured output
            try:
                structured_llm = llm.with_structured_output(FindingReport)
                sys_msg = SystemMessage(content=SYSTEM_PROMPT)
                evidence_text = "\n".join(state["evidence"])
                user_msg = HumanMessage(
                    content=(
                        f"Produce final threat report for finding {finding.id} ({finding.rule}).\n"
                        f"Description: {finding.description}\n"
                        f"Evidence gathered:\n{evidence_text}\n"
                        f"Provide risk_level, confidence (0.0-1.0), attack_type_hypothesis, "
                        f"evidence list, and recommended actions."
                    )
                )
                report = structured_llm.invoke([sys_msg, user_msg])
                # Ensure fields are properly set
                report.finding_id = finding.id
                report.investigation_steps = state["tool_records"]
                report.used_fallback = False
                report.rule = finding.rule
                report.severity_score = finding.severity_score
                return {"verdict": report}
            except Exception as e:
                # Fallback on failure
                report = build_fallback_report(
                    finding=finding,
                    investigation_steps=state["tool_records"],
                    evidence_strings=state["evidence"],
                    reason=f"Structured output failed: {str(e)}",
                )
                return {"verdict": report, "used_fallback": True}

        # Mock provider final report
        report = llm.generate_final_report(
            finding=finding,
            investigation_steps=state["tool_records"],
            evidence_strings=state["evidence"],
        )
        return {"verdict": report}

    # Conditional edge logic
    def route_after_investigate(state: AgentState) -> Literal["run_tool", "finalize"]:
        if state["is_complete"] or state["tool_call_count"] >= 6:
            return "finalize"
        if state.get("next_tool_call"):
            return "run_tool"
        return "finalize"

    def route_after_assess(state: AgentState) -> Literal["investigate", "finalize"]:
        if state["is_complete"] or state["tool_call_count"] >= 6:
            return "finalize"
        return "investigate"

    workflow = StateGraph(AgentState)
    workflow.add_node("investigate", investigate_node)
    workflow.add_node("run_tool", run_tool_node)
    workflow.add_node("assess", assess_node)
    workflow.add_node("finalize", finalize_node)

    workflow.set_entry_point("investigate")
    workflow.add_conditional_edges("investigate", route_after_investigate)
    workflow.add_edge("run_tool", "assess")
    workflow.add_conditional_edges("assess", route_after_assess)
    workflow.add_edge("finalize", END)

    return workflow.compile()


def _format_evidence_line(
    step_num: int, tool_name: str, args: Dict[str, Any], res: Dict[str, Any]
) -> str:
    """Produce a concise, factual evidence statement traceable to tool results."""
    if res.get("status") == "failed" or "error" in res:
        return f"Step #{step_num} [{tool_name}]: Encountered error: {res.get('error')}"

    if tool_name == "get_failed_logins":
        return (
            f"Step #{step_num} [get_failed_logins]: Found {res.get('total_failed_logins', 0)} failed logins. "
            f"Targeted {res.get('unique_users_count', 0)} users from {res.get('unique_ips_count', 0)} IPs "
            f"(span: {res.get('first_failure')} to {res.get('last_failure')})."
        )
    elif tool_name == "get_ip_reputation":
        return (
            f"Step #{step_num} [get_ip_reputation]: IP {res.get('ip')} is private={res.get('is_private')}, "
            f"public={res.get('is_public')}, blocklisted={res.get('is_blocklisted')} "
            f"(Reputation: '{res.get('reputation')}')."
        )
    elif tool_name == "check_success_after_failures":
        succ = res.get("success_found")
        dt = res.get("seconds_after_last_failure")
        return (
            f"Step #{step_num} [check_success_after_failures]: Success found={succ} "
            f"({dt} seconds after last failure at {res.get('last_failure_time')})."
        )
    elif tool_name == "get_activity_for_user":
        return (
            f"Step #{step_num} [get_activity_for_user]: User '{res.get('username')}' has {res.get('total_events')} total events "
            f"across {res.get('distinct_ips_count')} IPs (Breakdown: {res.get('event_breakdown')})."
        )
    elif tool_name == "get_activity_for_ip":
        return (
            f"Step #{step_num} [get_activity_for_ip]: IP {res.get('ip')} has {res.get('total_events')} events "
            f"targeting {res.get('unique_users_count')} unique users."
        )
    elif tool_name == "get_time_pattern":
        return (
            f"Step #{step_num} [get_time_pattern]: Entity '{res.get('entity_value')}' has {res.get('total_successful_logins')} logins; "
            f"business hours ratio is {res.get('business_hours_ratio')} (predominantly business hours: {res.get('is_predominantly_business_hours')})."
        )
    return f"Step #{step_num} [{tool_name}]: Result summary: {str(res)[:120]}"


def investigate_finding(
    finding: Finding, provider: Optional[str] = None
) -> FindingReport:
    """Run an isolated investigation workflow for a candidate finding."""
    prov_name = (provider or get_active_provider_name()).lower()
    app = create_investigation_graph()

    initial_state: AgentState = {
        "finding": finding,
        "messages": [],
        "evidence": [
            f"Initial candidate alert: Rule='{finding.rule}', Severity={finding.severity_score}, Desc='{finding.description}'"
        ],
        "tool_call_count": 0,
        "tool_records": [],
        "next_tool_call": None,
        "is_complete": False,
        "used_fallback": False,
        "verdict": None,
        "provider_name": prov_name,
        "retry_count": 0,
    }

    final_state = app.invoke(initial_state)
    verdict = final_state.get("verdict")

    if not verdict:
        # Fallback if graph finished without verdict
        verdict = build_fallback_report(
            finding=finding,
            investigation_steps=final_state.get("tool_records", []),
            evidence_strings=final_state.get("evidence", []),
            reason="Graph completed without final report",
        )

    return verdict


def investigate_all_findings(
    findings: List[Finding],
    max_findings: int = 10,
    provider: Optional[str] = None,
) -> RunSummary:
    """Investigate top candidate findings prioritized by severity score (default limit: 10)."""
    # Sort findings by severity score descending
    sorted_findings = sorted(findings, key=lambda f: f.severity_score, reverse=True)
    selected_findings = sorted_findings[:max_findings]

    reports: List[FindingReport] = []
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

    for finding in selected_findings:
        report = investigate_finding(finding=finding, provider=provider)
        reports.append(report)
        risk_level = report.risk_level
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1
        else:
            risk_counts[risk_level] = 1

    return RunSummary(
        total_findings=len(findings),
        investigated_findings=len(reports),
        risk_counts=risk_counts,
        finding_reports=reports,
    )

