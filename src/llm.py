"""LLM provider abstraction supporting Gemini, Ollama, and Mock providers."""

import json
import os
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

from src.schemas import Finding, FindingReport, ToolCallRecord

load_dotenv()

SYSTEM_PROMPT = """You are a cautious Security Operations Center (SOC) analyst.
Investigate suspicious security log findings using the available tools.
Rules to adhere to strictly:
1. Cite only facts supported by tool results or deterministic finding metadata.
2. Do not invent counts, timestamps, IP reputation, or events.
3. Consider benign explanations such as mistyped passwords, forgotten passwords, and known users authenticating from usual IP addresses.
4. Distinguish suspicious behavior from confirmed compromise.
5. Clearly state uncertainty and evidence gaps.
6. Choose risk_level strictly from: Low, Medium, High, or Critical.
7. Recommend practical, non-disruptive defensive next steps.
8. Never execute destructive or disruptive remediation actions.
"""


def get_active_provider_name() -> str:
    """Determine the active LLM provider based on environment variables."""
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    google_key = os.getenv("GOOGLE_API_KEY", "").strip()

    if provider in ["gemini", "ollama", "mock"]:
        # If user explicitly configured gemini but has no key, fall back to mock
        if provider == "gemini" and (not google_key or google_key == "your_google_api_key_here"):
            return "mock"
        return provider

    # If provider is not explicitly set:
    if google_key and google_key != "your_google_api_key_here":
        return "gemini"
    return "mock"


def build_fallback_report(
    finding: Finding,
    investigation_steps: List[ToolCallRecord],
    evidence_strings: List[str],
    reason: str = "Automated fallback due to LLM response limit or error",
) -> FindingReport:
    """Construct a deterministic rule-based threat assessment fallback."""
    is_private = finding.metadata.get("is_private_ip", False)
    rule = finding.rule

    # Derive verdict deterministically
    if rule == "failed_then_success":
        if is_private:
            title = "Benign Forgotten Password Retries (Internal IP)"
            risk = "Low"
            conf = 0.85
            hypo = "Benign Noise / User Forgotten Password"
            actions = [
                "Verify user was able to log in successfully",
                "Ensure self-service password reset is functioning",
                "No IP blocking required for internal host",
            ]
        else:
            title = "External Brute Force with Confirmed Compromise"
            risk = "Critical" if finding.metadata.get("failed_login_count", 0) >= 30 else "High"
            conf = 0.95
            hypo = "Brute Force Compromise"
            actions = [
                f"Immediately revoke all active sessions for {finding.username}",
                "Force an out-of-band password reset",
                "Enable Multi-Factor Authentication (MFA) immediately",
                f"Review post-compromise activity from IP {finding.ip}",
            ]
    elif rule == "password_spraying":
        title = "Horizontal Password Spraying Campaign"
        risk = "High"
        conf = 0.90
        hypo = "Password Spraying"
        actions = [
            f"Add external IP {finding.ip} to edge firewall drop rule",
            "Audit all targeted accounts for successful logins from other IPs",
            "Review identity lockout thresholds and notify affected users",
        ]
    elif rule == "off_hours_login":
        title = "Anomalous Off-Hours Administrative Login"
        risk = "High" if finding.metadata.get("is_new_ip") else "Medium"
        conf = 0.85
        hypo = "Off-Hours Admin Login"
        actions = [
            f"Verify out-of-band with admin user {finding.username}",
            "Review session audit trail for privilege abuse or unauthorized changes",
            "Enforce conditional access policies restricting off-hours access",
        ]
    elif rule == "multi_ip_account":
        title = "Distributed Credential Stuffing / Account Abuse"
        risk = "Critical"
        conf = 0.92
        hypo = "Credential Stuffing"
        actions = [
            f"Invalidate active sessions immediately for account {finding.username}",
            "Require step-up MFA challenge",
            "Monitor IP pool for coordinated botnet activity",
        ]
    else:
        title = f"Suspicious Activity ({rule})"
        risk = "Medium" if not is_private else "Low"
        conf = 0.70
        hypo = "Suspicious Authentication Anomaly"
        actions = [
            "Monitor account for repeated failure bursts",
            "Check endpoint health and auth logs",
        ]

    # Combine existing evidence with fallback note
    combined_evidence = list(evidence_strings)
    combined_evidence.append(
        f"Deterministic finding baseline: Rule={finding.rule}, Severity={finding.severity_score}, Desc={finding.description}"
    )
    combined_evidence.append(f"Fallback reason: {reason}")

    return FindingReport(
        finding_id=finding.id,
        title=title,
        risk_level=risk,
        confidence=conf,
        attack_type_hypothesis=hypo,
        evidence=combined_evidence,
        recommended_actions=actions,
        investigation_steps=investigation_steps,
        used_fallback=True,
        rule=finding.rule,
        severity_score=finding.severity_score,
    )


class MockLLMProvider:
    """Deterministic scripted mock provider for reproducible offline investigations."""

    def __init__(self):
        self.provider_name = "mock"

    def plan_next_tool(
        self,
        finding: Finding,
        call_count: int,
        executed_tools: List[str],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Determine next tool to call based on finding type and investigation progression."""
        # Hard limit check
        if call_count >= 6:
            return None

        rule = finding.rule
        ip = finding.ip
        user = finding.username

        if rule == "failed_then_success":
            if "check_success_after_failures" not in executed_tools:
                return ("check_success_after_failures", {"ip": ip, "user": user})
            if "get_ip_reputation" not in executed_tools:
                return ("get_ip_reputation", {"ip": ip})
            if "get_activity_for_user" not in executed_tools and user:
                return ("get_activity_for_user", {"user": user})
            return None

        elif rule == "password_spraying":
            if "get_failed_logins" not in executed_tools:
                return ("get_failed_logins", {"ip": ip})
            if "get_ip_reputation" not in executed_tools:
                return ("get_ip_reputation", {"ip": ip})
            if "get_activity_for_ip" not in executed_tools:
                return ("get_activity_for_ip", {"ip": ip})
            return None

        elif rule == "off_hours_login":
            if "get_activity_for_user" not in executed_tools and user:
                return ("get_activity_for_user", {"user": user})
            if "get_time_pattern" not in executed_tools and user:
                return ("get_time_pattern", {"entity_type": "user", "entity_value": user})
            if "get_ip_reputation" not in executed_tools:
                return ("get_ip_reputation", {"ip": ip})
            return None

        elif rule == "multi_ip_account":
            if "get_activity_for_user" not in executed_tools and user:
                return ("get_activity_for_user", {"user": user})
            if "get_failed_logins" not in executed_tools and user:
                return ("get_failed_logins", {"user": user})
            sample_ip = ip or (finding.metadata.get("distinct_ips", [None])[0])
            if sample_ip and "get_ip_reputation" not in executed_tools:
                return ("get_ip_reputation", {"ip": sample_ip})
            return None

        else:
            # Generic burst or other finding
            if "get_failed_logins" not in executed_tools:
                return ("get_failed_logins", {"ip": ip, "user": user})
            if ip and "get_ip_reputation" not in executed_tools:
                return ("get_ip_reputation", {"ip": ip})
            return None

    def generate_final_report(
        self,
        finding: Finding,
        investigation_steps: List[ToolCallRecord],
        evidence_strings: List[str],
    ) -> FindingReport:
        """Produce the structured FindingReport with factual evidence citations."""
        rule = finding.rule
        is_private = finding.metadata.get("is_private_ip", False)

        # Check evidence from tool results
        rep_is_private = None
        for step in investigation_steps:
            if step.tool_name == "get_ip_reputation":
                rep_is_private = step.compact_result.get("is_private")

        is_internal = is_private or (rep_is_private is True)

        if rule == "failed_then_success":
            if is_internal:
                title = "Benign High-Volume Retries (User Forgotten Password)"
                risk = "Low"
                conf = 0.92
                attack_type = "Benign Noise"
                actions = [
                    "Verify user was able to log in successfully from their usual workstation",
                    "No IP blocking or account suspension needed",
                    "Encourage password manager adoption",
                ]
            else:
                title = "Brute Force Attack Resulting in Account Compromise"
                risk = "High" if finding.metadata.get("failed_login_count", 0) < 50 else "Critical"
                conf = 0.96
                attack_type = "Brute Force"
                actions = [
                    f"Immediately isolate and revoke active session tokens for user '{finding.username}'",
                    "Initiate out-of-band credential reset",
                    "Enforce MFA challenge on all subsequent authentication requests",
                    f"Inspect host logs for suspicious commands executed after success from {finding.ip}",
                ]

        elif rule == "password_spraying":
            title = "External Password Spraying Campaign"
            risk = "High"
            conf = 0.94
            attack_type = "Password Spraying"
            actions = [
                f"Rate-limit and block authentication requests from source IP {finding.ip}",
                "Review targeted accounts for password compliance and recent resets",
                "Ensure smart lockout policies are active on external identity endpoints",
            ]

        elif rule == "off_hours_login":
            title = "Anomalous Off-Hours Administrator Login"
            risk = "High"
            conf = 0.90
            attack_type = "Off-Hours Admin Login"
            actions = [
                f"Perform out-of-band verification with administrator '{finding.username}'",
                f"Review administrative audit logs for actions performed from {finding.ip}",
                "Restrict administrative portal access to trusted corporate VPN ranges",
            ]

        elif rule == "multi_ip_account":
            title = "Distributed Credential Stuffing / Account Abuse"
            risk = "Critical"
            conf = 0.95
            attack_type = "Credential Stuffing"
            actions = [
                f"Immediately revoke all active sessions and refresh tokens for '{finding.username}'",
                "Force an immediate password change with mandatory MFA re-registration",
                "Deploy CAPTCHA or proof-of-work challenges on distributed login routes",
            ]

        else:
            title = f"Suspicious Activity ({finding.rule})"
            risk = "Low" if is_internal else "Medium"
            conf = 0.75
            attack_type = "Suspicious Behavior"
            actions = [
                "Continue monitoring account for repeated failures",
                "Review firewall logs for correlated scans",
            ]

        return FindingReport(
            finding_id=finding.id,
            title=title,
            risk_level=risk,
            confidence=conf,
            attack_type_hypothesis=attack_type,
            evidence=evidence_strings,
            recommended_actions=actions,
            investigation_steps=investigation_steps,
            used_fallback=False,
            rule=finding.rule,
            severity_score=finding.severity_score,
        )


def get_llm_instance(provider: Optional[str] = None):
    """Factory to instantiate LLM client for Gemini or Ollama or Mock."""
    prov = (provider or get_active_provider_name()).lower()

    if prov == "gemini":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            api_key = os.getenv("GOOGLE_API_KEY", "")
            model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
            return ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=api_key,
                temperature=0.0,
            )
        except Exception as e:
            # Fall back to mock if initialization fails
            print(f"[Warning] Failed to initialize Gemini model: {e}. Falling back to Mock.")
            return MockLLMProvider()

    elif prov == "ollama":
        try:
            from langchain_ollama import ChatOllama
            model_name = os.getenv("OLLAMA_MODEL", "llama3.1")
            return ChatOllama(model=model_name, temperature=0.0)
        except Exception as e:
            print(f"[Warning] Failed to initialize Ollama model: {e}. Falling back to Mock.")
            return MockLLMProvider()

    return MockLLMProvider()
