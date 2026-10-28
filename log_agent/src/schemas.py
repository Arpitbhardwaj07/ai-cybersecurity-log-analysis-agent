"""Data schemas and Pydantic models for cybersecurity log analysis."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """Represents a suspicious candidate finding identified by deterministic rules."""

    id: str = Field(description="Unique identifier for the finding")
    rule: str = Field(description="Detection rule name that triggered this finding")
    severity_score: float = Field(
        ge=0.0, le=100.0, description="Deterministic severity score between 0 and 100"
    )
    ip: Optional[str] = Field(default=None, description="Involved IP address if applicable")
    username: Optional[str] = Field(
        default=None, description="Involved username if applicable"
    )
    start_time: str = Field(description="ISO formatted start timestamp of the activity")
    end_time: str = Field(description="ISO formatted end timestamp of the activity")
    description: str = Field(description="Short human-readable description of the finding")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Deterministic factual counters and metadata"
    )


class ToolCallRecord(BaseModel):
    """Record of a single tool execution during an investigation."""

    call_number: int = Field(ge=1, le=6, description="Sequential call index (1 to 6)")
    tool_name: str = Field(description="Name of the executed tool")
    arguments: Dict[str, Any] = Field(
        default_factory=dict, description="Validated arguments passed to the tool"
    )
    compact_result: Dict[str, Any] = Field(
        default_factory=dict, description="Compact deterministic tool output"
    )


class FindingReport(BaseModel):
    """Structured threat assessment report for an investigated finding."""

    finding_id: str = Field(description="ID of the investigated candidate finding")
    title: str = Field(description="Descriptive title of the threat assessment")
    risk_level: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Assessed risk level: Low, Medium, High, or Critical"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0"
    )
    attack_type_hypothesis: str = Field(
        description="Hypothesized attack type (e.g., Brute Force, Password Spraying, Credential Stuffing, Off-Hours Admin Login, Benign Noise)"
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="List of factual claims traceable to tool results and finding metadata",
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Practical, non-disruptive defensive remediation actions",
    )
    investigation_steps: List[ToolCallRecord] = Field(
        default_factory=list,
        description="Full ordered trace of tool executions performed",
    )
    used_fallback: bool = Field(
        default=False,
        description="Whether a deterministic fallback was used due to LLM error/limit",
    )
    rule: Optional[str] = Field(
        default=None, description="Original rule name triggering the finding"
    )
    severity_score: Optional[float] = Field(
        default=None, description="Original rule severity score"
    )


class RunSummary(BaseModel):
    """Overall summary of an analysis run."""

    total_findings: int = Field(ge=0, description="Total candidate findings detected")
    investigated_findings: int = Field(
        ge=0, description="Number of findings investigated by the agent"
    )
    risk_counts: Dict[str, int] = Field(
        default_factory=lambda: {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
        description="Finding counts grouped by risk level",
    )
    finding_reports: List[FindingReport] = Field(
        default_factory=list, description="List of structured finding reports"
    )
    execution_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp of when the analysis run finished",
    )
