"""Incident Time Machine: Deterministic log reconstruction and incident analysis engine."""

# Core deterministic engine (Zero external dependencies)
from .engine import IncidentTimeMachine, format_cli_summary
from .lambda_handler import lambda_handler
from .models import (
    AnalysisReport,
    CorrelatedTrace,
    Event,
    Hypothesis,
    LogLevel,
    ValidationError,
)
from .parser import parse_and_validate_record, parse_records
from .prompts import INCIDENT_AGENT_SYSTEM_PROMPT

__all__ = [
    "IncidentTimeMachine",
    "format_cli_summary",
    "lambda_handler",
    "AnalysisReport",
    "CorrelatedTrace",
    "Event",
    "Hypothesis",
    "LogLevel",
    "ValidationError",
    "parse_and_validate_record",
    "parse_records",
    "INCIDENT_AGENT_SYSTEM_PROMPT",
    # Lazy Strands agent exports
    "FIXTURES_DIR",
    "analyze_incident_logs",
    "invoke_lambda_incident_analysis",
    "DeterministicMockIncidentModel",
    "check_model_provider_status",
    "create_incident_agent",
]


def __getattr__(name: str):
    """Lazy load Strands agent integrations to keep the core engine 100% independent."""
    if name in {"FIXTURES_DIR", "analyze_incident_logs"}:
        from .tools import FIXTURES_DIR, analyze_incident_logs
        return FIXTURES_DIR if name == "FIXTURES_DIR" else analyze_incident_logs
    if name == "invoke_lambda_incident_analysis":
        from .remote_tool import invoke_lambda_incident_analysis
        return invoke_lambda_incident_analysis
    if name in {"DeterministicMockIncidentModel", "check_model_provider_status", "create_incident_agent"}:
        from .agent import (
            DeterministicMockIncidentModel,
            check_model_provider_status,
            create_incident_agent,
        )
        if name == "DeterministicMockIncidentModel":
            return DeterministicMockIncidentModel
        if name == "check_model_provider_status":
            return check_model_provider_status
        return create_incident_agent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

