"""Strands agent tools for Incident Time Machine."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

from strands import tool

from .engine import IncidentTimeMachine

# Security boundary: Resolve the authorized fixtures directory once at module load
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = (_PROJECT_ROOT / "fixtures").resolve()


@tool
def analyze_incident_logs(fixture_name: str) -> Dict[str, Any]:
    """Deterministically analyze log events from a pre-approved fixture file.

    Ingests the log file, validates timestamps and schema, sorts events chronologically,
    correlates request IDs across services, identifies the earliest recorded error, and
    generates evidence-backed hypotheses citing concrete event IDs.

    Args:
        fixture_name: Name or relative path of the JSON fixture file within the authorized
            fixtures directory (e.g. 'incident_out_of_order.json').

    Returns:
        Structured JSON dictionary containing:
        - status: 'success' or 'error'
        - timeline: Chronologically sorted list of events with stable event IDs (evt-0001, etc.)
        - traces: Distributed traces correlated by request_id
        - earliest_recorded_error: Earliest non-healthy event, or null if none
        - hypotheses: Evidence-backed hypotheses citing explicit event IDs with uncertainties
        - unknowns: Telemetry gaps and unmonitored dimensions
        - validation_errors: Quarantined malformed or timezone-naive log entries
    """
    # 1. Argument validation
    if not isinstance(fixture_name, str):
        return {
            "status": "error",
            "error_code": "INVALID_ARGUMENT",
            "message": f"Argument 'fixture_name' must be a string, got {type(fixture_name).__name__}.",
        }

    cleaned_name = fixture_name.strip()
    if not cleaned_name:
        return {
            "status": "error",
            "error_code": "INVALID_ARGUMENT",
            "message": "Argument 'fixture_name' cannot be empty.",
        }

    # Normalize relative paths that start with 'fixtures/' or './fixtures/'
    if cleaned_name.startswith("fixtures/") or cleaned_name.startswith("fixtures\\"):
        cleaned_name = cleaned_name[9:]
    elif cleaned_name.startswith("./fixtures/") or cleaned_name.startswith(".\\fixtures\\"):
        cleaned_name = cleaned_name[11:]

    # 2. Filesystem security boundary: Path Traversal Defense
    # Resolve against FIXTURES_DIR and ensure target strictly resides within FIXTURES_DIR
    target_path = (FIXTURES_DIR / cleaned_name).resolve()

    try:
        target_path.relative_to(FIXTURES_DIR)
    except ValueError:
        return {
            "status": "error",
            "error_code": "ACCESS_DENIED",
            "message": (
                f"Security violation: Access denied. Path '{fixture_name}' escapes the "
                "authorized fixtures directory."
            ),
        }

    # 3. File existence and type checks
    if not target_path.exists():
        return {
            "status": "error",
            "error_code": "FILE_NOT_FOUND",
            "message": f"Fixture file not found in fixtures directory: '{cleaned_name}'.",
        }

    if not target_path.is_file() or target_path.suffix.lower() != ".json":
        return {
            "status": "error",
            "error_code": "INVALID_FILE_TYPE",
            "message": f"File '{cleaned_name}' is not an authorized .json fixture file.",
        }

    # 4. Invoke deterministic engine without duplicating analysis logic
    try:
        engine = IncidentTimeMachine.from_file(target_path)
        report = engine.analyze()
        report_dict = report.to_dict()
        report_dict["status"] = "success"
        report_dict["fixture"] = cleaned_name
        return report_dict
    except Exception as exc:
        return {
            "status": "error",
            "error_code": "ANALYSIS_ERROR",
            "message": f"Failed to analyze log fixture: {str(exc)}",
        }
