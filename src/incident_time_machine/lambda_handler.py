"""AWS Lambda handler for Incident Time Machine.

Accepts JSON log events directly, validates the request, executes the deterministic
reconstruction engine, and returns a structured analysis report.

Does NOT require Gemini credentials, external network access, or the Strands SDK.
Compatible with standard AWS Lambda Python runtimes (Python 3.11, 3.12, 3.13).
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

from .engine import IncidentTimeMachine
from .models import AnalysisReport


def _extract_logs_from_event(event: Any) -> List[Dict[str, Any]]:
    """Extract and validate raw log records from various AWS Lambda event envelopes.

    Supports:
    1. Direct list: `[{"timestamp": ..., ...}, ...]`
    2. Direct dict with 'logs', 'records', or 'events': `{"logs": [...]}`
    3. API Gateway / Lambda Function URL envelope: `{"body": "{\"logs\": [...]}"}`
    4. Amazon Bedrock Agent Action Group requestBody envelope

    Raises:
        ValueError: If event format is invalid or cannot be parsed into a log list.
    """
    if event is None:
        raise ValueError("Event payload cannot be None.")

    # Case 1: Event passed as raw JSON string
    if isinstance(event, str):
        event_str = event.strip()
        if not event_str:
            raise ValueError("Event string payload cannot be empty.")
        try:
            event = json.loads(event_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in event payload: {exc}")

    # Case 2: Event is directly a list of log entries
    if isinstance(event, list):
        return event

    if not isinstance(event, dict):
        raise ValueError(f"Expected event dict or list, got {type(event).__name__}.")

    # Case 3: API Gateway / Lambda Function URL envelope with "body"
    if "body" in event:
        body = event["body"]
        if body is None:
            raise ValueError("HTTP request body cannot be None.")

        if isinstance(body, str):
            if event.get("isBase64Encoded", False):
                try:
                    body = base64.b64decode(body).decode("utf-8")
                except Exception as exc:
                    raise ValueError(f"Failed to decode base64 body: {exc}")

            body_str = body.strip()
            if not body_str:
                raise ValueError("HTTP request body string cannot be empty.")
            try:
                parsed_body = json.loads(body_str)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in HTTP request body: {exc}")
        elif isinstance(body, (dict, list)):
            parsed_body = body
        else:
            raise ValueError(f"Unexpected type for 'body': {type(body).__name__}.")

        # Recursively extract from parsed body
        return _extract_logs_from_event(parsed_body)

    # Case 4: Amazon Bedrock Agent Action Group envelope
    if "requestBody" in event and isinstance(event["requestBody"], dict):
        req_body = event["requestBody"]
        content = req_body.get("content", {})
        json_content = content.get("application/json", {})
        if "properties" in json_content:
            for prop in json_content["properties"]:
                if prop.get("name") in {"logs", "records", "events"}:
                    val = prop.get("value")
                    if isinstance(val, str):
                        val = json.loads(val)
                    if isinstance(val, list):
                        return val

    # Case 5: Standard dict keys
    for key in ("logs", "records", "events"):
        if key in event:
            candidate = event[key]
            if isinstance(candidate, list):
                return candidate
            if isinstance(candidate, str):
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, list):
                        return parsed
                except json.JSONDecodeError:
                    pass
            raise ValueError(f"Field '{key}' must be a list of log records.")

    raise ValueError(
        "Invalid event structure. Expected a list of logs or a dict containing 'logs', 'records', 'events', or 'body'."
    )


def lambda_handler(event: Any, context: Any = None) -> Dict[str, Any]:
    """Main AWS Lambda handler entrypoint.

    Args:
        event: Lambda invocation event (direct payload, API Gateway proxy, or Bedrock Action Group).
        context: Lambda execution context (AWS Lambda runtime object).

    Returns:
        Structured response compatible with both API Gateway and direct Lambda invocation:
        - 200: Successfully parsed and analyzed timeline report
        - 400: Bad Request / malformed event envelope
        - 500: Unexpected internal error
    """
    try:
        raw_logs = _extract_logs_from_event(event)
    except ValueError as exc:
        error_payload = {
            "error_code": "BAD_REQUEST",
            "message": str(exc),
        }
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(error_payload),
            "error": error_payload,
        }
    except Exception as exc:
        error_payload = {
            "error_code": "INTERNAL_ERROR",
            "message": f"Unexpected error during event extraction: {str(exc)}",
        }
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(error_payload),
            "error": error_payload,
        }

    try:
        # Run the deterministic reconstruction engine
        engine = IncidentTimeMachine(raw_records=raw_logs)
        report: AnalysisReport = engine.analyze()
        report_dict = report.to_dict()

        # Build response compatible with API Gateway and direct invocation
        response_body = {
            "status": "success",
            "report": report_dict,
        }

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response_body),
            "status": "success",
            "report": report_dict,
        }
    except Exception as exc:
        error_payload = {
            "error_code": "ENGINE_ERROR",
            "message": f"Deterministic engine failed: {str(exc)}",
        }
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(error_payload),
            "error": error_payload,
        }
