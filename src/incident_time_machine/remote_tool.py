"""Strands tool for invoking the deployed AWS Lambda Incident Time Machine engine."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
import botocore.exceptions
from strands import tool

from .tools import FIXTURES_DIR

# Default deployed Lambda configuration
DEFAULT_FUNCTION_NAME = "incident-time-machine"
DEFAULT_REGION = "ap-southeast-2"


def resolve_aws_region(explicit_region: Optional[str] = None) -> str:
    """Resolve the target AWS region following standard AWS precedence.

    Order of precedence:
    1. Explicit argument passed to the function/tool
    2. AWS_REGION environment variable
    3. AWS_DEFAULT_REGION environment variable
    4. Region configured in active boto3.Session
    5. Default deployed region: 'ap-southeast-2'
    """
    if explicit_region and explicit_region.strip():
        return explicit_region.strip()

    env_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if env_region and env_region.strip():
        return env_region.strip()

    session_region = boto3.Session().region_name
    if session_region and session_region.strip():
        return session_region.strip()

    return DEFAULT_REGION


@tool
def invoke_lambda_incident_analysis(
    fixture_name: str = "",
    logs: Optional[List[Dict[str, Any]]] = None,
    function_name: str = DEFAULT_FUNCTION_NAME,
    region_name: str = "",
) -> Dict[str, Any]:
    """Invoke the deployed AWS Lambda Incident Time Machine engine to reconstruct incident timelines.

    Calls the remote AWS Lambda function ('incident-time-machine') using boto3 Lambda 'Invoke'
    with InvocationType='RequestResponse'. Decodes the streaming response, validates the report,
    and returns the structured post-mortem timeline.

    Args:
        fixture_name: Optional name of a pre-approved fixture in the local 'fixtures/' directory
            (e.g., 'incident_out_of_order.json'). Must not escape the authorized fixtures directory.
        logs: Optional list of raw log record dictionaries. If provided, sent directly to Lambda.
        function_name: Name or ARN of the deployed AWS Lambda function (default: 'incident-time-machine').
        region_name: AWS region where the Lambda is deployed (default: 'ap-southeast-2').

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
    # 1. Resolve target AWS region
    target_region = resolve_aws_region(region_name)
    target_function = (function_name or DEFAULT_FUNCTION_NAME).strip()

    # 2. Extract payload records (from fixture or direct logs)
    records_to_send: List[Dict[str, Any]] = []

    if logs is not None:
        if not isinstance(logs, list):
            return {
                "status": "error",
                "error_code": "INVALID_ARGUMENT",
                "message": f"Argument 'logs' must be a list of log entries, got {type(logs).__name__}.",
            }
        records_to_send = logs
    elif fixture_name and fixture_name.strip():
        cleaned_name = fixture_name.strip()
        if cleaned_name.startswith("fixtures/") or cleaned_name.startswith("fixtures\\"):
            cleaned_name = cleaned_name[9:]
        elif cleaned_name.startswith("./fixtures/") or cleaned_name.startswith(".\\fixtures\\"):
            cleaned_name = cleaned_name[11:]

        target_path = (FIXTURES_DIR / cleaned_name).resolve()

        # Jail check: prevent path traversal
        try:
            target_path.relative_to(FIXTURES_DIR)
        except ValueError:
            return {
                "status": "error",
                "error_code": "ACCESS_DENIED",
                "message": f"Security violation: Path '{fixture_name}' escapes the authorized fixtures directory.",
            }

        if not target_path.exists():
            return {
                "status": "error",
                "error_code": "FILE_NOT_FOUND",
                "message": f"Fixture file not found: '{cleaned_name}'.",
            }

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if not isinstance(loaded, list):
                return {
                    "status": "error",
                    "error_code": "INVALID_FIXTURE_FORMAT",
                    "message": f"Expected JSON array in fixture '{cleaned_name}', got {type(loaded).__name__}.",
                }
            records_to_send = loaded
        except json.JSONDecodeError as exc:
            return {
                "status": "error",
                "error_code": "INVALID_JSON",
                "message": f"Failed to parse JSON in fixture '{cleaned_name}': {exc}",
            }
    else:
        return {
            "status": "error",
            "error_code": "INVALID_ARGUMENT",
            "message": "Either 'fixture_name' or 'logs' must be provided.",
        }

    # 3. Construct invocation payload matching Lambda handler contract
    lambda_payload = {"logs": records_to_send}
    payload_bytes = json.dumps(lambda_payload).encode("utf-8")

    # 4. Invoke AWS Lambda function
    try:
        lambda_client = boto3.client("lambda", region_name=target_region)
        response = lambda_client.invoke(
            FunctionName=target_function,
            InvocationType="RequestResponse",
            Payload=payload_bytes,
        )
    except botocore.exceptions.NoCredentialsError:
        return {
            "status": "error",
            "error_code": "NO_CREDENTIALS",
            "message": (
                "AWS credentials not configured. Please configure an AWS profile or set "
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY with 'lambda:InvokeFunction' permission "
                f"for function '{target_function}' in region '{target_region}'."
            ),
        }
    except botocore.exceptions.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "CLIENT_ERROR")
        msg = exc.response.get("Error", {}).get("Message", str(exc))
        return {
            "status": "error",
            "error_code": code,
            "message": f"AWS ClientError [{code}] during Lambda invocation: {msg}",
            "region": target_region,
            "function_name": target_function,
        }
    except botocore.exceptions.BotoCoreError as exc:
        return {
            "status": "error",
            "error_code": "AWS_INVOCATION_ERROR",
            "message": f"BotoCoreError during Lambda invocation: {str(exc)}",
            "region": target_region,
            "function_name": target_function,
        }
    except Exception as exc:
        return {
            "status": "error",
            "error_code": "UNEXPECTED_ERROR",
            "message": f"Unexpected error during Lambda invocation: {str(exc)}",
        }

    # 5. Check Lambda outer invocation status
    status_code = response.get("StatusCode")
    if status_code != 200:
        return {
            "status": "error",
            "error_code": "INVOCATION_HTTP_ERROR",
            "message": f"Lambda service returned HTTP status code {status_code}.",
            "region": target_region,
            "function_name": target_function,
        }

    # 6. Check for Lambda execution errors (unhandled exceptions in runtime)
    function_error = response.get("FunctionError")
    payload_stream = response.get("Payload")

    if payload_stream is None:
        return {
            "status": "error",
            "error_code": "EMPTY_PAYLOAD",
            "message": "Lambda response contained an empty Payload stream.",
        }

    try:
        raw_body = payload_stream.read().decode("utf-8")
    except Exception as exc:
        return {
            "status": "error",
            "error_code": "STREAM_DECODE_ERROR",
            "message": f"Failed to read/decode Lambda Payload stream: {exc}",
        }

    try:
        parsed_body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        return {
            "status": "error",
            "error_code": "MALFORMED_JSON_RESPONSE",
            "message": f"Lambda response payload is not valid JSON: {exc}",
            "raw_payload_preview": raw_body[:200],
        }

    if function_error:
        # Runtime crash or unhandled error inside Lambda
        err_msg = parsed_body.get("errorMessage", "Unknown Lambda function execution error")
        err_type = parsed_body.get("errorType", function_error)
        return {
            "status": "error",
            "error_code": "FUNCTION_ERROR",
            "function_error_type": err_type,
            "message": f"Lambda execution failed ({err_type}): {err_msg}",
            "details": parsed_body,
        }

    # 7. Parse the handler's response envelope
    # Standard handler returns: {"statusCode": 200, "status": "success", "report": {...}}
    if isinstance(parsed_body, dict):
        inner_status = parsed_body.get("statusCode")
        if inner_status and inner_status != 200:
            err_info = parsed_body.get("error") or parsed_body.get("body")
            return {
                "status": "error",
                "error_code": "LAMBDA_HANDLER_ERROR",
                "statusCode": inner_status,
                "message": f"Lambda handler returned status {inner_status}: {err_info}",
            }

        # Extract report dictionary
        if "report" in parsed_body and isinstance(parsed_body["report"], dict):
            report_data = parsed_body["report"]
        elif "timeline" in parsed_body:
            # Body is direct report dictionary
            report_data = parsed_body
        else:
            return {
                "status": "error",
                "error_code": "INVALID_REPORT_STRUCTURE",
                "message": "Lambda response missing 'report' or 'timeline' fields.",
                "response_keys": list(parsed_body.keys()),
            }

        # Return standardized successful report
        return {
            "status": "success",
            "execution_mode": "remote_lambda",
            "function_name": target_function,
            "region": target_region,
            "timeline": report_data.get("timeline", []),
            "traces": report_data.get("traces", {}),
            "earliest_recorded_error": report_data.get("earliest_recorded_error"),
            "hypotheses": report_data.get("hypotheses", []),
            "unknowns": report_data.get("unknowns", []),
            "validation_errors": report_data.get("validation_errors", []),
            "unassociated_event_ids": report_data.get("unassociated_event_ids", []),
        }

    return {
        "status": "error",
        "error_code": "UNEXPECTED_RESPONSE_TYPE",
        "message": f"Expected dict from Lambda response, got {type(parsed_body).__name__}.",
    }
