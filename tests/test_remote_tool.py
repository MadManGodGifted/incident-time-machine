"""Unit tests for the remote AWS Lambda-backed Strands tool."""

import io
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import botocore.exceptions
import boto3
from src.incident_time_machine.agent import (
    DeterministicMockIncidentModel,
    create_incident_agent,
)
from src.incident_time_machine.remote_tool import (
    DEFAULT_FUNCTION_NAME,
    DEFAULT_REGION,
    invoke_lambda_incident_analysis,
    resolve_aws_region,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# Helper to build a streaming mock payload
def _build_streaming_payload(data: dict | str) -> io.BytesIO:
    if isinstance(data, dict):
        encoded = json.dumps(data).encode("utf-8")
    else:
        encoded = data.encode("utf-8")
    return io.BytesIO(encoded)


# ==============================================================================
# Category 1: Successful Lambda Invocations & Envelope Parsing
# ==============================================================================

@patch("boto3.client")
def test_successful_lambda_invocation_with_fixture(mock_boto_client):
    """Verify tool loads fixture, calls Lambda Invoke, and extracts structured incident report."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    mock_report = {
        "status": "success",
        "report": {
            "timeline": [
                {
                    "event_id": "evt-0001",
                    "timestamp": "2026-10-25T08:14:10.000Z",
                    "service": "api-gateway",
                    "level": "INFO",
                    "message": "Incoming request",
                    "request_id": "req-1",
                },
                {
                    "event_id": "evt-0002",
                    "timestamp": "2026-10-25T08:14:15.200Z",
                    "service": "inventory-service",
                    "level": "ERROR",
                    "message": "Connection pool exhausted",
                    "request_id": "req-1",
                },
            ],
            "traces": {"req-1": {"event_ids": ["evt-0001", "evt-0002"], "has_error": True}},
            "earliest_recorded_error": {"event_id": "evt-0002", "service": "inventory-service"},
            "hypotheses": [{"hypothesis_id": "hyp-01", "claim": "Failure in inventory-service", "evidence_event_ids": ["evt-0002"]}],
            "unknowns": ["Host metrics missing"],
            "validation_errors": [],
        },
    }

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": _build_streaming_payload(mock_report),
    }

    result = invoke_lambda_incident_analysis(
        fixture_name="incident_out_of_order.json",
        function_name="incident-time-machine",
        region_name="ap-southeast-2",
    )

    # 1. Verify boto3 client parameters
    mock_boto_client.assert_called_once_with("lambda", region_name="ap-southeast-2")

    # 2. Verify invoke parameters
    mock_lambda.invoke.assert_called_once()
    call_kwargs = mock_lambda.invoke.call_args.kwargs
    assert call_kwargs["FunctionName"] == "incident-time-machine"
    assert call_kwargs["InvocationType"] == "RequestResponse"
    sent_payload = json.loads(call_kwargs["Payload"].decode("utf-8"))
    assert "logs" in sent_payload
    assert len(sent_payload["logs"]) == 12  # 12 entries in incident fixture

    # 3. Verify returned report
    assert result["status"] == "success"
    assert result["execution_mode"] == "remote_lambda"
    assert result["region"] == "ap-southeast-2"
    assert len(result["timeline"]) == 2
    assert result["earliest_recorded_error"]["event_id"] == "evt-0002"
    assert "req-1" in result["traces"]
    assert len(result["hypotheses"]) == 1


@patch("boto3.client")
def test_successful_lambda_invocation_with_direct_logs(mock_boto_client):
    """Verify tool sends directly provided log entries to Lambda."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": _build_streaming_payload({
            "status": "success",
            "report": {
                "timeline": [{"event_id": "evt-0001", "service": "direct-log-service"}],
                "traces": {},
                "earliest_recorded_error": None,
                "hypotheses": [],
                "unknowns": [],
                "validation_errors": [],
            },
        }),
    }

    custom_logs = [{"timestamp": "2026-10-25T10:00:00Z", "service": "direct", "level": "INFO", "message": "test"}]
    result = invoke_lambda_incident_analysis(logs=custom_logs)

    assert result["status"] == "success"
    assert result["function_name"] == DEFAULT_FUNCTION_NAME
    assert result["region"] == DEFAULT_REGION


# ==============================================================================
# Category 2: Lambda Execution Errors & Handler Errors
# ==============================================================================

@patch("boto3.client")
def test_lambda_unhandled_function_error(mock_boto_client):
    """Verify tool detects FunctionError and extracts runtime error details."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    error_response = {
        "errorMessage": "Process ran out of memory (Task timed out after 30.00 seconds)",
        "errorType": "Sandbox.TimedOut",
        "stackTrace": ["File 'lambda_function.py', line 12"],
    }

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "FunctionError": "Unhandled",
        "Payload": _build_streaming_payload(error_response),
    }

    result = invoke_lambda_incident_analysis(fixture_name="healthy_traffic.json")

    assert result["status"] == "error"
    assert result["error_code"] == "FUNCTION_ERROR"
    assert "Sandbox.TimedOut" in result["message"]
    assert "Task timed out" in result["message"]


@patch("boto3.client")
def test_lambda_handler_400_bad_request(mock_boto_client):
    """Verify tool detects inner 400 Bad Request returned by the handler."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    handler_bad_request = {
        "statusCode": 400,
        "error": {
            "error_code": "BAD_REQUEST",
            "message": "Field 'logs' must be a list of log records.",
        },
    }

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": _build_streaming_payload(handler_bad_request),
    }

    result = invoke_lambda_incident_analysis(fixture_name="healthy_traffic.json")

    assert result["status"] == "error"
    assert result["error_code"] == "LAMBDA_HANDLER_ERROR"
    assert result["statusCode"] == 400
    assert "BAD_REQUEST" in result["message"]


@patch("boto3.client")
def test_malformed_lambda_json_payload(mock_boto_client):
    """Verify tool handles non-JSON bytes returned in Lambda Payload."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": _build_streaming_payload("<html>502 Bad Gateway</html>"),
    }

    result = invoke_lambda_incident_analysis(fixture_name="healthy_traffic.json")

    assert result["status"] == "error"
    assert result["error_code"] == "MALFORMED_JSON_RESPONSE"


# ==============================================================================
# Category 3: AWS ClientError & Invocation Exceptions
# ==============================================================================

@patch("boto3.client")
def test_client_error_resource_not_found(mock_boto_client):
    """Verify tool formats ResourceNotFoundException clearly."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    client_error = botocore.exceptions.ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Function not found: incident-time-machine"}},
        "Invoke",
    )
    mock_lambda.invoke.side_effect = client_error

    result = invoke_lambda_incident_analysis(fixture_name="healthy_traffic.json")

    assert result["status"] == "error"
    assert result["error_code"] == "ResourceNotFoundException"
    assert "Function not found" in result["message"]
    assert result["region"] == DEFAULT_REGION


@patch("boto3.client")
def test_client_error_access_denied(mock_boto_client):
    """Verify tool formats AccessDeniedException clearly when lacking lambda:InvokeFunction."""
    mock_lambda = MagicMock()
    mock_boto_client.return_value = mock_lambda

    client_error = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized to perform: lambda:InvokeFunction"}},
        "Invoke",
    )
    mock_lambda.invoke.side_effect = client_error

    result = invoke_lambda_incident_analysis(fixture_name="healthy_traffic.json")

    assert result["status"] == "error"
    assert result["error_code"] == "AccessDeniedException"
    assert "AccessDeniedException" in result["message"]


@patch("boto3.client")
def test_no_credentials_error_guidance(mock_boto_client):
    """Verify tool returns a clean NO_CREDENTIALS error with permission guidance."""
    mock_boto_client.side_effect = botocore.exceptions.NoCredentialsError()

    result = invoke_lambda_incident_analysis(fixture_name="healthy_traffic.json")

    assert result["status"] == "error"
    assert result["error_code"] == "NO_CREDENTIALS"
    assert "lambda:InvokeFunction" in result["message"]
    assert "incident-time-machine" in result["message"]


# ==============================================================================
# Category 4: Security (Path Traversal Defenses & Region Precedence)
# ==============================================================================

def test_remote_tool_rejects_path_traversal_before_aws():
    """Verify path traversal is rejected locally before making any AWS network call."""
    with patch("boto3.client") as mock_boto:
        result = invoke_lambda_incident_analysis(fixture_name="../../etc/passwd")
        assert result["status"] == "error"
        assert result["error_code"] == "ACCESS_DENIED"
        # Boto3 client must not have been created or called
        mock_boto.assert_not_called()


def test_region_resolution_precedence(monkeypatch):
    """Verify region resolution follows: explicit -> AWS_REGION -> AWS_DEFAULT_REGION -> ap-southeast-2."""
    # 1. Default fallback
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    assert resolve_aws_region(None) == "ap-southeast-2"

    # 2. AWS_DEFAULT_REGION
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    assert resolve_aws_region(None) == "us-west-2"

    # 3. AWS_REGION takes precedence over AWS_DEFAULT_REGION
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    assert resolve_aws_region(None) == "eu-central-1"

    # 4. Explicit argument overrides environment
    assert resolve_aws_region("ap-southeast-2") == "ap-southeast-2"


# ==============================================================================
# Category 5: Strands Agent with Remote Lambda Tool
# ==============================================================================

def test_strands_agent_invokes_remote_lambda_tool(monkeypatch):
    """Verify Strands Agent configured with tool_mode='remote' invokes invoke_lambda_incident_analysis."""
    raw_report = {
        "status": "success",
        "timeline": [
            {"event_id": "evt-0001", "service": "api-gateway", "timestamp_iso": "2026-10-25T08:14:10Z"},
            {"event_id": "evt-0005", "service": "inventory-service", "level": "ERROR", "timestamp_iso": "2026-10-25T08:14:15Z"},
        ],
        "traces": {"req-ord-1001": {"services": ["api-gateway", "inventory-service"], "has_error": True}},
        "earliest_recorded_error": {"event_id": "evt-0005", "service": "inventory-service"},
        "hypotheses": [{"hypothesis_id": "hyp-01", "claim": "Remote test failure", "evidence_event_ids": ["evt-0005"]}],
        "unknowns": ["Remote test telemetry missing"],
        "validation_errors": [],
    }
    mock_payload = _build_streaming_payload({
        "statusCode": 200,
        "status": "success",
        "report": raw_report,
    })
    mock_client = MagicMock()
    mock_client.invoke.return_value = {
        "StatusCode": 200,
        "Payload": mock_payload,
    }
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: mock_client)

    # Create agent in remote mode
    agent, provider_info = create_incident_agent(
        target_fixture="incident_out_of_order.json",
        tool_mode="remote",
    )
    assert "remote tool" in provider_info

    response = agent("Investigate the incident in 'incident_out_of_order.json'")
    response_text = str(response)

    # Confirm Lambda was invoked by the tool and mock model received results
    assert mock_client.invoke.called
    call_kwargs = mock_client.invoke.call_args[1]
    assert call_kwargs["FunctionName"] == "incident-time-machine"
    assert "Earliest Recorded Error" in response_text
    assert "evt-0005" in response_text
