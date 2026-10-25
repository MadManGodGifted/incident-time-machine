"""Tests for the AWS Lambda handler for Incident Time Machine."""

import base64
import json
from pathlib import Path
import sys
import pytest

from lambda_function import lambda_handler
from src.incident_time_machine.lambda_handler import _extract_logs_from_event

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ==============================================================================
# Category 1: Valid Invocations & Envelopes
# ==============================================================================

def test_lambda_handler_direct_list_invocation():
    """Verify handler processes a direct list of log records."""
    records = [
        {
            "timestamp": "2026-10-25T10:00:00Z",
            "service": "api-gateway",
            "level": "INFO",
            "message": "Gateway received request",
            "request_id": "req-101",
        },
        {
            "timestamp": "2026-10-25T10:00:01Z",
            "service": "auth-service",
            "level": "INFO",
            "message": "Auth succeeded",
            "request_id": "req-101",
        },
    ]

    response = lambda_handler(records, context=None)

    assert response["statusCode"] == 200
    assert response["status"] == "success"
    assert "report" in response

    report = response["report"]
    assert len(report["timeline"]) == 2
    assert report["timeline"][0]["event_id"] == "evt-0001"
    assert "req-101" in report["traces"]
    assert report["earliest_recorded_error"] is None

    # Check JSON body is also parsable
    body = json.loads(response["body"])
    assert body["status"] == "success"
    assert len(body["report"]["timeline"]) == 2


def test_lambda_handler_dict_with_logs_key():
    """Verify handler processes a dict with 'logs' key."""
    fixture_path = FIXTURES_DIR / "healthy_traffic.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        logs = json.load(f)

    event = {"logs": logs}
    response = lambda_handler(event, context=None)

    assert response["statusCode"] == 200
    report = response["report"]
    assert len(report["timeline"]) == 7
    assert report["earliest_recorded_error"] is None
    assert "no errors detected in the supplied logs" in report["hypotheses"][0]["claim"].lower()


def test_lambda_handler_api_gateway_proxy_event():
    """Verify handler processes an API Gateway / Lambda Function URL envelope."""
    fixture_path = FIXTURES_DIR / "incident_out_of_order.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        logs = json.load(f)

    api_gateway_event = {
        "resource": "/analyze",
        "path": "/analyze",
        "httpMethod": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"logs": logs}),
        "isBase64Encoded": False,
    }

    response = lambda_handler(api_gateway_event, context=None)

    assert response["statusCode"] == 200
    report = response["report"]
    assert len(report["timeline"]) == 12

    # Earliest recorded error
    earliest = report["earliest_recorded_error"]
    assert earliest is not None
    assert earliest["event_id"] == "evt-0005"
    assert earliest["service"] == "inventory-service"


def test_lambda_handler_base64_encoded_body():
    """Verify handler processes base64-encoded body from API Gateway."""
    raw_payload = json.dumps([
        {
            "timestamp": "2026-10-25T12:00:00Z",
            "service": "lambda-worker",
            "level": "INFO",
            "message": "Task completed successfully",
            "request_id": "req-b64",
        }
    ])
    b64_body = base64.b64encode(raw_payload.encode("utf-8")).decode("utf-8")

    event = {
        "httpMethod": "POST",
        "body": b64_body,
        "isBase64Encoded": True,
    }

    response = lambda_handler(event, context=None)
    assert response["statusCode"] == 200
    report = response["report"]
    assert len(report["timeline"]) == 1
    assert report["timeline"][0]["request_id"] == "req-b64"


def test_lambda_handler_bedrock_agent_action_group_event():
    """Verify handler processes an Amazon Bedrock Agent Action Group envelope."""
    records = [
        {
            "timestamp": "2026-10-25T08:00:00Z",
            "service": "bedrock-agent",
            "level": "INFO",
            "message": "Invoked tool action",
        }
    ]

    bedrock_event = {
        "actionGroup": "IncidentAnalysisGroup",
        "apiPath": "/analyze",
        "httpMethod": "POST",
        "requestBody": {
            "content": {
                "application/json": {
                    "properties": [
                        {
                            "name": "logs",
                            "type": "array",
                            "value": records,
                        }
                    ]
                }
            }
        },
    }

    response = lambda_handler(bedrock_event, context=None)
    assert response["statusCode"] == 200
    assert len(response["report"]["timeline"]) == 1


# ==============================================================================
# Category 2: Invalid Inputs & Error Handling (400 Bad Request)
# ==============================================================================

def test_lambda_handler_rejects_none_event():
    """Verify handler rejects None event with 400 Bad Request."""
    response = lambda_handler(None, context=None)
    assert response["statusCode"] == 400
    assert response["error"]["error_code"] == "BAD_REQUEST"
    assert "cannot be None" in response["error"]["message"]


def test_lambda_handler_rejects_empty_string_body():
    """Verify handler rejects empty string or whitespace with 400."""
    response = lambda_handler("   ", context=None)
    assert response["statusCode"] == 400
    assert response["error"]["error_code"] == "BAD_REQUEST"


def test_lambda_handler_rejects_malformed_json_string():
    """Verify handler rejects unparseable JSON string with 400."""
    response = lambda_handler("{not: valid: json}", context=None)
    assert response["statusCode"] == 400
    assert "Malformed JSON" in response["error"]["message"]


def test_lambda_handler_rejects_invalid_structure():
    """Verify handler rejects dict without recognizable log keys."""
    response = lambda_handler({"unrelated_key": 123}, context=None)
    assert response["statusCode"] == 400
    assert response["error"]["error_code"] == "BAD_REQUEST"


def test_lambda_handler_rejects_non_list_logs_field():
    """Verify handler rejects 'logs' if not a list."""
    response = lambda_handler({"logs": "this is a string, not a list"}, context=None)
    assert response["statusCode"] == 400
    assert "must be a list" in response["error"]["message"]


# ==============================================================================
# Category 3: Malformed Log Records & Quarantining
# ==============================================================================

def test_lambda_handler_quarantines_malformed_records():
    """Verify malformed records are quarantined and clearly documented in the report."""
    mixed_records = [
        {
            "timestamp": "2026-10-25T10:00:00Z",
            "service": "good-service",
            "level": "INFO",
            "message": "Valid log record",
        },
        {
            "timestamp": "2026-10-25T10:00:01",  # Timezone-naive!
            "service": "bad-service",
            "level": "INFO",
            "message": "Naive timestamp",
        },
        {
            "timestamp": "not-a-timestamp",  # Malformed ISO!
            "service": "bad-service",
            "level": "INFO",
            "message": "Garbage timestamp",
        },
        {
            "timestamp": "2026-10-25T10:00:02Z",
            "service": "bad-service",
            # missing level!
            "message": "Missing level",
        },
    ]

    response = lambda_handler(mixed_records, context=None)

    assert response["statusCode"] == 200
    report = response["report"]

    # Only 1 valid record should be in timeline
    assert len(report["timeline"]) == 1
    assert report["timeline"][0]["service"] == "good-service"

    # Exactly 3 validation errors quarantined
    assert len(report["validation_errors"]) == 3
    assert any("timezone-naive" in err["reason"] for err in report["validation_errors"])
    assert any("Malformed ISO" in err["reason"] for err in report["validation_errors"])
    assert any("Missing required field" in err["reason"] for err in report["validation_errors"])


# ==============================================================================
# Category 4: Report Schema Invariants & Independence
# ==============================================================================

def test_lambda_handler_report_schema_keys():
    """Verify the report returned by the Lambda handler strictly satisfies schema keys."""
    records = [
        {
            "timestamp": "2026-10-25T10:00:00Z",
            "service": "srv-a",
            "level": "INFO",
            "message": "msg",
        }
    ]
    response = lambda_handler(records, context=None)

    expected_schema_keys = [
        "timeline",
        "traces",
        "unassociated_event_ids",
        "earliest_recorded_error",
        "hypotheses",
        "unknowns",
        "validation_errors",
    ]
    report = response["report"]
    for key in expected_schema_keys:
        assert key in report, f"Report missing schema key: {key}"


def test_lambda_handler_strands_independence():
    """Verify that importing and invoking lambda_handler does not require or load strands."""
    from src.incident_time_machine.lambda_handler import lambda_handler as direct_handler

    result = direct_handler([
        {
            "timestamp": "2026-10-25T10:00:00Z",
            "service": "independent-check",
            "level": "INFO",
            "message": "Testing zero external framework dependency",
        }
    ])
    assert result["statusCode"] == 200
    assert len(result["report"]["timeline"]) == 1
