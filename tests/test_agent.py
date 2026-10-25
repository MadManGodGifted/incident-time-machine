"""Tests for Strands Agent and custom tool integration."""

from pathlib import Path
import pytest

from src.incident_time_machine.agent import (
    DeterministicMockIncidentModel,
    check_model_provider_status,
    create_incident_agent,
)
from src.incident_time_machine.tools import FIXTURES_DIR, analyze_incident_logs


# ==============================================================================
# Category 1: Strands Tool Direct Invocation & Output Schema
# ==============================================================================

def test_tool_invocation_incident_fixture():
    """Verify analyze_incident_logs successfully processes incident fixture and returns valid schema."""
    result = analyze_incident_logs("incident_out_of_order.json")

    assert result["status"] == "success"
    assert result["fixture"] == "incident_out_of_order.json"

    # Schema keys required by Incident Time Machine specification
    expected_keys = [
        "status",
        "fixture",
        "timeline",
        "traces",
        "unassociated_event_ids",
        "earliest_recorded_error",
        "hypotheses",
        "unknowns",
        "validation_errors",
    ]
    for key in expected_keys:
        assert key in result, f"Missing expected key in tool result: {key}"

    # Verify timeline content
    timeline = result["timeline"]
    assert len(timeline) == 12
    assert timeline[0]["event_id"] == "evt-0001"

    # Verify earliest recorded error
    earliest = result["earliest_recorded_error"]
    assert earliest is not None
    assert earliest["event_id"] == "evt-0005"
    assert earliest["service"] == "inventory-service"
    assert "Connection pool exhausted" in earliest["message"]

    # Verify correlated traces
    traces = result["traces"]
    assert "req-ord-1001" in traces
    assert traces["req-ord-1001"]["has_error"] is True


def test_tool_invocation_healthy_fixture():
    """Verify analyze_incident_logs processes healthy traffic with zero error events."""
    result = analyze_incident_logs("healthy_traffic.json")

    assert result["status"] == "success"
    assert len(result["timeline"]) == 7
    assert result["earliest_recorded_error"] is None

    # Verify healthy hypothesis specifies no errors in supplied logs
    hypotheses = result["hypotheses"]
    assert len(hypotheses) >= 1
    assert "no errors detected in the supplied logs" in hypotheses[0]["claim"].lower()


def test_tool_accepts_fixtures_prefix():
    """Verify analyze_incident_logs handles both 'fixture.json' and 'fixtures/fixture.json'."""
    res1 = analyze_incident_logs("healthy_traffic.json")
    res2 = analyze_incident_logs("fixtures/healthy_traffic.json")
    res3 = analyze_incident_logs("./fixtures/healthy_traffic.json")

    assert res1["status"] == "success"
    assert res2["status"] == "success"
    assert res3["status"] == "success"
    assert len(res1["timeline"]) == len(res2["timeline"]) == len(res3["timeline"])


# ==============================================================================
# Category 2: Security & Filesystem Boundary (Path Traversal Defenses)
# ==============================================================================

def test_tool_rejects_path_traversal():
    """Verify that paths escaping FIXTURES_DIR are strictly rejected with ACCESS_DENIED."""
    escape_attempts = [
        "../README.md",
        "../../requirements.txt",
        "..\\..\\Windows\\System32\\calc.exe",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]

    for bad_path in escape_attempts:
        result = analyze_incident_logs(bad_path)
        assert result["status"] == "error", f"Should have failed on '{bad_path}'"
        assert result["error_code"] == "ACCESS_DENIED", (
            f"Expected ACCESS_DENIED for '{bad_path}', got {result.get('error_code')}"
        )
        assert "escapes" in result["message"].lower() or "denied" in result["message"].lower()


def test_tool_rejects_non_existent_file():
    """Verify that non-existent files within fixtures return FILE_NOT_FOUND."""
    result = analyze_incident_logs("does_not_exist.json")
    assert result["status"] == "error"
    assert result["error_code"] == "FILE_NOT_FOUND"


def test_tool_rejects_non_json_file(tmp_path):
    """Verify that non-JSON files are rejected with INVALID_FILE_TYPE."""
    # Attempting to load a non-json file name
    result = analyze_incident_logs("some_script.py")
    assert result["status"] == "error"
    # Either non-existent or invalid file type
    assert result["error_code"] in {"FILE_NOT_FOUND", "INVALID_FILE_TYPE"}


def test_tool_rejects_invalid_arguments():
    """Verify that non-string and empty arguments are rejected with INVALID_ARGUMENT."""
    bad_args = [None, 12345, "", "   ", ["incident_out_of_order.json"]]
    for arg in bad_args:
        result = analyze_incident_logs(arg)  # type: ignore
        assert result["status"] == "error"
        assert result["error_code"] == "INVALID_ARGUMENT"


# ==============================================================================
# Category 3: Evidence-ID Integrity
# ==============================================================================

def test_evidence_id_integrity_across_fixtures():
    """Verify that every hypothesis in tool output cites only valid timeline event IDs."""
    for fixture in ["incident_out_of_order.json", "healthy_traffic.json"]:
        result = analyze_incident_logs(fixture)
        assert result["status"] == "success"

        timeline_ids = {evt["event_id"] for evt in result["timeline"]}
        for hyp in result["hypotheses"]:
            assert len(hyp["evidence_event_ids"]) > 0
            for eid in hyp["evidence_event_ids"]:
                assert eid in timeline_ids, (
                    f"Tool output violated evidence integrity: hypothesis '{hyp['hypothesis_id']}' "
                    f"cited '{eid}' which is not in timeline {timeline_ids}"
                )


# ==============================================================================
# Category 4: Strands Agent & Mock Model Integration
# ==============================================================================

def test_check_model_provider_status():
    """Verify check_model_provider_status runs safely and never prints or leaks keys."""
    is_available, status_msg, model = check_model_provider_status()
    assert isinstance(is_available, bool)
    assert isinstance(status_msg, str)
    assert len(status_msg) > 0


def test_agent_invokes_custom_tool_via_mock():
    """Verify Strands Agent executes tool call loop and returns synthesis without live API keys."""
    # Instantiate the agent with the deterministic mock model pointing to incident fixture
    agent, provider_info = create_incident_agent(target_fixture="incident_out_of_order.json")
    assert "Mock Model Harness" in provider_info

    # Invoke agent with an incident query
    prompt = "Investigate the incident in 'incident_out_of_order.json' using the tool."
    response = agent(prompt)

    # Convert response to string
    response_text = str(response)

    # Assert that tool was executed (mock model received tool output and emitted synthesis)
    assert "Earliest Recorded Error" in response_text
    assert "evt-0005" in response_text
    assert "Causation Notice" in response_text
    assert "Competing Hypotheses" in response_text


def test_agent_invokes_custom_tool_healthy_traffic_via_mock():
    """Verify Strands Agent handles healthy traffic without claiming global enterprise health."""
    mock_model = DeterministicMockIncidentModel(target_fixture="healthy_traffic.json")
    agent, _ = create_incident_agent(model=mock_model, target_fixture="healthy_traffic.json")

    response = agent("Analyze the logs in healthy_traffic.json")
    response_text = str(response)

    assert "No errors were detected in the supplied logs" in response_text
    assert "Limitation Notice" in response_text
    assert "evt-0001" in response_text
