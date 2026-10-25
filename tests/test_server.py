"""Unit tests for the Incident Time Machine local HTTP server."""

from __future__ import annotations

import json
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch
import pytest

from src.incident_time_machine.server import WEB_DIR, create_server


@pytest.fixture(scope="module")
def running_server():
    """Start an ephemeral local HTTP server on port 0 and terminate it after tests."""
    server = create_server(host="127.0.0.1", port=0)
    actual_port = server.server_port
    base_url = f"http://127.0.0.1:{actual_port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.1)  # Brief warm-up

    yield base_url

    server.shutdown()
    server.server_close()
    server_thread.join(timeout=1.0)


# ==============================================================================
# Category 1: Static Files and Status Endpoints
# ==============================================================================

def test_get_root_serves_html(running_server):
    """Verify GET / returns index.html dashboard."""
    req = urllib.request.Request(f"{running_server}/")
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        content_type = response.headers.get("Content-Type", "")
        assert "text/html" in content_type.lower()
        html_text = response.read().decode("utf-8")
        assert "Incident Time Machine" in html_text
        assert "Chronological Event Timeline" in html_text


def test_get_api_status(running_server):
    """Verify GET /api/status returns service configuration and AWS region."""
    req = urllib.request.Request(f"{running_server}/api/status")
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        data = json.loads(response.read().decode("utf-8"))
        assert data["status"] == "healthy"
        assert data["active_region"] == "ap-southeast-2"
        assert data["lambda_function"] == "incident-time-machine"
        assert "local" in data["supported_modes"]
        assert "remote" in data["supported_modes"]


def test_get_api_fixtures(running_server):
    """Verify GET /api/fixtures lists both pre-approved fixtures safely."""
    req = urllib.request.Request(f"{running_server}/api/fixtures")
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        data = json.loads(response.read().decode("utf-8"))
        assert data["status"] == "success"
        fixture_names = [f["name"] for f in data["fixtures"]]
        assert "incident_out_of_order.json" in fixture_names
        assert "healthy_traffic.json" in fixture_names


# ==============================================================================
# Category 2: Local Mode Analysis & Validation
# ==============================================================================

def test_post_analyze_local_incident_fixture(running_server):
    """Verify POST /api/analyze executes local deterministic engine on incident fixture."""
    payload = json.dumps({"mode": "local", "fixture": "incident_out_of_order.json"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        data = json.loads(response.read().decode("utf-8"))
        assert data["status"] == "success"
        assert data["execution_mode"] == "local"

        report = data["report"]
        assert len(report["timeline"]) == 12
        assert report["earliest_recorded_error"]["event_id"] == "evt-0005"
        assert "req-ord-1001" in report["traces"]


def test_post_analyze_local_healthy_fixture(running_server):
    """Verify POST /api/analyze handles healthy traffic fixture with zero error events."""
    payload = json.dumps({"mode": "local", "fixture": "healthy_traffic.json"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        data = json.loads(response.read().decode("utf-8"))
        report = data["report"]
        assert len(report["timeline"]) == 7
        assert report["earliest_recorded_error"] is None


def test_post_analyze_rejects_path_traversal(running_server):
    """Verify POST /api/analyze blocks directory traversal with 403 Forbidden."""
    bad_payload = json.dumps({"mode": "local", "fixture": "../../etc/passwd"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        data=bad_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)

    assert exc_info.value.code == 403
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body["error_code"] == "ACCESS_DENIED"


def test_post_analyze_rejects_non_existent_fixture(running_server):
    """Verify POST /api/analyze returns 404 for missing fixture."""
    bad_payload = json.dumps({"mode": "local", "fixture": "non_existent_fixture.json"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        data=bad_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)

    assert exc_info.value.code == 404
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body["error_code"] == "FILE_NOT_FOUND"


def test_post_analyze_rejects_invalid_mode(running_server):
    """Verify POST /api/analyze rejects unknown execution mode with 400 Bad Request."""
    bad_payload = json.dumps({"mode": "quantum_simulator", "fixture": "healthy_traffic.json"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        data=bad_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)

    assert exc_info.value.code == 400
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body["error_code"] == "INVALID_MODE"


# ==============================================================================
# Category 3: Remote Mode & Mocked AWS Invocation
# ==============================================================================

@patch("src.incident_time_machine.server.invoke_lambda_incident_analysis")
def test_post_analyze_remote_mode_success(mock_remote_call, running_server):
    """Verify POST /api/analyze in remote mode dispatches to invoke_lambda_incident_analysis."""
    mock_remote_call.return_value = {
        "status": "success",
        "execution_mode": "remote_lambda",
        "timeline": [{"event_id": "evt-0001", "service": "api-gateway", "timestamp_iso": "2026-10-25T08:14:10Z"}],
        "traces": {},
        "earliest_recorded_error": None,
        "hypotheses": [],
        "unknowns": [],
        "validation_errors": [],
    }

    payload = json.dumps({"mode": "remote", "fixture": "incident_out_of_order.json"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
        data = json.loads(response.read().decode("utf-8"))
        assert data["status"] == "success"
        assert data["execution_mode"] == "remote_lambda"
        assert mock_remote_call.called
        call_kwargs = mock_remote_call.call_args[1]
        assert call_kwargs["fixture_name"] == "incident_out_of_order.json"
        assert call_kwargs["function_name"] == "incident-time-machine"
        assert call_kwargs["region_name"] == "ap-southeast-2"


def test_cors_preflight_options(running_server):
    """Verify OPTIONS preflight request returns 204 No Content with security headers."""
    req = urllib.request.Request(
        f"{running_server}/api/analyze",
        headers={"Origin": "https://incident-time-machine.vercel.app"},
        method="OPTIONS",
    )
    with urllib.request.urlopen(req) as response:
        assert response.status == 204
        assert response.headers.get("Access-Control-Allow-Origin") == "https://incident-time-machine.vercel.app"
        assert "POST" in response.headers.get("Access-Control-Allow-Methods", "")
        assert "Content-Type" in response.headers.get("Access-Control-Allow-Headers", "")


def test_post_analyze_token_auth_enforcement(running_server):
    """Verify ITM_ACCESS_TOKEN enforces Bearer/x-api-key authentication when configured."""
    payload = json.dumps({"mode": "local", "fixture": "healthy_traffic.json"}).encode("utf-8")

    with patch.dict("os.environ", {"ITM_ACCESS_TOKEN": "itm-prod-token-12345"}):
        # 1. Unauthenticated request should fail with 401 Unauthorized
        unauth_req = urllib.request.Request(
            f"{running_server}/api/analyze",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(unauth_req)
        assert exc_info.value.code == 401
        err_body = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_body["error_code"] == "UNAUTHORIZED"

        # 2. Authenticated request with Bearer token succeeds with 200 OK
        bearer_req = urllib.request.Request(
            f"{running_server}/api/analyze",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer itm-prod-token-12345",
            },
            method="POST",
        )
        with urllib.request.urlopen(bearer_req) as response:
            assert response.status == 200

        # 3. Authenticated request with x-api-key header succeeds with 200 OK
        apikey_req = urllib.request.Request(
            f"{running_server}/api/analyze",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": "itm-prod-token-12345",
            },
            method="POST",
        )
        with urllib.request.urlopen(apikey_req) as response:
            assert response.status == 200

