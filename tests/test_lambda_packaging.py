"""Packaging and isolated artifact tests for incident_time_machine_lambda.zip."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ZIP_PATH = PROJECT_ROOT / "incident_time_machine_lambda.zip"


# ==============================================================================
# Category 1: Archive Structure & Invariant Checks
# ==============================================================================

def test_zip_artifact_exists():
    """Verify that incident_time_machine_lambda.zip exists at the project root."""
    assert ZIP_PATH.exists(), f"ZIP artifact not found at {ZIP_PATH}. Run PowerShell packaging first."
    assert ZIP_PATH.is_file()
    assert ZIP_PATH.stat().st_size > 0, "ZIP artifact is empty"


def test_zip_contains_required_modules_at_correct_paths():
    """Verify that every required module is present at the exact relative path inside the archive."""
    with zipfile.ZipFile(ZIP_PATH, "r") as z:
        names = z.namelist()

        # Root entrypoint
        assert "lambda_function.py" in names, "Missing lambda_function.py at archive root"

        # Core deterministic package
        required_src_files = [
            "src/incident_time_machine/__init__.py",
            "src/incident_time_machine/lambda_handler.py",
            "src/incident_time_machine/engine.py",
            "src/incident_time_machine/models.py",
            "src/incident_time_machine/parser.py",
            "src/incident_time_machine/prompts.py",
        ]
        for req in required_src_files:
            assert req in names, f"Missing required module in ZIP: {req}"

        # Invariant: No cached bytecode or tests in production archive
        for name in names:
            assert "__pycache__" not in name, f"Found __pycache__ in archive: {name}"
            assert not name.endswith(".pyc"), f"Found .pyc file in archive: {name}"
            assert not name.startswith("tests/"), f"Test files should not be packaged: {name}"


# ==============================================================================
# Category 2: Isolated Extraction & Handler Import
# ==============================================================================

def test_handler_importable_from_extracted_zip():
    """Verify lambda_function.lambda_handler is cleanly importable from the extracted archive."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(ZIP_PATH, "r") as z:
            z.extractall(tmpdir)

        # Run an isolated python subprocess where cwd is tmpdir and sys.path excludes project root
        test_code = (
            "import os, sys\n"
            "assert 'lambda_function.py' in os.listdir('.'), 'Missing entrypoint in cwd'\n"
            "import lambda_function\n"
            "assert callable(lambda_function.lambda_handler), 'lambda_handler is not callable'\n"
            "print('SUCCESS')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", test_code],
            cwd=tmpdir,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Import test failed:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert "SUCCESS" in proc.stdout


# ==============================================================================
# Category 3: Isolated Smoke Execution (Zero Strands, Zero Credentials, Zero Fixture Dependencies)
# ==============================================================================

def test_isolated_smoke_execution_valid_and_invalid_events():
    """Run an isolated subprocess test simulating an AWS Lambda container environment.

    Invariants checked:
    1. Strands is strictly unavailable (ModuleNotFoundError if imported).
    2. Zero environment variables / credentials required.
    3. Independent of local fixture files.
    4. Valid logs produce 200 OK with deterministic report.
    5. Invalid events produce 400 Bad Request.
    6. Malformed events produce 200 OK with quarantined records.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(ZIP_PATH, "r") as z:
            z.extractall(tmpdir)

        smoke_script = """
import sys, os, json

# Guarantee Strands cannot be loaded
sys.modules['strands'] = None

# Ensure working directory is strictly the isolated extraction directory
import lambda_function
handler = lambda_function.lambda_handler

# 1. Valid event (out-of-order timestamps across services)
valid_event = {
    "logs": [
        {
            "timestamp": "2026-10-25T14:00:10.500Z",
            "service": "billing-service",
            "level": "ERROR",
            "message": "Payment gateway timeout after 5000ms",
            "request_id": "req-isolated-99"
        },
        {
            "timestamp": "2026-10-25T14:00:01.000Z",
            "service": "api-gateway",
            "level": "INFO",
            "message": "POST /checkout received",
            "request_id": "req-isolated-99"
        }
    ]
}

res1 = handler(valid_event, None)
assert res1["statusCode"] == 200, f"Expected 200, got {res1['statusCode']}"
assert res1["status"] == "success"
report = res1["report"]

# Check schema keys
for k in ["timeline", "traces", "earliest_recorded_error", "hypotheses", "unknowns", "validation_errors"]:
    assert k in report, f"Missing key in report: {k}"

# Check chronological ordering: api-gateway (14:00:01) before billing-service (14:00:10)
assert len(report["timeline"]) == 2
assert report["timeline"][0]["event_id"] == "evt-0001"
assert report["timeline"][0]["service"] == "api-gateway"
assert report["timeline"][1]["event_id"] == "evt-0002"
assert report["timeline"][1]["service"] == "billing-service"

# Earliest recorded error
assert report["earliest_recorded_error"]["event_id"] == "evt-0002"
assert report["earliest_recorded_error"]["service"] == "billing-service"

# 2. API Gateway proxy event
proxy_event = {
    "httpMethod": "POST",
    "body": json.dumps({"logs": [{"timestamp": "2026-10-25T10:00:00Z", "service": "api", "level": "INFO", "message": "ok"}]})
}
res2 = handler(proxy_event, None)
assert res2["statusCode"] == 200
assert len(res2["report"]["timeline"]) == 1

# 3. Invalid event structure (expect 400 Bad Request)
bad_event = {"unrecognized": True}
res3 = handler(bad_event, None)
assert res3["statusCode"] == 400
assert res3["error"]["error_code"] == "BAD_REQUEST"

# 4. Malformed records (expect 200 with quarantined entries)
malformed_event = {
    "logs": [
        {"timestamp": "2026-10-25T10:00:00Z", "service": "ok-srv", "level": "INFO", "message": "valid"},
        {"timestamp": "bad-date", "service": "bad-srv", "level": "INFO", "message": "malformed"},
        {"timestamp": "2026-10-25T10:00:00", "service": "bad-srv", "level": "INFO", "message": "naive"}
    ]
}
res4 = handler(malformed_event, None)
assert res4["statusCode"] == 200
assert len(res4["report"]["timeline"]) == 1
assert len(res4["report"]["validation_errors"]) == 2

print("ISOLATED_SMOKE_TEST_PASSED")
"""
        proc = subprocess.run(
            [sys.executable, "-c", smoke_script],
            cwd=tmpdir,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"Isolated smoke test failed:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        assert "ISOLATED_SMOKE_TEST_PASSED" in proc.stdout
