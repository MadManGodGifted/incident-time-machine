"""Lightweight local HTTP server bridging the Incident Time Machine dashboard to local and AWS Lambda engines.

Built 100% on the Python standard library (http.server, json, urllib).
Exclusively binds to 127.0.0.1 to guarantee zero external exposure of AWS credentials.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.parse

from .engine import IncidentTimeMachine
from .remote_tool import DEFAULT_FUNCTION_NAME, DEFAULT_REGION, invoke_lambda_incident_analysis
from .tools import FIXTURES_DIR, analyze_incident_logs

# Static assets directory
WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"

# Maximum request body size (1 MB limit prevents memory saturation)
MAX_REQUEST_BYTES = 1024 * 1024

# Rate limiting (sliding window per client IP)
_RATE_LIMIT_WINDOW_SEC = 60.0
_MAX_REQUESTS_PER_WINDOW = 60
_request_timestamps: Dict[str, List[float]] = defaultdict(list)
_rate_limit_lock = threading.Lock()


def _check_rate_limit(client_ip: str) -> bool:
    """Sliding window rate-limiter per client IP address."""
    now = time.time()
    with _rate_limit_lock:
        history = _request_timestamps[client_ip]
        history = [t for t in history if now - t < _RATE_LIMIT_WINDOW_SEC]
        if len(history) >= _MAX_REQUESTS_PER_WINDOW:
            _request_timestamps[client_ip] = history
            return True
        history.append(now)
        _request_timestamps[client_ip] = history
        return False


def is_aws_credentials_configured() -> bool:
    """Check whether AWS credentials exist in the local environment without logging secrets."""
    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        return creds is not None and creds.access_key is not None
    except Exception:
        return False


class IncidentTimeMachineHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler serving static dashboard assets and secure REST endpoints."""

    def __init__(self, *args: Any, directory: Optional[str] = None, **kwargs: Any) -> None:
        if directory is None:
            directory = str(WEB_DIR)
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        """Override default logging to provide clean, unprivileged console logs without secrets."""
        sys.stderr.write(f"[ITM-Server] {self.address_string()} - {format % args}\n")

    def _is_authorized(self) -> bool:
        """Check whether incoming request possesses valid authorization if ITM_ACCESS_TOKEN is configured."""
        required_token = os.environ.get("ITM_ACCESS_TOKEN")
        if not required_token:
            return True  # Open access when no access token configured

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token == required_token:
                return True

        api_key = self.headers.get("x-api-key", "").strip()
        if api_key and api_key == required_token:
            return True

        return False

    def _send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        """Helper to send standardized JSON responses with security headers."""
        encoded = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        req_origin = self.headers.get("Origin")
        allow_origin = req_origin if req_origin else "*"
        self.send_header("Access-Control-Allow-Origin", allow_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key")
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests from browser."""
        req_origin = self.headers.get("Origin")
        allow_origin = req_origin if req_origin else "*"
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", allow_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Route GET requests: /api/* to JSON handlers, else serve static assets from web/."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/status":
            self._handle_api_status()
        elif path == "/api/fixtures":
            self._handle_api_fixtures()
        elif path.startswith("/api/"):
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"status": "error", "error_code": "NOT_FOUND", "message": f"API endpoint '{path}' not found."},
            )
        else:
            # Fallback to serving static files from WEB_DIR
            if path in {"", "/"}:
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self) -> None:
        """Route POST requests: currently supports /api/analyze."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/analyze":
            self._handle_api_analyze()
        else:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"status": "error", "error_code": "NOT_FOUND", "message": f"API endpoint '{path}' not found."},
            )

    # --------------------------------------------------------------------------
    # API Endpoints
    # --------------------------------------------------------------------------

    def _handle_api_status(self) -> None:
        """GET /api/status - Returns system status, active AWS configuration, and credential health."""
        has_creds = is_aws_credentials_configured()
        response = {
            "status": "healthy",
            "service": "Incident Time Machine Local Bridge",
            "version": "1.0.0",
            "active_region": DEFAULT_REGION,
            "lambda_function": DEFAULT_FUNCTION_NAME,
            "aws_credentials_configured": has_creds,
            "supported_modes": ["local", "remote"],
            "model_integration": "optional (deterministic analysis enforced)",
        }
        self._send_json_response(HTTPStatus.OK, response)

    def _handle_api_fixtures(self) -> None:
        """GET /api/fixtures - Lists available pre-approved JSON fixtures safely."""
        fixtures: List[Dict[str, Any]] = []

        if FIXTURES_DIR.exists() and FIXTURES_DIR.is_dir():
            for p in sorted(FIXTURES_DIR.glob("*.json")):
                desc = "Custom incident log stream"
                if p.name == "incident_out_of_order.json":
                    desc = "Synthetic cascading multi-service outage (out-of-order logs)"
                elif p.name == "healthy_traffic.json":
                    desc = "Normal baseline multi-service traffic (zero errors)"

                try:
                    size = p.stat().st_size
                except Exception:
                    size = 0

                fixtures.append({
                    "name": p.name,
                    "description": desc,
                    "size_bytes": size,
                })

        self._send_json_response(HTTPStatus.OK, {"status": "success", "fixtures": fixtures})

    def _handle_api_analyze(self) -> None:
        """POST /api/analyze - Execute deterministic incident reconstruction (local or remote)."""
        client_ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or (
            self.client_address[0] if hasattr(self, "client_address") else "127.0.0.1"
        )
        if _check_rate_limit(client_ip):
            self._send_json_response(
                HTTPStatus.TOO_MANY_REQUESTS,
                {
                    "status": "error",
                    "error_code": "RATE_LIMITED",
                    "message": "Too many requests. Please wait before submitting more analyses.",
                },
            )
            return

        if not self._is_authorized():
            self._send_json_response(
                HTTPStatus.UNAUTHORIZED,
                {
                    "status": "error",
                    "error_code": "UNAUTHORIZED",
                    "message": "Authorization required: provide valid Bearer token or x-api-key header.",
                },
            )
            return

        content_length_str = self.headers.get("Content-Length")
        if not content_length_str:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "error_code": "MISSING_CONTENT_LENGTH", "message": "Missing Content-Length header."},
            )
            return

        try:
            content_length = int(content_length_str)
        except ValueError:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "error_code": "INVALID_CONTENT_LENGTH", "message": "Invalid Content-Length."},
            )
            return

        if content_length > MAX_REQUEST_BYTES:
            self._send_json_response(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"status": "error", "error_code": "PAYLOAD_TOO_LARGE", "message": f"Payload exceeds {MAX_REQUEST_BYTES} bytes limit."},
            )
            return

        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type.lower():
            self._send_json_response(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"status": "error", "error_code": "UNSUPPORTED_MEDIA_TYPE", "message": "Content-Type must be 'application/json'."},
            )
            return

        raw_bytes = self.rfile.read(content_length)
        try:
            body = json.loads(raw_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "error_code": "INVALID_JSON", "message": f"Malformed JSON request body: {exc}"},
            )
            return

        if not isinstance(body, dict):
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "error_code": "INVALID_BODY", "message": "Request body must be a JSON object."},
            )
            return

        # 1. Validate Mode
        mode = str(body.get("mode", "local")).strip().lower()
        if mode not in {"local", "remote"}:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {
                    "status": "error",
                    "error_code": "INVALID_MODE",
                    "message": "Field 'mode' must be either 'local' or 'remote'.",
                },
            )
            return

        # 2. Validate Fixture / Direct Logs
        fixture_name = body.get("fixture")
        direct_logs = body.get("logs")

        if not fixture_name and direct_logs is None:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {
                    "status": "error",
                    "error_code": "MISSING_INPUT",
                    "message": "Must provide either 'fixture' (filename) or 'logs' (array).",
                },
            )
            return

        if fixture_name is not None and not isinstance(fixture_name, str):
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {
                    "status": "error",
                    "error_code": "INVALID_ARGUMENT",
                    "message": "Field 'fixture' must be a string.",
                },
            )
            return

        cleaned_fixture = str(fixture_name or "").strip()
        if cleaned_fixture:
            # Prevent path traversal
            if cleaned_fixture.startswith("fixtures/") or cleaned_fixture.startswith("fixtures\\"):
                cleaned_fixture = cleaned_fixture[9:]
            target_path = (FIXTURES_DIR / cleaned_fixture).resolve()
            try:
                target_path.relative_to(FIXTURES_DIR)
            except ValueError:
                self._send_json_response(
                    HTTPStatus.FORBIDDEN,
                    {
                        "status": "error",
                        "error_code": "ACCESS_DENIED",
                        "message": f"Security violation: path '{cleaned_fixture}' escapes authorized fixtures directory.",
                    },
                )
                return

            if not target_path.exists() or not target_path.is_file():
                self._send_json_response(
                    HTTPStatus.NOT_FOUND,
                    {
                        "status": "error",
                        "error_code": "FILE_NOT_FOUND",
                        "message": f"Fixture file '{cleaned_fixture}' not found.",
                    },
                )
                return

        # 3. Execution Dispatch
        if mode == "local":
            try:
                if direct_logs is not None:
                    if not isinstance(direct_logs, list):
                        self._send_json_response(
                            HTTPStatus.BAD_REQUEST,
                            {"status": "error", "error_code": "INVALID_LOGS", "message": "'logs' must be a list of records."},
                        )
                        return
                    engine = IncidentTimeMachine()
                    report = engine.analyze(direct_logs)
                    report_dict = report.to_dict()
                    self._send_json_response(
                        HTTPStatus.OK,
                        {
                            "status": "success",
                            "execution_mode": "local",
                            "report": report_dict,
                        },
                    )
                else:
                    tool_res = analyze_incident_logs(cleaned_fixture)
                    if tool_res.get("status") == "error":
                        self._send_json_response(HTTPStatus.BAD_REQUEST, tool_res)
                        return
                    self._send_json_response(
                        HTTPStatus.OK,
                        {
                            "status": "success",
                            "execution_mode": "local",
                            "report": tool_res,
                        },
                    )
            except Exception as exc:
                self._send_json_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "error_code": "ENGINE_ERROR", "message": f"Local analysis failed: {exc}"},
                )
        else:
            # Remote AWS Lambda Execution
            # Strictly locked to configured Lambda function and region
            target_func = DEFAULT_FUNCTION_NAME
            target_region = DEFAULT_REGION

            try:
                lambda_res = invoke_lambda_incident_analysis(
                    fixture_name=cleaned_fixture,
                    logs=direct_logs,
                    function_name=target_func,
                    region_name=target_region,
                )
                if lambda_res.get("status") == "error":
                    # Error from AWS or credentials
                    status_code = HTTPStatus.SERVICE_UNAVAILABLE if lambda_res.get("error_code") == "NO_CREDENTIALS" else HTTPStatus.BAD_GATEWAY
                    self._send_json_response(status_code, lambda_res)
                    return

                self._send_json_response(
                    HTTPStatus.OK,
                    {
                        "status": "success",
                        "execution_mode": "remote_lambda",
                        "function_name": target_func,
                        "region": target_region,
                        "report": lambda_res,
                    },
                )
            except Exception as exc:
                self._send_json_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "error_code": "REMOTE_INVOCATION_FAILED", "message": f"Remote Lambda call failed: {exc}"},
                )


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    """Create and configure the local HTTP server instance bound strictly to localhost."""
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    server_address = (host, port)
    return ThreadingHTTPServer(server_address, IncidentTimeMachineHandler)


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the Incident Time Machine local dashboard server until interrupted."""
    # Ensure web directory exists
    WEB_DIR.mkdir(parents=True, exist_ok=True)

    server = create_server(host=host, port=port)
    actual_port = server.server_port
    print("=" * 70)
    print("       INCIDENT TIME MACHINE - LOCAL DASHBOARD SERVER")
    print("=" * 70)
    print(f"Server Host           : http://{host}:{actual_port}")
    print(f"Static Web Directory  : {WEB_DIR}")
    print(f"Fixtures Directory    : {FIXTURES_DIR}")
    print(f"Target AWS Function   : {DEFAULT_FUNCTION_NAME}")
    print(f"Target AWS Region     : {DEFAULT_REGION}")
    print(f"AWS Credentials Found : {'YES' if is_aws_credentials_configured() else 'NO (Local mode ready; Remote requires AWS creds)'}")
    print("=" * 70)
    print(f"Open in your browser  : http://{host}:{actual_port}")
    print("Press Ctrl+C to terminate the server.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Incident Time Machine server gracefully...")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Incident Time Machine Local HTTP Server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    # Safety assertion: forbid binding to 0.0.0.0 to prevent network credential exposure
    if args.host not in {"127.0.0.1", "localhost"}:
        print(f"Security Alert: Forcing host binding to 127.0.0.1 instead of '{args.host}'.", file=sys.stderr)
        args.host = "127.0.0.1"

    run_server(host=args.host, port=args.port)
