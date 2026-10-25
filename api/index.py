"""Vercel Serverless Function entrypoint for Incident Time Machine."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
import sys
import urllib.parse

# Ensure project root is in sys.path so src is importable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.incident_time_machine.server import IncidentTimeMachineHandler


class handler(IncidentTimeMachineHandler):
    """Vercel-compatible serverless request handler."""

    def do_GET(self) -> None:
        """Route GET requests: /api/status, /api/fixtures."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if path.endswith("/status") or path == "/api/status":
            self._handle_api_status()
        elif path.endswith("/fixtures") or path == "/api/fixtures":
            self._handle_api_fixtures()
        else:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {
                    "status": "error",
                    "error_code": "NOT_FOUND",
                    "message": f"API endpoint '{self.path}' not found.",
                },
            )

    def do_POST(self) -> None:
        """Route POST requests: /api/analyze."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if path.endswith("/analyze") or path == "/api/analyze":
            self._handle_api_analyze()
        else:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {
                    "status": "error",
                    "error_code": "NOT_FOUND",
                    "message": f"API endpoint '{self.path}' not found.",
                },
            )
