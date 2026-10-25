"""Unit tests for Vercel serverless function entrypoints and configuration."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from api.index import handler as IndexHandler
from api.status import handler as StatusHandler
from api.fixtures import handler as FixturesHandler
from api.analyze import handler as AnalyzeHandler


class MockVercelServer:
    """Mock HTTP server for instantiating BaseHTTPRequestHandler in memory."""
    pass


class MockSocket:
    """Mock socket compatible with Python 3.11 - 3.14 socketserver implementation."""

    def __init__(self, raw_input: bytes) -> None:
        self.rfile = io.BytesIO(raw_input)
        self.sent_bytes = bytearray()

    def makefile(self, mode: str, *args, **kwargs) -> io.BytesIO | MockSocket:
        if "r" in mode:
            return self.rfile
        return self

    def sendall(self, b: bytes) -> None:
        self.sent_bytes.extend(b)

    def write(self, b: bytes) -> None:
        self.sent_bytes.extend(b)

    def flush(self) -> None:
        pass


def make_mock_handler(handler_cls, method, path, body=b"", headers=None):
    """Helper to instantiate and invoke handler methods in-memory without networking."""
    headers = headers or {}
    if body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))
    if body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    # Format HTTP request line and headers
    header_lines = [f"{k}: {v}" for k, v in headers.items()]
    raw_request = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(header_lines) + "\r\n\r\n"
    full_payload = raw_request.encode("utf-8") + body

    sock = MockSocket(full_payload)
    h = handler_cls(sock, ("127.0.0.1", 12345), MockVercelServer())
    return h, bytes(sock.sent_bytes)


def test_vercel_json_syntax_and_rewrites():
    """Verify vercel.json is valid and contains required rewrites for web and api."""
    vpath = Path(__file__).resolve().parent.parent / "vercel.json"
    assert vpath.exists(), "vercel.json must exist in project root."
    with open(vpath, "r", encoding="utf-8") as f:
        config = json.load(f)

    rewrites = config.get("rewrites", [])
    destinations = [r["destination"] for r in rewrites]
    assert "/web/index.html" in destinations
    assert "/web/style.css" in destinations
    assert "/web/app.js" in destinations
    assert "/api/index.py" in destinations


def test_vercel_status_handler_get():
    """Verify api/index handler routes GET /api/status."""
    _, raw_out = make_mock_handler(IndexHandler, "GET", "/api/status")
    output = raw_out.decode("utf-8")
    assert "200 OK" in output
    assert "ap-southeast-2" in output
    assert "incident-time-machine" in output


def test_vercel_fixtures_handler_get():
    """Verify api/index handler routes GET /api/fixtures."""
    _, raw_out = make_mock_handler(IndexHandler, "GET", "/api/fixtures")
    output = raw_out.decode("utf-8")
    assert "200 OK" in output
    assert "incident_out_of_order.json" in output
    assert "healthy_traffic.json" in output


def test_vercel_analyze_handler_post_local():
    """Verify api/index handler routes POST /api/analyze."""
    payload = json.dumps({"mode": "local", "fixture": "incident_out_of_order.json"}).encode("utf-8")
    _, raw_out = make_mock_handler(IndexHandler, "POST", "/api/analyze", body=payload)
    output = raw_out.decode("utf-8")
    assert "200 OK" in output
    assert "evt-0005" in output
    assert "inventory-service" in output


def test_vercel_dedicated_handlers_importable():
    """Verify dedicated route handlers export valid handler subclasses."""
    assert issubclass(StatusHandler, IndexHandler)
    assert issubclass(FixturesHandler, IndexHandler)
    assert issubclass(AnalyzeHandler, IndexHandler)
