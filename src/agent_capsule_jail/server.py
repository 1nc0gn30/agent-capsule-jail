"""REST API Server & Static Asset Host for agent-capsule-jail.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .capsule import CapsuleConfig, CapsuleRunner, ResourceLimits
from .telemetry import TelemetryRegistry


def _is_local_origin(origin) -> bool:
    """Browser Origin check. No Origin header = non-browser client (CLI/agent): allowed.
    Otherwise only http(s)://localhost / 127.0.0.1 / [::1] pages may call this API, so a
    random website can't drive the local server from the user's browser (CSRF)."""
    if not origin:
        return True
    from urllib.parse import urlparse
    try:
        u = urlparse(origin)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and u.hostname in ("localhost", "127.0.0.1", "::1")


def _cors_origin(handler) -> str:
    origin = handler.headers.get("Origin")
    return origin if origin and _is_local_origin(origin) else "http://127.0.0.1"



class CapsuleApiHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for REST API and Glassmorphic Cockpit."""

    server_version = "AgentCapsuleJail/0.1.0"
    runner: CapsuleRunner
    telemetry: TelemetryRegistry
    public_dir: Path

    def log_message(self, format: str, *args: Any) -> None:
        """Silence default verbose stdout logging for clean CLI output."""
        return

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", _cors_origin(self))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")

    def _send_json(self, status_code: int, data: Any) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight inquiries."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path == "":
            path = "/"

        # 1. Health Probe Endpoints
        if path in ("/health", "/api/health"):
            stats = self.telemetry.get_stats()
            self._send_json(HTTPStatus.OK, {
                "status": "healthy",
                "service": "agent-capsule-jail",
                "port": 8105,
                "version": "0.1.0",
                "engine": "kernel-enclave-jail",
                "uptime_seconds": stats.get("uptime_seconds", 0),
                "total_capsules": stats.get("total_capsules", 0),
            })
            return

        # 2. Telemetry Metrics Endpoint
        if path == "/api/stats":
            self._send_json(HTTPStatus.OK, self.telemetry.get_stats())
            return

        # 3. Recent Capsule Runs Endpoint
        if path == "/api/capsules":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["50"])[0])
            runs = self.telemetry.get_recent_capsules(limit=limit)
            self._send_json(HTTPStatus.OK, {
                "capsules": runs,
                "count": len(runs),
                "total_tracked": self.telemetry.stats.total_capsules,
            })
            return

        # 4. Static Web Cockpit Files (public/ directory)
        rel_file = parsed.path.lstrip("/")
        if rel_file == "" or rel_file == "index.html":
            target = self.public_dir / "index.html"
        else:
            target = self.public_dir / rel_file

        # Prevent directory traversal
        try:
            target = target.resolve()
            if not str(target).startswith(str(self.public_dir.resolve())):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied"})
                return
        except Exception:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "File not found"})
            return

        if target.exists() and target.is_file():
            mime, _ = mimetypes.guess_type(str(target))
            if not mime:
                if target.suffix == ".js":
                    mime = "application/javascript"
                elif target.suffix == ".css":
                    mime = "text/css"
                elif target.suffix == ".html":
                    mime = "text/html"
                else:
                    mime = "application/octet-stream"

            try:
                content = target.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})
                return

        # Fallback 404 for undefined routes
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint or resource not found", "path": parsed.path})

    def do_POST(self) -> None:
        if not _is_local_origin(self.headers.get("Origin")):
            _body = b'{"error": "cross-origin request blocked"}'
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_body)))
            self.end_headers()
            self.wfile.write(_body)
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/exec":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 5 * 1024 * 1024:  # 5MB body max
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Payload exceeds 5MB limit"})
                return

            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                data = json.loads(raw_body.decode("utf-8"))
            except Exception:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body"})
                return

            command = data.get("command", "")
            script = data.get("script")
            if not command and not script:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'command' or 'script' in request"})
                return

            # Parse resource limit overrides
            timeout_sec = float(data.get("timeout_sec", 30.0))
            timeout_sec = max(0.5, min(timeout_sec, 300.0))  # 0.5s to 5min clamp

            memory_mb = int(data.get("memory_mb", 512))
            memory_mb = max(32, min(memory_mb, 4096))  # 32MB to 4GB clamp

            max_procs = int(data.get("max_procs", 64))
            max_file_size_mb = int(data.get("max_file_size_mb", 50))
            allowed_env = list(data.get("allowed_env", []))
            commit = bool(data.get("commit", False))
            destination_dir = data.get("destination_dir")
            initial_files = data.get("initial_files", {})

            cfg = CapsuleConfig(
                limits=ResourceLimits(
                    timeout_sec=timeout_sec,
                    memory_mb=memory_mb,
                    max_procs=max_procs,
                    max_file_size_mb=max_file_size_mb,
                ),
                allowed_env=allowed_env,
                commit=commit,
                destination_dir=destination_dir,
                initial_files=initial_files,
            )

            # Execute within ephemeral sandbox
            result = self.runner.run(command=command, config=cfg, script=script)

            # Record telemetry
            self.telemetry.record_run(result)

            self._send_json(HTTPStatus.OK, result.to_dict())
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown POST endpoint", "path": parsed.path})


class CapsuleServer:
    """Multi-threaded HTTP Server for Capsule Jail."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8105,
        public_dir: Optional[Path] = None,
        flight_recorder_url: str = "http://127.0.0.1:8104/api/ingest",
    ):
        self.host = host
        self.port = port
        self.public_dir = public_dir or (Path(__file__).resolve().parent.parent.parent / "public")
        self.runner = CapsuleRunner()
        self.telemetry = TelemetryRegistry(flight_recorder_url=flight_recorder_url)
        self.httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, block: bool = True) -> None:
        """Start the API server."""
        # Bind runner and telemetry to the handler class
        handler_class = CapsuleApiHandler
        handler_class.runner = self.runner
        handler_class.telemetry = self.telemetry
        handler_class.public_dir = self.public_dir

        self.httpd = ThreadingHTTPServer((self.host, self.port), handler_class)
        self.httpd.daemon_threads = True

        if block:
            try:
                self.httpd.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop the running server."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
