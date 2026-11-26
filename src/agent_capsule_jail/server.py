"""REST API Server & Static Asset Host for agent-capsule-jail.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.

Browser trust model:
  * Host header must be a loopback name with this daemon's port (blocks DNS rebinding).
  * Requests carrying an Origin header must match an explicit allowlist (self origin,
    Zoth Studio on :3000, https://zoth.nullai.tech, plus $CAPSULE_EXTRA_ORIGINS); anything
    else gets 403. Requests without Origin (CLI / agents) are allowed.
  * The token-bearing page (GET /) never carries CORS headers.
  * POST /api/exec additionally requires the per-install exec token.
"""

from __future__ import annotations

import hmac
import json
import math
import mimetypes
import os
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .capsule import (
    LIMIT_BOUNDS,
    CapsuleConfig,
    CapsuleNetworkDenied,
    CapsuleRunner,
    CapsuleSecurityError,
    ResourceLimits,
    network_opt_in_enabled,
    pids_enforcement,
    sandbox_mode,
)
from .telemetry import TelemetryRegistry


TOKEN_PATH = Path(os.environ.get("CAPSULE_TOKEN_FILE", str(Path.home() / ".config" / "agent-capsule-jail" / "token")))

STUDIO_ORIGINS = ("http://127.0.0.1:3000", "http://localhost:3000", "https://zoth.nullai.tech")
FRAME_ANCESTORS = "frame-ancestors 'self' http://127.0.0.1:3000 http://localhost:3000 https://zoth.nullai.tech"

_ORIGIN_RE = re.compile(r"^(https?)://(127\.0\.0\.1|localhost|\[::1\])(?::(\d{1,5}))?$")
_HOST_RE = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\]):(\d{1,5})$")
TOKEN_HINT = "run `agent-capsule-jail token` and send the value as the X-Capsule-Token header"


class RequestError(Exception):
    """Client input error -> HTTP 400 JSON."""


def _safe_rel(raw: str) -> Optional[str]:
    """Request path -> safe relative path inside the static dir.
    '' means index; None means the path tried to climb out ('..', '%2e%2e', absolute drive)."""
    rel = unquote(str(raw or "")).replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or ":" in (parts[0] if parts else "") or "\x00" in rel:
        return None
    return "/".join(parts)


def load_or_create_token() -> str:
    """Per-install exec token, stored owner-only (0600). $CAPSULE_TOKEN overrides."""
    env = os.environ.get("CAPSULE_TOKEN", "").strip()
    if env:
        return env
    import secrets
    try:
        tok = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    except OSError:
        pass
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(TOKEN_PATH.parent, 0o700)
    tok = secrets.token_urlsafe(32)
    fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(tok + "\n")
    return tok


def _is_local_origin(origin) -> bool:
    """Syntactic loopback-origin check: exact scheme://host[:port] with an integer port
    in 1..65535. Rejects suffix tricks such as http://127.0.0.1:8105.example.invalid.
    No Origin header (CLI / agent) counts as local."""
    if not origin:
        return True
    m = _ORIGIN_RE.match(str(origin))
    if not m:
        return False
    if m.group(3) is not None:
        port = int(m.group(3))
        if not 1 <= port <= 65535:
            return False
    return True


def _extra_origins() -> List[str]:
    return [o.strip().rstrip("/") for o in os.environ.get("CAPSULE_EXTRA_ORIGINS", "").split(",") if o.strip()]


def allowed_origins(port: int) -> List[str]:
    return [f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}",
            *STUDIO_ORIGINS, *_extra_origins()]


def origin_allowed(origin: Optional[str], port: int) -> bool:
    """None/empty -> True (non-browser client). Otherwise exact allowlist match: the
    daemon's own loopback origin, Zoth Studio, or operator-listed extras."""
    if not origin:
        return True
    origin = str(origin).strip()
    if origin in STUDIO_ORIGINS or origin in _extra_origins():
        return True
    return _is_local_origin(origin) and origin in allowed_origins(port)[:3]


def host_allowed(host: Optional[str], port: int, bind_host: str = "127.0.0.1") -> bool:
    """Host header must name this daemon on a loopback name (DNS-rebinding guard).
    A missing Host header (HTTP/1.0 tooling) is tolerated; browsers always send one."""
    if host is None:
        return True
    host = host.strip().lower()
    m = _HOST_RE.match(host)
    if m and int(m.group(2)) == port:
        return True
    if bind_host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::") and host == f"{bind_host}:{port}":
        return True
    extra = [h.strip().lower() for h in os.environ.get("CAPSULE_EXTRA_HOSTS", "").split(",") if h.strip()]
    return host in extra


def _num(data: Dict[str, Any], key: str, default: float, kind: type) -> Tuple[Any, bool]:
    """Parse a numeric field and clamp it to LIMIT_BOUNDS. Returns (value, was_clamped).
    Raises RequestError for wrong types (bool, str, NaN, inf, objects)."""
    raw = data.get(key, default)
    if raw is None:
        raw = default
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise RequestError(f"'{key}' must be a number")
    if isinstance(raw, float) and (math.isnan(raw) or math.isinf(raw)):
        raise RequestError(f"'{key}' must be a finite number")
    lo, hi = LIMIT_BOUNDS[key]
    val = kind(raw)
    clamped = max(kind(lo), min(val, kind(hi)))
    return clamped, clamped != val


def parse_exec_request(data: Any) -> Tuple[CapsuleConfig, Any, Optional[str], Dict[str, Any]]:
    """Validate an /api/exec (or MCP) body. Returns (config, command, script, clamped_fields)."""
    if not isinstance(data, dict):
        raise RequestError("request body must be a JSON object")
    command = data.get("command", "")
    script = data.get("script")
    if command is None:
        command = ""
    if not isinstance(command, (str, list)) or (isinstance(command, list) and not all(isinstance(c, str) for c in command)):
        raise RequestError("'command' must be a string or a list of strings")
    if script is not None and not isinstance(script, str):
        raise RequestError("'script' must be a string")
    if not command and not script:
        raise RequestError("Missing 'command' or 'script' in request")
    if isinstance(command, str) and len(command) > 64 * 1024:
        raise RequestError("'command' exceeds 64 KiB")

    clamped: Dict[str, Any] = {}
    timeout_sec, c1 = _num(data, "timeout_sec", 30.0, float)
    memory_mb, c2 = _num(data, "memory_mb", 512, int)
    max_procs, c3 = _num(data, "max_procs", 64, int)
    max_file_size_mb, c4 = _num(data, "max_file_size_mb", 50, int)
    for name, flag, val in (("timeout_sec", c1, timeout_sec), ("memory_mb", c2, memory_mb),
                            ("max_procs", c3, max_procs), ("max_file_size_mb", c4, max_file_size_mb)):
        if flag:
            clamped[name] = val

    allowed_env = data.get("allowed_env", [])
    if allowed_env is None:
        allowed_env = []
    if not isinstance(allowed_env, list) or not all(isinstance(k, str) for k in allowed_env):
        raise RequestError("'allowed_env' must be a list of strings")
    initial_files = data.get("initial_files", {})
    if initial_files is None:
        initial_files = {}
    if not isinstance(initial_files, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in initial_files.items()):
        raise RequestError("'initial_files' must be an object of {relative_path: text}")
    for flag in ("commit", "allow_network"):
        if flag in data and not isinstance(data[flag], bool):
            raise RequestError(f"'{flag}' must be a boolean")
    destination_dir = data.get("destination_dir")
    if destination_dir is not None and not isinstance(destination_dir, str):
        raise RequestError("'destination_dir' must be a string")

    cfg = CapsuleConfig(
        limits=ResourceLimits(
            timeout_sec=timeout_sec,
            memory_mb=memory_mb,
            max_procs=max_procs,
            max_file_size_mb=max_file_size_mb,
        ),
        allowed_env=allowed_env,
        commit=bool(data.get("commit", False)),
        destination_dir=destination_dir,
        initial_files=initial_files,
        allow_network=bool(data.get("allow_network", False)),
    )
    return cfg, command, script, clamped


class CapsuleApiHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for the REST API and web cockpit."""

    server_version = f"AgentCapsuleJail/{__version__}"
    runner: CapsuleRunner
    telemetry: TelemetryRegistry
    public_dir: Path

    def log_message(self, format: str, *args: Any) -> None:
        return

    # ---- helpers -------------------------------------------------------
    @property
    def _port(self) -> int:
        return int(self.server.server_address[1])

    def _origin(self) -> Optional[str]:
        return self.headers.get("Origin")

    def _common_headers(self, cors: bool) -> None:
        self.send_header("Vary", "Origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", FRAME_ANCESTORS)
        origin = self._origin()
        if cors and origin and origin_allowed(origin, self._port):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Capsule-Token")
            self.send_header("Access-Control-Max-Age", "600")

    def _send_json(self, status_code: int, data: Any, cors: bool = True) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self._common_headers(cors)
        self.end_headers()
        self.wfile.write(payload)

    def _guard(self) -> bool:
        """Host + Origin gate shared by every method. Returns False if a 403 was sent."""
        bind = getattr(self.server, "bind_host", "127.0.0.1")
        if not host_allowed(self.headers.get("Host"), self._port, bind):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "foreign Host header rejected (DNS-rebinding guard)"}, cors=False)
            return False
        if not origin_allowed(self._origin(), self._port):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "cross-origin request blocked"}, cors=False)
            return False
        return True

    # ---- methods -------------------------------------------------------
    def do_OPTIONS(self) -> None:
        if not self._guard():
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self._common_headers(cors=True)
        self.end_headers()

    def do_GET(self) -> None:
        try:
            if not self._guard():
                return
            self._handle_get()
        except Exception as e:  # never drop the connection without a reply
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"internal error: {type(e).__name__}"})

    def do_POST(self) -> None:
        try:
            if not self._guard():
                return
            self._handle_post()
        except Exception as e:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"internal error: {type(e).__name__}"})

    def _health(self) -> Dict[str, Any]:
        stats = self.telemetry.get_stats()
        return {
            "status": "healthy",
            "service": "agent-capsule-jail",
            "version": __version__,
            "sandbox": sandbox_mode(),
            "exec_requires_token": True,
            "port": self._port,
            "engine": "bubblewrap-namespace-jail",
            "pids_enforcement": pids_enforcement(),
            "network_opt_in_enabled": network_opt_in_enabled(),
            "uptime_seconds": stats.get("uptime_seconds", 0),
            "total_capsules": stats.get("total_capsules", 0),
        }

    def _handle_get(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path in ("/health", "/api/health"):
            self._send_json(HTTPStatus.OK, self._health())
            return

        if path == "/api/stats":
            self._send_json(HTTPStatus.OK, self.telemetry.get_stats())
            return

        if path == "/api/capsules":
            query = parse_qs(parsed.query)
            raw = query.get("limit", ["50"])[0]
            try:
                limit = int(raw)
            except (TypeError, ValueError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "'limit' must be an integer between 1 and 200"})
                return
            limit = max(1, min(limit, 200))
            runs = self.telemetry.get_recent_capsules(limit=limit)
            self._send_json(HTTPStatus.OK, {
                "capsules": runs,
                "count": len(runs),
                "limit": limit,
                "total_tracked": self.telemetry.stats.total_capsules,
            })
            return

        if path.startswith("/api/"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown API endpoint", "path": parsed.path})
            return

        # Static cockpit files (public/). Traversal attempts get a hard 404.
        rel_file = _safe_rel(parsed.path)
        if rel_file is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "File not found"}, cors=False)
            return
        public_root = self.public_dir.resolve()
        target = public_root / (rel_file or "index.html")
        try:
            target = target.resolve()
        except (OSError, RuntimeError):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "File not found"}, cors=False)
            return
        if not target.is_relative_to(public_root):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "File not found"}, cors=False)
            return
        if not target.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint or resource not found", "path": parsed.path}, cors=False)
            return

        mime, _ = mimetypes.guess_type(str(target))
        if not mime:
            mime = {".js": "application/javascript", ".css": "text/css", ".html": "text/html"}.get(
                target.suffix, "application/octet-stream")
        content = target.read_bytes()
        is_index = target == public_root / "index.html"
        if is_index:
            tok = getattr(self.server, "exec_token", "") or ""
            if tok and b'name="capsule-token"' not in content:
                meta_tag = f'  <meta name="capsule-token" content="{tok}">\n</head>'.encode("utf-8")
                content = content.replace(b"</head>", meta_tag, 1)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(content)))
        if is_index:
            self.send_header("Cache-Control", "no-store")
        # Static files (and above all the token page) never carry CORS headers.
        self._common_headers(cors=False)
        self.end_headers()
        self.wfile.write(content)

    def _handle_post(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path != "/api/exec":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown POST endpoint", "path": parsed.path})
            return

        supplied = self.headers.get("X-Capsule-Token", "")
        auth = self.headers.get("Authorization", "")
        if not supplied and auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        expected = getattr(self.server, "exec_token", "") or ""
        if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "exec token required", "hint": TOKEN_HINT})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
            return
        if content_length > 5 * 1024 * 1024:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Payload exceeds 5MB limit"})
            return
        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body"})
            return

        try:
            cfg, command, script, clamped = parse_exec_request(data)
        except RequestError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})
            return

        try:
            result = self.runner.run(command=command, config=cfg, script=script)
        except CapsuleNetworkDenied as e:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": str(e), "policy_violation": True,
                                                   "hint": "operator opt-in: CAPSULE_ALLOW_NETWORK=1"})
            return
        except CapsuleSecurityError as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(e), "policy_violation": True})
            return

        result.flight_recorder_dispatched = self.telemetry.record_run(result)
        body = result.to_dict()
        body.pop("scratch_dir", None)
        if clamped:
            body["clamped"] = clamped
        self._send_json(HTTPStatus.OK, body)


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
        self.exec_token = load_or_create_token()

    def start(self, block: bool = True) -> None:
        handler_class = type("BoundCapsuleApiHandler", (CapsuleApiHandler,), {
            "runner": self.runner,
            "telemetry": self.telemetry,
            "public_dir": self.public_dir,
        })
        self.httpd = ThreadingHTTPServer((self.host, self.port), handler_class)
        self.httpd.daemon_threads = True
        self.httpd.exec_token = self.exec_token
        self.httpd.bind_host = self.host
        self.port = int(self.httpd.server_address[1])

        if block:
            try:
                self.httpd.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
