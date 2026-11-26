"""Zero-dependency stdio MCP server for agent-capsule-jail (JSON-RPC 2.0, newline-delimited).

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.

Tools:
  capsule_jail_exec    run a command/script in a bubblewrap capsule (local CapsuleRunner)
  capsule_jail_status  sandbox capabilities + live :8105 daemon health/stats

Run:  agent-capsule-jail mcp      (or python3 -m agent_capsule_jail.mcp_server)
"""

from __future__ import annotations

import json
import sys
import urllib.request
from typing import Any, Dict, Optional, TextIO

from . import __version__
from .capsule import CapsuleNetworkDenied, CapsuleRunner, CapsuleSecurityError, network_opt_in_enabled, pids_enforcement, sandbox_mode
from .server import RequestError, parse_exec_request

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

EXEC_OUTPUT_FIELDS = (
    "capsule_id", "status", "exit_code", "stdout", "stderr", "duration_ms", "fs_diff",
    "cpu_time_user_s", "cpu_time_system_s", "max_rss_kb", "receipt_sha256", "sandbox_mode",
)

EXEC_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "command": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                    "description": "Shell command string or argv list to run inside the capsule"},
        "script": {"type": "string", "description": "Inline Python source (written to capsule_script.py)"},
        "timeout_sec": {"type": "number", "minimum": 0.5, "maximum": 60, "default": 30},
        "memory_mb": {"type": "integer", "minimum": 32, "maximum": 4096, "default": 512},
        "max_procs": {"type": "integer", "minimum": 1, "maximum": 512, "default": 64},
        "max_file_size_mb": {"type": "integer", "minimum": 1, "maximum": 1024, "default": 50},
        "allowed_env": {"type": "array", "items": {"type": "string"},
                        "description": "Host env names to pass through (secret-looking names are always stripped)"},
        "initial_files": {"type": "object", "additionalProperties": {"type": "string"},
                          "description": "{relative_path: text} seeded into the scratch dir"},
    },
    "anyOf": [{"required": ["command"]}, {"required": ["script"]}],
    "additionalProperties": False,
}

EXEC_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "capsule_id": {"type": "string"},
        "status": {"type": "string", "enum": ["success", "error", "timeout", "oom_killed"]},
        "exit_code": {"type": "integer"},
        "stdout": {"type": "string"},
        "stderr": {"type": "string"},
        "duration_ms": {"type": "number"},
        "fs_diff": {"type": "object"},
        "cpu_time_user_s": {"type": "number"},
        "cpu_time_system_s": {"type": "number"},
        "max_rss_kb": {"type": "integer"},
        "receipt_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "sandbox_mode": {"type": "string"},
    },
    "required": list(EXEC_OUTPUT_FIELDS),
}

STATUS_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {"port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 8105}},
    "additionalProperties": False,
}

STATUS_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "service": {"type": "string"},
        "version": {"type": "string"},
        "sandbox_mode": {"type": "string"},
        "pids_enforcement": {"type": "string"},
        "network_opt_in_enabled": {"type": "boolean"},
        "daemon_online": {"type": "boolean"},
        "daemon_port": {"type": "integer"},
        "health": {"type": ["object", "null"]},
        "stats": {"type": ["object", "null"]},
    },
    "required": ["service", "version", "sandbox_mode", "pids_enforcement", "daemon_online", "daemon_port"],
}

TOOLS = [
    {
        "name": "capsule_jail_exec",
        "title": "Run in Capsule Jail",
        "description": ("Run a command or Python script in an ephemeral bubblewrap capsule: read-only root, "
                        "private /home /root /run /tmp, no network, all capabilities dropped, rlimit/cgroup quotas, "
                        "secret env stripping. Returns stdout/stderr/exit code, filesystem diff, per-run rusage "
                        "and a SHA-256 receipt."),
        "inputSchema": EXEC_INPUT_SCHEMA,
        "outputSchema": EXEC_OUTPUT_SCHEMA,
    },
    {
        "name": "capsule_jail_status",
        "title": "Capsule Jail Status",
        "description": "Report sandbox mode, process-cap enforcement, network opt-in, and live :8105 daemon health/stats.",
        "inputSchema": STATUS_INPUT_SCHEMA,
        "outputSchema": STATUS_OUTPUT_SCHEMA,
    },
]


def _get_json(url: str, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def tool_status(args: Dict[str, Any]) -> Dict[str, Any]:
    port = args.get("port", 8105)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RequestError("'port' must be an integer 1..65535")
    health = _get_json(f"http://127.0.0.1:{port}/api/health")
    stats = _get_json(f"http://127.0.0.1:{port}/api/stats") if health else None
    return {
        "service": "agent-capsule-jail",
        "version": __version__,
        "sandbox_mode": sandbox_mode(),
        "pids_enforcement": pids_enforcement(),
        "network_opt_in_enabled": network_opt_in_enabled(),
        "daemon_online": bool(health and health.get("status") == "healthy"),
        "daemon_port": port,
        "health": health,
        "stats": stats,
    }


def tool_exec(args: Dict[str, Any], runner: Optional[CapsuleRunner] = None) -> Dict[str, Any]:
    allowed = set(EXEC_INPUT_SCHEMA["properties"])
    unknown = set(args) - allowed
    if unknown:
        raise RequestError(f"unknown argument(s): {', '.join(sorted(unknown))}")
    cfg, command, script, _clamped = parse_exec_request(dict(args))
    result = (runner or CapsuleRunner()).run(command=command, config=cfg, script=script)
    full = result.to_dict()
    return {k: full[k] for k in EXEC_OUTPUT_FIELDS}


class McpServer:
    def __init__(self) -> None:
        self.runner = CapsuleRunner()

    def handle(self, msg: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return self._error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        method = msg["method"]
        mid = msg.get("id")
        is_notification = "id" not in msg
        params = msg.get("params") or {}

        if method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                requested = params.get("protocolVersion") if isinstance(params, dict) else None
                result = {
                    "protocolVersion": requested if requested in SUPPORTED_PROTOCOLS else PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "agent-capsule-jail", "title": "Agent Capsule Jail", "version": __version__},
                    "instructions": "Use capsule_jail_exec to run untrusted commands in a bubblewrap capsule.",
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = self._call(params)
            else:
                return None if is_notification else self._error(mid, -32601, f"Method not found: {method}")
        except Exception as e:  # pragma: no cover - defensive
            return None if is_notification else self._error(mid, -32603, f"Internal error: {type(e).__name__}: {e}")
        return None if is_notification else {"jsonrpc": "2.0", "id": mid, "result": result}

    def _call(self, params: Any) -> Dict[str, Any]:
        if not isinstance(params, dict):
            return self._tool_error("params must be an object")
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return self._tool_error("arguments must be an object")
        try:
            if name == "capsule_jail_exec":
                data = tool_exec(args, self.runner)
            elif name == "capsule_jail_status":
                data = tool_status(args)
            else:
                return self._tool_error(f"unknown tool: {name}")
        except CapsuleNetworkDenied as e:
            return self._tool_error(f"network denied: {e}")
        except (RequestError, CapsuleSecurityError) as e:
            return self._tool_error(str(e))
        # A non-zero exit inside the capsule is a valid tool result, not a tool failure.
        return {
            "content": [{"type": "text", "text": json.dumps(data, indent=2)}],
            "structuredContent": data,
            "isError": False,
        }

    @staticmethod
    def _tool_error(message: str) -> Dict[str, Any]:
        return {"content": [{"type": "text", "text": message}], "isError": True}

    @staticmethod
    def _error(mid: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                reply: Any = self._error(None, -32700, "Parse error")
            else:
                if isinstance(msg, list):
                    replies = [r for r in (self.handle(m) for m in msg) if r is not None]
                    reply = replies or None
                else:
                    reply = self.handle(msg)
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()
        return 0


def main() -> None:
    sys.exit(McpServer().serve())


if __name__ == "__main__":
    main()
