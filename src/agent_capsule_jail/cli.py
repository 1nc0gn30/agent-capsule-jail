"""Unified Command Line Interface for agent-capsule-jail.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

from .capsule import CapsuleConfig, CapsuleRunner, ResourceLimits
from .server import CapsuleServer


def _default_bind_host() -> str:
    """Bind address: localhost unless explicitly opted in via $ZOTH_BIND_HOST or
    $HOST (IP literal only; zsh sets HOST to the hostname) or --host."""
    import ipaddress, os
    for var in ("ZOTH_BIND_HOST", "HOST"):
        val = os.environ.get(var, "").strip()
        if val == "localhost":
            return "127.0.0.1"
        if val:
            try:
                ipaddress.ip_address(val)
                return val
            except ValueError:
                pass
    return "127.0.0.1"


C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_GOLD = "\033[38;5;214m"
C_CYAN = "\033[38;5;51m"
C_GREEN = "\033[38;5;48m"
C_RED = "\033[38;5;196m"
C_GRAY = "\033[38;5;244m"


def print_banner() -> None:
    print(f"""{C_GOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║               🛡️ AGENT CAPSULE JAIL — KERNEL ENCLAVE ENGINE 🛡️              ║
║         Neal Frazier Tech (@1nc0gn30) • Ephemeral Execution Sandbox          ║
╚══════════════════════════════════════════════════════════════════════════════╝{C_RESET}""")


def cmd_exec(args: argparse.Namespace) -> int:
    """Execute a command or script directly inside an ephemeral sandbox."""
    runner = CapsuleRunner()
    raw_cmd = list(args.command or [])
    if raw_cmd and raw_cmd[0] == "--":
        raw_cmd = raw_cmd[1:]

    script_content = None
    if args.script:
        script_path = Path(args.script)
        if not script_path.exists():
            print(f"{C_RED}Error: script file '{args.script}' not found.{C_RESET}", file=sys.stderr)
            return 1
        script_content = script_path.read_text(encoding="utf-8")

    if not raw_cmd and not script_content:
        print(f"{C_RED}Error: please provide a command or --script to execute.{C_RESET}", file=sys.stderr)
        return 1

    command = raw_cmd if raw_cmd else ""

    cfg = CapsuleConfig(
        limits=ResourceLimits(
            timeout_sec=args.timeout,
            memory_mb=args.memory,
            max_procs=args.max_procs,
            max_file_size_mb=args.max_fsize,
        ),
        allowed_env=args.env or [],
        commit=args.commit,
        destination_dir=args.dest,
    )

    if not args.quiet and not args.json:
        print(f"{C_CYAN}⚡ Initializing ephemeral capsule...{C_RESET}")
        print(f"{C_GRAY}   Quotas: CPU timeout={args.timeout}s, RAM={args.memory}MB, Procs={args.max_procs}, FSize={args.max_fsize}MB{C_RESET}")
        if command:
            print(f"{C_GRAY}   Command: {command}{C_RESET}")
        if args.script:
            print(f"{C_GRAY}   Script:  {args.script}{C_RESET}")

    res = runner.run(command=command, config=cfg, script=script_content)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.exit_code == 0 else 1

    # Pretty output
    print(f"\n{C_BOLD}--- Execution Output ---{C_RESET}")
    if res.stdout:
        print(res.stdout, end="" if res.stdout.endswith("\n") else "\n")
    if res.stderr:
        print(f"{C_RED}{res.stderr}{C_RESET}", end="" if res.stderr.endswith("\n") else "\n")

    print(f"{C_BOLD}--- Forensic Telemetry ---{C_RESET}")
    status_color = C_GREEN if res.status == "success" else C_RED
    print(f"Status:       {status_color}{res.status.upper()}{C_RESET} (Exit Code: {res.exit_code})")
    print(f"Duration:     {res.duration_ms} ms (CPU User: {res.cpu_time_user_s}s, Sys: {res.cpu_time_sys_s}s)")
    print(f"Peak RSS:     {round(res.max_rss_kb / 1024.0, 2)} MB")
    print(f"Timed Out:    {res.timed_out}")
    print(f"OOM Killed:   {res.memory_exceeded}")

    fs = res.fs_diff or {}
    created = fs.get("created", [])
    modified = fs.get("modified", [])
    deleted = fs.get("deleted", [])
    print(f"Filesystem:   +{len(created)} created, ~{len(modified)} modified, -{len(deleted)} deleted")
    if created:
        for c in created[:5]:
            print(f"  {C_GREEN}+ {c['path']} ({c['size_bytes']} bytes){C_RESET}")
        if len(created) > 5:
            print(f"  {C_GRAY}... and {len(created) - 5} more{C_RESET}")

    if args.commit and res.committed:
        print(f"{C_GREEN}✓ Changes committed to destination: {args.dest}{C_RESET}")
    elif args.commit and not res.committed:
        print(f"{C_RED}✗ Failed to commit changes to destination: {args.dest}{C_RESET}")
    else:
        print(f"{C_DIM}Ephemeral scratch space destroyed.{C_RESET}")

    return 0 if res.exit_code == 0 else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the REST API and Glassmorphic Web Cockpit."""
    print_banner()
    port = args.port
    host = args.host

    print(f"{C_GREEN}● Starting Agent Capsule Jail Server on http://{host}:{port}{C_RESET}")
    print(f"  REST API:           http://{host}:{port}/api/exec")
    print(f"  Telemetry Stats:    http://{host}:{port}/api/stats")
    print(f"  Health Check:       http://{host}:{port}/api/health")
    print(f"  Glassmorphic GUI:   http://{host}:{port}/")
    print(f"{C_GRAY}  Flight Recorder:    http://127.0.0.1:8104/api/ingest{C_RESET}")
    print(f"{C_DIM}Press Ctrl+C to terminate server gracefully.{C_RESET}\n")

    server = CapsuleServer(host=host, port=port)
    try:
        server.start(block=True)
    except KeyboardInterrupt:
        print(f"\n{C_GOLD}Shutting down Agent Capsule Jail...{C_RESET}")
        server.stop()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Query live server status and display health metrics."""
    url = f"http://127.0.0.1:{args.port}/api/stats"
    health_url = f"http://127.0.0.1:{args.port}/api/health"

    print_banner()
    try:
        req = urllib.request.Request(health_url)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            health = json.loads(resp.read().decode("utf-8"))

        req_stats = urllib.request.Request(url)
        with urllib.request.urlopen(req_stats, timeout=2.0) as resp:
            stats = json.loads(resp.read().decode("utf-8"))

        print(f"{C_GREEN}● ONLINE{C_RESET} — agent-capsule-jail on port {args.port}")
        print(f"Uptime:             {stats.get('uptime_seconds', 0)}s")
        print(f"Total Capsules:     {stats.get('total_capsules', 0)}")
        print(f"Successes:          {C_GREEN}{stats.get('total_successes', 0)}{C_RESET}")
        print(f"Errors:             {C_RED}{stats.get('total_errors', 0)}{C_RESET}")
        print(f"Timeouts Enforced:  {C_GOLD}{stats.get('total_timeouts', 0)}{C_RESET}")
        print(f"Memory Kills:       {C_RED}{stats.get('total_memory_kills', 0)}{C_RESET}")
        print(f"Cumulative CPU:     {round(stats.get('cumulative_cpu_ms', 0), 2)} ms")
        print(f"RAM Shielded:       {round(stats.get('cumulative_ram_saved_mb', 0), 2)} MB")
        print(f"Flight Rec Events:  {stats.get('flight_recorder_events_sent', 0)}")
        return 0
    except Exception as e:
        print(f"{C_RED}● OFFLINE{C_RESET} — Could not reach http://127.0.0.1:{args.port} ({e})")
        return 1


def cmd_test(args: argparse.Namespace) -> int:
    """Run automated test suite."""
    print_banner()
    print(f"{C_CYAN}Running test suite...{C_RESET}")
    test_dir = Path(__file__).resolve().parent.parent.parent / "tests"
    cmd = [sys.executable, "-m", "pytest", str(test_dir), "-v"]
    try:
        return subprocess.run(cmd).returncode
    except FileNotFoundError:
        # Fallback to standard unittest if pytest not in PATH
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(test_dir)]
        return subprocess.run(cmd).returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-capsule",
        description="Autonomous ephemeral sandboxed execution engine and kernel enclave for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Command: exec
    p_exec = subparsers.add_parser("exec", help="Execute a command in an isolated ephemeral capsule")
    p_exec.add_argument("--timeout", type=float, default=30.0, help="CPU timeout in seconds (default: 30.0)")
    p_exec.add_argument("--memory", type=int, default=512, help="Memory ceiling in MB (default: 512)")
    p_exec.add_argument("--max-procs", type=int, default=64, help="Max process quota (default: 64)")
    p_exec.add_argument("--max-fsize", type=int, default=50, help="Max file size write in MB (default: 50)")
    p_exec.add_argument("--env", action="append", help="Allow specific host environment variable")
    p_exec.add_argument("--script", type=str, help="Path to Python script to execute inside capsule")
    p_exec.add_argument("--commit", action="store_true", help="Commit scratch changes to destination")
    p_exec.add_argument("--dest", type=str, help="Destination directory if committing")
    p_exec.add_argument("--json", action="store_true", help="Output result as pure JSON")
    p_exec.add_argument("--quiet", "-q", action="store_true", help="Suppress header banner")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="Command and arguments to execute")

    # Command: serve
    p_serve = subparsers.add_parser("serve", help="Run the REST API and Glassmorphic Web Cockpit")
    p_serve.add_argument("--port", type=int, default=8105, help="Port to bind (default: 8105)")
    p_serve.add_argument("--host", type=str, default=_default_bind_host(), help="Host interface (default: 127.0.0.1 or $ZOTH_BIND_HOST; use 0.0.0.0 only on trusted networks)")

    # Command: status
    p_status = subparsers.add_parser("status", help="Inspect status of running capsule daemon")
    p_status.add_argument("--port", type=int, default=8105, help="Daemon port (default: 8105)")

    # Command: test
    subparsers.add_parser("test", help="Run automated unit and integration tests")

    args = parser.parse_args()

    if args.subcommand == "exec":
        sys.exit(cmd_exec(args))
    elif args.subcommand == "serve":
        sys.exit(cmd_serve(args))
    elif args.subcommand == "status":
        sys.exit(cmd_status(args))
    elif args.subcommand == "test":
        sys.exit(cmd_test(args))
    else:
        print_banner()
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
