#!/usr/bin/env python3
"""Agent Capsule Jail - Root Server Launcher
Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""
import sys
from pathlib import Path
import argparse

src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from agent_capsule_jail.server import CapsuleServer

def main():
    parser = argparse.ArgumentParser(description="Agent Capsule Jail Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8105, help="Port to bind to")
    args = parser.parse_args()

    print(f"Starting Agent Capsule Jail on http://{args.host}:{args.port}")
    server = CapsuleServer(host=args.host, port=args.port)
    server.start(block=True)

if __name__ == "__main__":
    main()
