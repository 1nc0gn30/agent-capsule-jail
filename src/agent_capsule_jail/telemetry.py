"""Telemetry, Metrics Aggregation & Flight Recorder Forwarder.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import collections
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .capsule import CapsuleResult


@dataclass
class CapsuleStats:
    """Aggregated operational telemetry metrics."""
    total_capsules: int = 0
    active_capsules: int = 0
    total_successes: int = 0
    total_errors: int = 0
    total_timeouts: int = 0
    total_memory_kills: int = 0
    total_files_created: int = 0
    total_files_modified: int = 0
    total_files_deleted: int = 0
    cumulative_cpu_ms: float = 0.0   # sum of per-run user+sys CPU (os.wait4)
    cumulative_wall_ms: float = 0.0  # sum of per-run wall-clock durations
    peak_rss_kb: int = 0             # highest single-run max RSS seen
    uptime_seconds: float = 0.0
    flight_recorder_events_sent: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TelemetryRegistry:
    """Thread-safe telemetry store and event dispatcher."""

    def __init__(
        self,
        max_history: int = 100,
        flight_recorder_url: str = "http://127.0.0.1:8104/api/ingest",
    ):
        self.lock = threading.Lock()
        self.max_history = max_history
        self.history: Deque[Dict[str, Any]] = collections.deque(maxlen=max_history)
        self.flight_recorder_url = flight_recorder_url
        self.start_time = time.time()
        self.stats = CapsuleStats()

    def record_run(self, result: CapsuleResult) -> bool:
        """Record a completed capsule run and update metrics.
        Returns True only if the Flight Recorder acknowledged the event with a 2xx."""
        with self.lock:
            self.stats.total_capsules += 1
            if result.status == "success":
                self.stats.total_successes += 1
            elif result.status == "timeout":
                self.stats.total_timeouts += 1
            elif result.status == "oom_killed":
                self.stats.total_memory_kills += 1
            else:
                self.stats.total_errors += 1

            fs = result.fs_diff or {}
            self.stats.total_files_created += len(fs.get("created", []))
            self.stats.total_files_modified += len(fs.get("modified", []))
            self.stats.total_files_deleted += len(fs.get("deleted", []))

            self.stats.cumulative_cpu_ms += (result.cpu_time_user_s + result.cpu_time_sys_s) * 1000.0
            self.stats.cumulative_wall_ms += result.duration_ms
            self.stats.peak_rss_kb = max(self.stats.peak_rss_kb, int(result.max_rss_kb or 0))

        dispatched = self._forward_flight_recorder(result) if self.flight_recorder_url else False
        result.flight_recorder_dispatched = dispatched
        entry = result.to_dict()
        entry.pop("scratch_dir", None)
        with self.lock:
            self.history.appendleft(entry)
        return dispatched

    def _forward_flight_recorder(self, result: CapsuleResult) -> bool:
        """Short, bounded dispatch to agent-flight-recorder (0.5 s timeout). Returns True on 2xx."""
        try:
            fs = result.fs_diff or {}
            payload = {
                "session_id": "capsule-jail-audit",
                "event_type": "capsule_execution",
                "severity": "INFO" if result.status == "success" else "WARNING",
                "timestamp": result.timestamp,
                "payload": {
                    "capsule_id": result.capsule_id,
                    "command": result.command,
                    "exit_code": result.exit_code,
                    "status": result.status,
                    "duration_ms": result.duration_ms,
                    "timed_out": result.timed_out,
                    "memory_exceeded": result.memory_exceeded,
                    "files_created": len(fs.get("created", [])),
                    "files_modified": len(fs.get("modified", [])),
                    "files_deleted": len(fs.get("deleted", [])),
                    "max_rss_kb": result.max_rss_kb,
                    "receipt_sha256": result.receipt_sha256,
                },
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.flight_recorder_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                if 200 <= resp.status < 300:
                    with self.lock:
                        self.stats.flight_recorder_events_sent += 1
                    return True
        except Exception:
            # Flight recorder offline: report honestly as not dispatched.
            return False
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return snapshot of aggregated system metrics."""
        with self.lock:
            s = self.stats
            s.uptime_seconds = round(time.time() - self.start_time, 1)
            data = s.to_dict()
            data["recent_runs_cached"] = len(self.history)
            return data

    def get_recent_capsules(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return list of recent capsule runs."""
        with self.lock:
            return list(self.history)[:max(0, int(limit))]
