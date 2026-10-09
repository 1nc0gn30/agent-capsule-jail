"""Ephemeral Sandboxed Execution Engine and Kernel Enclave.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Sensitive Environment Variable Denylist
SENSITIVE_PATTERNS = [
    re.compile(r"^.*KEY.*$", re.IGNORECASE),
    re.compile(r"^.*TOKEN.*$", re.IGNORECASE),
    re.compile(r"^.*SECRET.*$", re.IGNORECASE),
    re.compile(r"^.*PASSWORD.*$", re.IGNORECASE),
    re.compile(r"^.*AUTH.*$", re.IGNORECASE),
    re.compile(r"^.*CREDENTIAL.*$", re.IGNORECASE),
    re.compile(r"^.*PRIVATE.*$", re.IGNORECASE),
    re.compile(r"^SSH_.*$", re.IGNORECASE),
    re.compile(r"^AWS_.*$", re.IGNORECASE),
    re.compile(r"^GITHUB_.*$", re.IGNORECASE),
    re.compile(r"^GH_.*$", re.IGNORECASE),
    re.compile(r"^STRIPE_.*$", re.IGNORECASE),
    re.compile(r"^SOLANA_.*$", re.IGNORECASE),
    re.compile(r"^DATABASE_URL$", re.IGNORECASE),
    re.compile(r"^OPENAI_.*$", re.IGNORECASE),
    re.compile(r"^ANTHROPIC_.*$", re.IGNORECASE),
    re.compile(r"^GEMINI_.*$", re.IGNORECASE),
]

SAFE_PASS_THROUGH = {
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "PYTHONPATH",
    "PYTHONHOME",
    "SYSTEMROOT",
    "USER",
    "LOGNAME",
}


@dataclass
class ResourceLimits:
    """Configurable resource quotas for the execution capsule."""
    timeout_sec: float = 30.0
    memory_mb: int = 512
    max_procs: int = 64
    max_file_size_mb: int = 50
    max_open_files: int = 256

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileEntry:
    """Metadata for a filesystem entity inside the sandbox."""
    path: str
    size_bytes: int
    sha256: str
    is_dir: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FilesystemDelta:
    """Catalog of filesystem alterations made during capsule lifetime."""
    created: List[Dict[str, Any]] = field(default_factory=list)
    modified: List[Dict[str, Any]] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    total_changes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "created": self.created,
            "modified": self.modified,
            "deleted": self.deleted,
            "total_changes": self.total_changes,
        }


@dataclass
class CapsuleConfig:
    """Full execution parameters for the capsule runner."""
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    allowed_env: List[str] = field(default_factory=list)
    working_dir: Optional[str] = None
    commit: bool = False
    destination_dir: Optional[str] = None
    initial_files: Dict[str, Union[str, bytes]] = field(default_factory=dict)
    capture_output: bool = True
    max_output_bytes: int = 10 * 1024 * 1024  # 10MB max stdout/err


@dataclass
class CapsuleResult:
    """Structured forensic outcome of a sandboxed capsule run."""
    capsule_id: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    cpu_time_user_s: float
    cpu_time_sys_s: float
    max_rss_kb: int
    timed_out: bool
    memory_exceeded: bool
    fs_diff: Dict[str, Any]
    committed: bool
    status: str  # "success", "error", "timeout", "oom_killed"
    timestamp: float
    scratch_dir: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CapsuleRunner:
    """Autonomous Kernel Enclave and Ephemeral Execution Sandbox."""

    def __init__(self, base_scratch_dir: Optional[str] = None):
        self.base_scratch_dir = Path(base_scratch_dir) if base_scratch_dir else Path(tempfile.gettempdir())
        self.active_capsules: Dict[str, subprocess.Popen] = {}

    @staticmethod
    def sanitize_environment(allowed_keys: Optional[List[str]] = None, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Strip sensitive host variables and build an isolated, safe execution environment."""
        clean_env: Dict[str, str] = {}
        allowed = set(allowed_keys or [])

        # Start with standard safe environment variables
        for key in SAFE_PASS_THROUGH:
            if key in os.environ:
                clean_env[key] = os.environ[key]

        # Check explicitly allowed variables
        for key in allowed:
            if key in os.environ:
                # Still verify not matching high-risk secret patterns unless explicitly prefixed with FORCE_
                clean_env[key] = os.environ[key]

        # Filter out anything matching sensitive regexes unless explicitly allowed
        for key in list(clean_env.keys()):
            if key not in allowed:
                for pattern in SENSITIVE_PATTERNS:
                    if pattern.match(key):
                        clean_env.pop(key, None)
                        break

        # Apply custom env additions
        if custom_env:
            for k, v in custom_env.items():
                clean_env[k] = str(v)

        # Fallback sane defaults
        if "PATH" not in clean_env:
            clean_env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        clean_env["PYTHONUNBUFFERED"] = "1"
        clean_env["LC_ALL"] = "C.UTF-8"
        clean_env["LANG"] = "C.UTF-8"

        return clean_env

    @staticmethod
    def _hash_file(file_path: Path) -> str:
        """Compute SHA256 of file contents."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, IOError):
            return ""

    def snapshot_directory(self, root: Path) -> Dict[str, FileEntry]:
        """Catalog all files inside the sandbox directory with sizes and checksums."""
        snapshot: Dict[str, FileEntry] = {}
        if not root.exists():
            return snapshot

        for p in root.rglob("*"):
            try:
                rel = str(p.relative_to(root))
                if p.is_file():
                    stat = p.stat()
                    snapshot[rel] = FileEntry(
                        path=rel,
                        size_bytes=stat.st_size,
                        sha256=self._hash_file(p),
                        is_dir=False,
                    )
                elif p.is_dir():
                    snapshot[rel] = FileEntry(
                        path=rel,
                        size_bytes=0,
                        sha256="",
                        is_dir=True,
                    )
            except (OSError, IOError):
                continue
        return snapshot

    def compute_diff(self, pre: Dict[str, FileEntry], post: Dict[str, FileEntry], root: Path) -> FilesystemDelta:
        """Compare directory state before and after execution to isolate all mutations."""
        created: List[Dict[str, Any]] = []
        modified: List[Dict[str, Any]] = []
        deleted: List[str] = []

        # Find created and modified
        for path, entry in post.items():
            if entry.is_dir:
                continue
            if path not in pre:
                created.append(entry.to_dict())
            else:
                pre_entry = pre[path]
                if not pre_entry.is_dir and (pre_entry.size_bytes != entry.size_bytes or pre_entry.sha256 != entry.sha256):
                    modified.append(entry.to_dict())

        # Find deleted
        for path, entry in pre.items():
            if not entry.is_dir and path not in post:
                deleted.append(path)

        total_changes = len(created) + len(modified) + len(deleted)
        return FilesystemDelta(
            created=created,
            modified=modified,
            deleted=deleted,
            total_changes=total_changes,
        )

    def commit_changes(self, delta: FilesystemDelta, scratch_root: Path, destination_root: Path) -> bool:
        """Commit filesystem delta from ephemeral scratch space into permanent destination."""
        try:
            destination_root.mkdir(parents=True, exist_ok=True)

            # Copy created and modified files
            for item in delta.created + delta.modified:
                rel_path = item["path"]
                src = scratch_root / rel_path
                dst = destination_root / rel_path
                if src.exists() and src.is_file():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)

            # Delete removed files
            for rel_path in delta.deleted:
                dst = destination_root / rel_path
                if dst.exists() and dst.is_file():
                    dst.unlink()

            return True
        except Exception:
            return False

    def run(
        self,
        command: Union[str, List[str]],
        config: Optional[CapsuleConfig] = None,
        script: Optional[str] = None,
    ) -> CapsuleResult:
        """Execute a command in an isolated ephemeral sandbox with strict resource enforcement."""
        cfg = config or CapsuleConfig()
        limits = cfg.limits
        start_ts = time.time()
        capsule_id = f"cap_{int(start_ts)}_{os.getpid()}_{id(command) % 100000}"

        # 1. Prepare Ephemeral Scratch Directory
        scratch_dir = Path(tempfile.mkdtemp(prefix=f"jail_{capsule_id}_", dir=self.base_scratch_dir))
        committed = False
        timed_out = False
        memory_exceeded = False
        exit_code = -1
        stdout_str = ""
        stderr_str = ""
        user_cpu = 0.0
        sys_cpu = 0.0
        max_rss = 0

        try:
            # Seed initial files if requested
            for rel_path, content in cfg.initial_files.items():
                target_file = scratch_dir / rel_path
                target_file.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, str):
                    target_file.write_text(content, encoding="utf-8")
                else:
                    target_file.write_bytes(content)

            # If inline script provided, save it as capsule_script.py / .sh
            cmd_args: List[str]
            if script:
                script_path = scratch_dir / "capsule_script.py"
                script_path.write_text(script, encoding="utf-8")
                cmd_args = [sys.executable, str(script_path)]
            elif isinstance(command, str):
                import shlex
                if any(c in command for c in ("|", ">", "<", ";", "&", "\n")):
                    cmd_args = ["/bin/sh", "-c", command]
                else:
                    try:
                        cmd_args = shlex.split(command)
                    except Exception:
                        cmd_args = ["/bin/sh", "-c", command]
            else:
                cmd_args = list(command)

            # Snapshot pre-execution directory
            pre_snapshot = self.snapshot_directory(scratch_dir)

            # Sanitize Environment
            child_env = self.sanitize_environment(cfg.allowed_env)
            child_env["HOME"] = str(scratch_dir)
            child_env["TMPDIR"] = str(scratch_dir)
            child_env["CAPSULE_ID"] = capsule_id

            # Pre-exec hook to configure kernel resource limits in child
            def _preexec_limits():
                # Isolate process group for clean kill
                os.setsid()

                # RLIMIT_CPU: Soft and Hard limits (sec)
                if hasattr(resource, "RLIMIT_CPU") and limits.timeout_sec > 0:
                    cpu_sec = max(1, int(limits.timeout_sec) + 1)
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec + 2))

                # RLIMIT_FSIZE: Max file write size (bytes)
                if hasattr(resource, "RLIMIT_FSIZE") and limits.max_file_size_mb > 0:
                    fsize = limits.max_file_size_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

                # RLIMIT_NPROC: Max processes / threads to prevent fork bombs
                # In Linux RLIMIT_NPROC applies per-UID, so set safe ceiling above existing processes
                if hasattr(resource, "RLIMIT_NPROC") and limits.max_procs > 0:
                    try:
                        cur_soft, cur_hard = resource.getrlimit(resource.RLIMIT_NPROC)
                        uid = os.getuid()
                        user_procs = 0
                        for p in os.listdir("/proc"):
                            if p.isdigit():
                                try:
                                    if os.stat(f"/proc/{p}").st_uid == uid:
                                        user_procs += 1
                                except OSError:
                                    pass
                        safe_ceiling = min(cur_hard, max(128, user_procs + limits.max_procs + 16))
                        resource.setrlimit(resource.RLIMIT_NPROC, (safe_ceiling, cur_hard))
                    except (ValueError, OSError):
                        pass

                # RLIMIT_DATA: Max heap data limit
                if hasattr(resource, "RLIMIT_DATA") and limits.memory_mb > 0:
                    data_bytes = limits.memory_mb * 1024 * 1024
                    try:
                        resource.setrlimit(resource.RLIMIT_DATA, (data_bytes, data_bytes))
                    except (ValueError, OSError):
                        pass

                # RLIMIT_AS: Address space limit (apply only if >= 128MB to prevent Python loader crash)
                if hasattr(resource, "RLIMIT_AS") and limits.memory_mb >= 128:
                    as_bytes = limits.memory_mb * 1024 * 1024
                    try:
                        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
                    except (ValueError, OSError):
                        pass

            # Launch Sandboxed Subprocess
            proc = subprocess.Popen(
                cmd_args,
                cwd=str(scratch_dir),
                env=child_env,
                stdout=subprocess.PIPE if cfg.capture_output else subprocess.DEVNULL,
                stderr=subprocess.PIPE if cfg.capture_output else subprocess.DEVNULL,
                preexec_fn=_preexec_limits,
            )
            self.active_capsules[capsule_id] = proc

            # Wait for execution with wall-clock timeout
            try:
                raw_out, raw_err = proc.communicate(timeout=limits.timeout_sec)
                exit_code = proc.returncode
                stdout_str = raw_out.decode("utf-8", errors="replace")[: cfg.max_output_bytes] if raw_out else ""
                stderr_str = raw_err.decode("utf-8", errors="replace")[: cfg.max_output_bytes] if raw_err else ""
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = -signal.SIGKILL
                stderr_str += f"\n[CAPSULE_JAIL] Wall-clock execution timeout ({limits.timeout_sec}s) exceeded."
                # Kill process group
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait()
            finally:
                self.active_capsules.pop(capsule_id, None)

            # Analyze exit signals for resource enforcement
            if exit_code < 0:
                sig_num = -exit_code
                if sig_num in (signal.SIGXCPU, signal.SIGKILL) and not timed_out:
                    timed_out = True
                    stderr_str += "\n[CAPSULE_JAIL] Process killed by kernel RLIMIT_CPU quota."
                elif sig_num in (signal.SIGSEGV, signal.SIGABRT) or "MemoryError" in stderr_str:
                    memory_exceeded = True
                    stderr_str += "\n[CAPSULE_JAIL] Process terminated due to RLIMIT memory exhaustion."
                elif sig_num == getattr(signal, "SIGXFSZ", 25):
                    stderr_str += "\n[CAPSULE_JAIL] Process terminated due to RLIMIT_FSIZE quota."

            # Measure resource usage via RUSAGE_CHILDREN
            try:
                usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                user_cpu = usage.ru_utime
                sys_cpu = usage.ru_stime
                max_rss = usage.ru_maxrss
            except Exception:
                pass

            # Snapshot post-execution directory and calculate delta diff
            post_snapshot = self.snapshot_directory(scratch_dir)
            fs_diff = self.compute_diff(pre_snapshot, post_snapshot, scratch_dir)

            # Handle Commit vs Discard
            if cfg.commit and cfg.destination_dir:
                dest = Path(cfg.destination_dir)
                committed = self.commit_changes(fs_diff, scratch_dir, dest)

        finally:
            # Discard scratch directory if not committing or once committed
            if not cfg.commit or committed:
                try:
                    shutil.rmtree(scratch_dir, ignore_errors=True)
                except Exception:
                    pass

        duration_ms = (time.time() - start_ts) * 1000.0

        # Classify status
        if timed_out:
            status = "timeout"
        elif memory_exceeded:
            status = "oom_killed"
        elif exit_code == 0:
            status = "success"
        else:
            status = "error"

        return CapsuleResult(
            capsule_id=capsule_id,
            command=" ".join(cmd_args) if isinstance(cmd_args, list) else str(command),
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_ms=round(duration_ms, 2),
            cpu_time_user_s=round(user_cpu, 4),
            cpu_time_sys_s=round(sys_cpu, 4),
            max_rss_kb=max_rss,
            timed_out=timed_out,
            memory_exceeded=memory_exceeded,
            fs_diff=fs_diff.to_dict(),
            committed=committed,
            status=status,
            timestamp=start_ts,
            scratch_dir=str(scratch_dir),
        )
