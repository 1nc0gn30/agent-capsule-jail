"""Ephemeral Sandboxed Execution Engine and Kernel Enclave.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.

Isolation boundary: Linux bubblewrap (read-only root, private tmpfs /home /root /run /tmp,
--unshare-all, --cap-drop ALL, --die-with-parent) plus rlimits, a per-capsule cgroup
TasksMax scope (systemd-run --user --scope, when available), environment secret stripping,
per-run os.wait4 rusage and a SHA-256 receipt over every result.
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
import threading
import time
from functools import lru_cache
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

# Only locale/terminal hints pass through. PATH, USER and LOGNAME are replaced with fixed
# values so host usernames / home paths never leak into the capsule.
SAFE_PASS_THROUGH = {
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
}

SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"

# Resource clamps shared by the REST API, CLI and MCP server.
LIMIT_BOUNDS = {
    "timeout_sec": (0.5, 60.0),
    "memory_mb": (32, 4096),
    "max_procs": (1, 512),
    "max_file_size_mb": (1, 1024),
}

OOM_MARKERS = ("MemoryError", "Cannot allocate memory", "std::bad_alloc", "out of memory")


def is_sensitive_env(name: str) -> bool:
    return any(p.match(name) for p in SENSITIVE_PATTERNS)


def network_opt_in_enabled() -> bool:
    """allow_network is an operator decision (host env), never an API caller decision."""
    return os.environ.get("CAPSULE_ALLOW_NETWORK") == "1"


def force_sensitive_env_enabled() -> bool:
    return os.environ.get("CAPSULE_FORCE_SENSITIVE_ENV") == "1"


@lru_cache(maxsize=1)
def _cgroup_scope_works() -> bool:
    if os.environ.get("CAPSULE_DISABLE_CGROUP") == "1" or not shutil.which("systemd-run"):
        return False
    try:
        r = subprocess.run(
            ["systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", "TasksMax=8", "true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def pids_enforcement() -> str:
    """How the per-capsule process cap is enforced on this host.
    'cgroup-tasksmax': systemd user scope with pids.max (exact per-capsule cap).
    'rlimit-nproc': prlimit RLIMIT_NPROC ceiling (per-UID on Linux, so approximate).
    'none': neither mechanism is available."""
    if os.environ.get("CAPSULE_DISABLE_CGROUP") != "1" and _cgroup_scope_works():
        return "cgroup-tasksmax"
    if shutil.which("prlimit"):
        return "rlimit-nproc"
    return "none"


def _capsule_python() -> str:
    for cand in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if os.path.exists(cand):
            return cand
    return sys.executable


def compute_receipt(capsule_id: str, command: str, exit_code: int, stdout: str, stderr: str,
                    fs_diff: Dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the forensic fields (sorted keys, no whitespace)."""
    canonical = json.dumps(
        {"capsule_id": capsule_id, "command": command, "exit_code": exit_code,
         "stdout": stdout, "stderr": stderr, "fs_diff": fs_diff},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    allow_network: bool = False  # sandbox has no network unless explicitly requested


class CapsuleSecurityError(ValueError):
    """Request rejected by sandbox policy (path escape, allowlist, no sandbox)."""


class CapsuleNetworkDenied(CapsuleSecurityError):
    """allow_network was requested but the operator has not set CAPSULE_ALLOW_NETWORK=1."""


def _bwrap_path() -> Optional[str]:
    return shutil.which("bwrap")


def sandbox_mode() -> str:
    """'bwrap' when bubblewrap isolation is available, 'unsandboxed' only when the
    operator explicitly opted in with CAPSULE_ALLOW_UNSANDBOXED=1, else 'unavailable'."""
    if os.environ.get("CAPSULE_DISABLE_BWRAP") != "1" and _bwrap_path():
        return "bwrap"
    if os.environ.get("CAPSULE_ALLOW_UNSANDBOXED") == "1":
        return "unsandboxed"
    return "unavailable"


def allowed_commands() -> Optional[Set[str]]:
    raw = os.environ.get("CAPSULE_ALLOWED_COMMANDS", "").strip()
    return {c.strip() for c in raw.split(",") if c.strip()} or None if raw else None


def commit_roots() -> List[Path]:
    raw = os.environ.get("CAPSULE_COMMIT_ROOTS", "")
    roots = [Path(r).expanduser() for r in raw.split(os.pathsep) if r.strip()]
    return [r.resolve() for r in (roots or [Path.home() / "capsule-commits"])]


def _inside(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def safe_relpath(scratch: Path, rel: str) -> Path:
    """Resolve rel inside scratch; reject absolute paths, '..' escapes and NULs."""
    if not isinstance(rel, str) or not rel or "\x00" in rel or os.path.isabs(rel):
        raise CapsuleSecurityError(f"invalid file path {rel!r}")
    target = (scratch / rel).resolve()
    if not _inside(target, scratch.resolve()) or target == scratch.resolve():
        raise CapsuleSecurityError(f"path escapes the capsule: {rel!r}")
    return target


def _set_no_new_privs() -> None:
    """PR_SET_NO_NEW_PRIVS: sudo / setuid binaries can no longer gain privileges."""
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(38, 1, 0, 0, 0)
    except Exception:
        pass


def build_bwrap_argv(cmd_args: List[str], scratch: Path, allow_network: bool) -> List[str]:
    """Read-only root, private /tmp and /home (only the scratch dir is writable),
    all namespaces unshared (no network unless allowed), all capabilities dropped.
    bwrap also sets no_new_privs, so sudo/setuid cannot escalate."""
    s = str(scratch)
    argv = [
        _bwrap_path() or "bwrap",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/home",
        "--tmpfs", "/root",
        "--bind", s, s,
        "--chdir", s,
        "--unshare-all",
        # The command runs as PID 1 of the capsule's PID namespace (no intermediate bwrap
        # init), so os.wait4() on our child carries this capsule's real CPU/RSS usage.
        "--as-pid-1",
        "--die-with-parent",
        "--new-session",
        "--cap-drop", "ALL",
    ]
    if allow_network:
        argv.append("--share-net")  # keep /run so resolv.conf (-> /run/...) still works
    else:
        argv[argv.index("--bind"):argv.index("--bind")] = ["--tmpfs", "/run"]
    return argv + ["--"] + cmd_args


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
    sandbox_argv: List[str] = field(default_factory=list)
    sandbox_mode: str = ""
    pids_enforcement: str = ""
    limits: Dict[str, Any] = field(default_factory=dict)
    env_denied: List[str] = field(default_factory=list)
    receipt_sha256: str = ""
    flight_recorder_dispatched: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cpu_time_system_s"] = self.cpu_time_sys_s
        return d

    def verify_receipt(self) -> bool:
        return self.receipt_sha256 == compute_receipt(
            self.capsule_id, self.command, self.exit_code, self.stdout, self.stderr, self.fs_diff)


class CapsuleRunner:
    """Autonomous Kernel Enclave and Ephemeral Execution Sandbox."""

    def __init__(self, base_scratch_dir: Optional[str] = None):
        self.base_scratch_dir = Path(base_scratch_dir) if base_scratch_dir else Path(tempfile.gettempdir())
        self.active_capsules: Dict[str, subprocess.Popen] = {}

    @staticmethod
    def sanitize_environment_report(allowed_keys: Optional[List[str]] = None,
                                    custom_env: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, str], List[str]]:
        """Build the capsule environment. Returns (env, denied_names).
        Names matching SENSITIVE_PATTERNS are stripped even when listed in allowed_keys;
        only the host operator can override that with CAPSULE_FORCE_SENSITIVE_ENV=1."""
        clean_env: Dict[str, str] = {}
        denied: List[str] = []
        force = force_sensitive_env_enabled()

        for key in SAFE_PASS_THROUGH:
            if key in os.environ:
                clean_env[key] = os.environ[key]

        for key in (allowed_keys or []):
            if not isinstance(key, str) or not key or key in ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR"):
                continue
            if is_sensitive_env(key) and not force:
                denied.append(key)
                continue
            if key in os.environ:
                clean_env[key] = os.environ[key]

        if custom_env:
            for k, v in custom_env.items():
                if is_sensitive_env(k) and not force:
                    denied.append(k)
                    continue
                clean_env[k] = str(v)

        clean_env["PATH"] = SAFE_PATH
        clean_env["USER"] = "capsule"
        clean_env["LOGNAME"] = "capsule"
        clean_env["PYTHONUNBUFFERED"] = "1"
        clean_env["LC_ALL"] = "C.UTF-8"
        clean_env["LANG"] = "C.UTF-8"
        return clean_env, sorted(set(denied))

    @staticmethod
    def sanitize_environment(allowed_keys: Optional[List[str]] = None, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Strip sensitive host variables and build an isolated, safe execution environment."""
        return CapsuleRunner.sanitize_environment_report(allowed_keys, custom_env)[0]

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
        """Commit filesystem delta from ephemeral scratch space into permanent destination.
        Destination must sit inside an allowed commit root (CAPSULE_COMMIT_ROOTS,
        default ~/capsule-commits); symlinks are never followed or copied."""
        try:
            destination_root = Path(destination_root).expanduser().resolve()
            if not any(_inside(destination_root, r) for r in commit_roots()):
                raise CapsuleSecurityError(
                    f"destination {destination_root} is outside the allowed commit roots "
                    f"({', '.join(str(r) for r in commit_roots())}); set CAPSULE_COMMIT_ROOTS to allow it")
            destination_root.mkdir(parents=True, exist_ok=True)
            scratch_real = scratch_root.resolve()

            # Copy created and modified files (regular files only, never via symlinks)
            for item in delta.created + delta.modified:
                rel_path = item["path"]
                src = scratch_root / rel_path
                if src.is_symlink() or not _inside(src.resolve(), scratch_real):
                    continue
                dst = (destination_root / rel_path).resolve()
                if not _inside(dst, destination_root):
                    continue
                if src.is_file():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst, follow_symlinks=False)

            # Delete removed files (only inside the destination root)
            for rel_path in delta.deleted:
                dst = destination_root / rel_path
                if dst.is_symlink() or not _inside(dst.resolve(), destination_root):
                    continue
                if dst.is_file():
                    dst.unlink()

            return True
        except CapsuleSecurityError:
            raise
        except Exception:
            return False

    @staticmethod
    def _drain(stream, sink: List[bytes], limit: int) -> None:
        """Read a pipe to EOF, keeping at most `limit` bytes (keeps draining so the child never blocks)."""
        total = 0
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                if total < limit:
                    sink.append(chunk[: limit - total])
                total += len(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def run(
        self,
        command: Union[str, List[str]],
        config: Optional[CapsuleConfig] = None,
        script: Optional[str] = None,
    ) -> CapsuleResult:
        """Execute a command in an isolated ephemeral sandbox with strict resource enforcement."""
        import shlex
        import uuid

        cfg = config or CapsuleConfig()
        limits = cfg.limits
        start_ts = time.time()
        capsule_id = f"cap_{int(start_ts)}_{uuid.uuid4().hex[:10]}"

        mode = sandbox_mode()
        if mode == "unavailable":
            raise CapsuleSecurityError(
                "bubblewrap (bwrap) is not installed, so commands cannot be isolated. "
                "Install bubblewrap, or set CAPSULE_ALLOW_UNSANDBOXED=1 to run without isolation.")
        if cfg.allow_network and not network_opt_in_enabled():
            raise CapsuleNetworkDenied(
                "allow_network is disabled on this host; the operator must start the daemon "
                "with CAPSULE_ALLOW_NETWORK=1 to permit networked capsules")

        pids_mode = pids_enforcement() if mode == "bwrap" else ("rlimit-nproc" if limits.max_procs > 0 else "none")

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
        env_denied: List[str] = []
        display_cmd = ""
        cmd_args: List[str] = []
        fs_diff = FilesystemDelta()

        try:
            # Seed initial files if requested
            for rel_path, content in cfg.initial_files.items():
                target_file = safe_relpath(scratch_dir, rel_path)
                target_file.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, str):
                    target_file.write_text(content, encoding="utf-8")
                else:
                    target_file.write_bytes(content)

            # Resolve argv. Inline scripts are written to capsule_script.py.
            if script:
                script_path = scratch_dir / "capsule_script.py"
                script_path.write_text(script, encoding="utf-8")
                cmd_args = [_capsule_python(), str(script_path)]
                display_cmd = "python3 capsule_script.py"
            elif isinstance(command, str):
                display_cmd = command
                if any(c in command for c in ("|", ">", "<", ";", "&", "\n", "$", "`")):
                    cmd_args = ["/bin/sh", "-c", command]
                else:
                    try:
                        cmd_args = shlex.split(command)
                    except ValueError:
                        cmd_args = ["/bin/sh", "-c", command]
            else:
                cmd_args = [str(c) for c in command]
                display_cmd = shlex.join(cmd_args)
            if not cmd_args:
                raise CapsuleSecurityError("empty command")

            allow = allowed_commands()
            if allow is not None:
                prog = os.path.basename(cmd_args[0]) if cmd_args else ""
                if script:
                    prog = "python3"
                if cmd_args[:2] == ["/bin/sh", "-c"]:
                    prog = "sh"
                if prog not in allow:
                    raise CapsuleSecurityError(
                        f"command {prog!r} is not in CAPSULE_ALLOWED_COMMANDS ({', '.join(sorted(allow))})")

            if mode == "bwrap":
                if pids_mode == "rlimit-nproc" and limits.max_procs > 0:
                    # RLIMIT_NPROC must be applied *inside* the sandbox (set before bwrap it blocks
                    # bwrap's own clone). It is per-UID on Linux, so the ceiling has to include the
                    # processes this UID already owns: approximate, reported as such.
                    uid = os.getuid()
                    owned = 0
                    for d in os.listdir("/proc"):
                        if d.isdigit():
                            try:
                                owned += os.stat(f"/proc/{d}").st_uid == uid
                            except OSError:
                                pass
                    ceiling = owned + limits.max_procs + 4
                    cmd_args = ["prlimit", f"--nproc={ceiling}:{ceiling}", "--"] + cmd_args
                cmd_args = build_bwrap_argv(cmd_args, scratch_dir, cfg.allow_network)
                if pids_mode == "cgroup-tasksmax":
                    # Exact per-capsule cap: systemd-run execs bwrap (--as-pid-1) inside a transient scope
                    # whose pids.max counts bwrap parent (1) + PID 1 command (1) + up to max_procs children.
                    cmd_args = ["systemd-run", "--user", "--scope", "--quiet", "--collect",
                                "-p", f"TasksMax={limits.max_procs + 2}",
                                "-p", f"MemoryMax={limits.memory_mb + 64}M",
                                "--"] + cmd_args

            pre_snapshot = self.snapshot_directory(scratch_dir)

            child_env, env_denied = self.sanitize_environment_report(cfg.allowed_env)
            child_env["HOME"] = str(scratch_dir)
            child_env["TMPDIR"] = str(scratch_dir)
            child_env["CAPSULE_ID"] = capsule_id
            if pids_mode == "cgroup-tasksmax":
                # systemd-run needs the user bus; these are not secrets and are not
                # visible inside bwrap beyond what the capsule env already exposes.
                for k in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
                    if k in os.environ:
                        child_env[k] = os.environ[k]

            def _preexec_limits():
                os.setsid()
                _set_no_new_privs()
                if hasattr(resource, "RLIMIT_CPU") and limits.timeout_sec > 0:
                    cpu_sec = max(1, int(limits.timeout_sec) + 1)
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec + 2))
                if hasattr(resource, "RLIMIT_FSIZE") and limits.max_file_size_mb > 0:
                    fsize = limits.max_file_size_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
                if mode != "bwrap" and hasattr(resource, "RLIMIT_NPROC") and limits.max_procs > 0:
                    try:
                        _cur_soft, cur_hard = resource.getrlimit(resource.RLIMIT_NPROC)
                        uid = os.getuid()
                        user_procs = 0
                        for p in os.listdir("/proc"):
                            if p.isdigit():
                                try:
                                    if os.stat(f"/proc/{p}").st_uid == uid:
                                        user_procs += 1
                                except OSError:
                                    pass
                        safe_ceiling = min(cur_hard, user_procs + limits.max_procs + 4)
                        resource.setrlimit(resource.RLIMIT_NPROC, (safe_ceiling, cur_hard))
                    except (ValueError, OSError):
                        pass
                if hasattr(resource, "RLIMIT_DATA") and limits.memory_mb > 0:
                    data_bytes = limits.memory_mb * 1024 * 1024
                    try:
                        resource.setrlimit(resource.RLIMIT_DATA, (data_bytes, data_bytes))
                    except (ValueError, OSError):
                        pass
                if hasattr(resource, "RLIMIT_AS") and limits.memory_mb >= 128:
                    as_bytes = limits.memory_mb * 1024 * 1024
                    try:
                        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
                    except (ValueError, OSError):
                        pass

            # Child is reaped with os.wait4 (not Popen.wait) so the rusage belongs to
            # this capsule only: cumulative RUSAGE_CHILDREN would mix every past run.
            proc = subprocess.Popen(
                cmd_args,
                cwd=str(scratch_dir),
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if cfg.capture_output else subprocess.DEVNULL,
                stderr=subprocess.PIPE if cfg.capture_output else subprocess.DEVNULL,
                preexec_fn=_preexec_limits,
            )
            self.active_capsules[capsule_id] = proc
            out_buf: List[bytes] = []
            err_buf: List[bytes] = []
            readers = []
            for stream, sink in ((proc.stdout, out_buf), (proc.stderr, err_buf)):
                if stream is not None:
                    t = threading.Thread(target=self._drain, args=(stream, sink, cfg.max_output_bytes), daemon=True)
                    t.start()
                    readers.append(t)

            reaped: Dict[str, Any] = {}

            def _reap() -> None:
                try:
                    _pid, status, usage = os.wait4(proc.pid, 0)
                    reaped["status"] = status
                    reaped["usage"] = usage
                except ChildProcessError:
                    pass

            waiter = threading.Thread(target=_reap, daemon=True)
            waiter.start()
            try:
                waiter.join(limits.timeout_sec)
                if waiter.is_alive():
                    timed_out = True
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except OSError:
                        try:
                            proc.kill()
                        except OSError:
                            pass
                    waiter.join(10)
                for t in readers:
                    t.join(5)
            finally:
                self.active_capsules.pop(capsule_id, None)

            if "status" in reaped:
                exit_code = os.waitstatus_to_exitcode(reaped["status"])
                usage = reaped["usage"]
                user_cpu = usage.ru_utime
                sys_cpu = usage.ru_stime
                max_rss = int(usage.ru_maxrss)
            else:
                exit_code = -signal.SIGKILL
            proc.returncode = exit_code  # already reaped; keep Popen from waiting again

            stdout_str = b"".join(out_buf).decode("utf-8", errors="replace")
            stderr_str = b"".join(err_buf).decode("utf-8", errors="replace")
            if timed_out:
                exit_code = -signal.SIGKILL
                stderr_str += f"\n[CAPSULE_JAIL] Wall-clock execution timeout ({limits.timeout_sec}s) exceeded."

            # Classify resource enforcement outcomes
            if not timed_out:
                if any(m in stderr_str for m in OOM_MARKERS):
                    memory_exceeded = True
                    stderr_str += "\n[CAPSULE_JAIL] Memory quota exhausted (allocation refused under RLIMIT_AS / MemoryMax)."
                elif exit_code < 0:
                    sig_num = -exit_code
                    cpu_used = user_cpu + sys_cpu
                    cpu_cap = max(1, int(limits.timeout_sec) + 1)
                    if sig_num == signal.SIGKILL and cpu_used < cpu_cap - 0.25:
                        # SIGKILL well below the CPU rlimit: the cgroup MemoryMax OOM killer.
                        memory_exceeded = True
                        stderr_str += "\n[CAPSULE_JAIL] Process killed by the capsule cgroup memory limit (OOM)."
                    elif sig_num == signal.SIGXCPU or sig_num == signal.SIGKILL:
                        timed_out = True
                        stderr_str += "\n[CAPSULE_JAIL] Process killed by kernel RLIMIT_CPU quota."
                    elif sig_num in (signal.SIGSEGV, signal.SIGABRT):
                        memory_exceeded = True
                        stderr_str += "\n[CAPSULE_JAIL] Process aborted; likely RLIMIT_AS memory exhaustion."
                    elif sig_num == getattr(signal, "SIGXFSZ", 25):
                        stderr_str += "\n[CAPSULE_JAIL] Process terminated due to RLIMIT_FSIZE quota."

            post_snapshot = self.snapshot_directory(scratch_dir)
            fs_diff = self.compute_diff(pre_snapshot, post_snapshot, scratch_dir)

            if cfg.commit and cfg.destination_dir:
                dest = Path(cfg.destination_dir)
                committed = self.commit_changes(fs_diff, scratch_dir, dest)

        finally:
            # Always discard the scratch dir (committed files were already copied out).
            try:
                shutil.rmtree(scratch_dir, ignore_errors=True)
            except Exception:
                pass

        duration_ms = (time.time() - start_ts) * 1000.0

        if timed_out:
            status = "timeout"
        elif memory_exceeded:
            status = "oom_killed"
        elif exit_code == 0:
            status = "success"
        else:
            status = "error"

        fs_dict = fs_diff.to_dict()
        return CapsuleResult(
            capsule_id=capsule_id,
            command=display_cmd,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_ms=round(duration_ms, 2),
            cpu_time_user_s=round(user_cpu, 4),
            cpu_time_sys_s=round(sys_cpu, 4),
            max_rss_kb=max_rss,
            timed_out=timed_out,
            memory_exceeded=memory_exceeded,
            fs_diff=fs_dict,
            committed=committed,
            status=status,
            timestamp=start_ts,
            scratch_dir=str(scratch_dir),
            sandbox_argv=list(cmd_args),
            sandbox_mode=mode,
            pids_enforcement=pids_mode,
            limits=limits.to_dict(),
            env_denied=env_denied,
            receipt_sha256=compute_receipt(capsule_id, display_cmd, exit_code, stdout_str, stderr_str, fs_dict),
        )
