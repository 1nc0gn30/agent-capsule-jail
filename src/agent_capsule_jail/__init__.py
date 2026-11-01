"""agent-capsule-jail: Autonomous zero-dependency ephemeral sandboxed execution engine and kernel enclave.

Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from .capsule import (
    CapsuleConfig,
    CapsuleResult,
    CapsuleRunner,
    FilesystemDelta,
    ResourceLimits,
)

__version__ = "0.1.0"
__author__ = "1nc0gn30 (@1nc0gn30)"

__all__ = [
    "CapsuleConfig",
    "CapsuleResult",
    "CapsuleRunner",
    "FilesystemDelta",
    "ResourceLimits",
    "__version__",
]
