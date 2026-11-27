"""emberpool: warm-pool Firecracker microVM sandboxes for AI agents.

The public API is exactly what this module exports.
"""

from emberpool._types import Result
from emberpool.pool import Sandbox, SandboxPool

__all__ = ["SandboxPool", "Sandbox", "Result"]
