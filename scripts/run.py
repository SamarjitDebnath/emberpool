"""Run one piece of Python code in a fresh sandbox and print the result.

Usage (as root, with EMBERPOOL_* settings in the environment):
    uv run --no-sync python scripts/run.py 'print(1 + 1)' [network] [timeout]

network is "deny" (default) or "allow:<name>,<name>". The guest's stdout goes
to stdout; its stderr, the timeout flag, file changes and the network trace go
to stderr. The exit status is the guest's exit code (255 for -1).
"""

from __future__ import annotations

import asyncio
import sys

from emberpool import SandboxPool


async def main(code: str, network: str, timeout: float) -> int:
    async with SandboxPool(size=1, network=network) as pool:
        result = await pool.run(code, timeout=timeout)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    print(f"-- exit_code={result.exit_code} timed_out={result.timed_out}", file=sys.stderr)
    for path in result.file_changes:
        print(f"-- changed: {path}", file=sys.stderr)
    for event in result.trace:
        print(f"-- trace: {event}", file=sys.stderr)
    return result.exit_code & 0xFF


if __name__ == "__main__":
    if not 2 <= len(sys.argv) <= 4:
        sys.exit(__doc__)
    code = sys.argv[1]
    network = sys.argv[2] if len(sys.argv) > 2 else "deny"
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0
    sys.exit(asyncio.run(main(code, network, timeout)))
