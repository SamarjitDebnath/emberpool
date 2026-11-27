"""Name validators and the only sanctioned way to run host commands.

Every name emberpool passes to `ip`, `nft` or the jailer is checked here at the
point of use (docs/40-rules.md rule 8). Every external command goes through
`run_command`: an argument list, no shell, a timeout and capped output
(rules 7 and 13).
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import secrets
import signal
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "NAME_PREFIX",
    "MAX_INTERFACE_LEN",
    "validate_vm_id",
    "validate_netns",
    "validate_interface",
    "validate_nft_table",
    "validate_nft_set",
    "validate_domain",
    "new_vm_id",
    "CommandResult",
    "CommandError",
    "CommandTimeout",
    "run_command",
]

# Every namespace, interface and nftables table emberpool creates starts with
# this prefix (rule 10). Test prefixes such as "ep-net" satisfy it too.
NAME_PREFIX = "ep"

# Linux IFNAMSIZ is 16 including the trailing NUL.
MAX_INTERFACE_LEN = 15

# Lowercase alphanumerics and single inner hyphens. Also valid as a jailer --id.
_VM_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
_NETNS_RE = re.compile(r"ep[a-z0-9-]{0,37}[a-z0-9]")
_INTERFACE_RE = re.compile(r"tap0|ep[a-z0-9-]{0,12}[a-z0-9]")
_NFT_TABLE_RE = re.compile(r"emberpool|ep[a-z0-9_-]{0,29}[a-z0-9]")
_NFT_SET_RE = re.compile(r"[a-z][a-z0-9_-]{0,62}")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _check(kind: str, value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{kind} must be a str, got {type(value).__name__}")
    if pattern.fullmatch(value) is None:
        raise ValueError(f"invalid {kind}: {value!r}")
    return value


def validate_vm_id(value: object) -> str:
    """1-32 chars: lowercase letters, digits, inner hyphens."""
    return _check("vm_id", value, _VM_ID_RE)


def validate_netns(value: object) -> str:
    """Network namespace name: starts with "ep", at most 40 chars."""
    return _check("netns", value, _NETNS_RE)


def validate_interface(value: object) -> str:
    """Interface name: "tap0", or "ep"-prefixed and at most 15 chars."""
    name = _check("interface", value, _INTERFACE_RE)
    if len(name) > MAX_INTERFACE_LEN:  # pattern already bounds it; belt and braces
        raise ValueError(f"interface name too long: {name!r}")
    return name


def validate_nft_table(value: object) -> str:
    """nftables table name: "emberpool", or starts with "ep" and at most 32 chars."""
    return _check("nft table", value, _NFT_TABLE_RE)


def validate_nft_set(value: object) -> str:
    """nftables set name: lowercase start, at most 63 chars."""
    return _check("nft set", value, _NFT_SET_RE)


def validate_domain(value: object) -> str:
    """Validate an allowlisted domain name and return it lowercased.

    ASCII only (IDNs must be given in punycode), at least two labels, no
    wildcards, no IP literals, one optional trailing dot which is removed.
    """
    if not isinstance(value, str):
        raise ValueError(f"domain must be a str, got {type(value).__name__}")
    if not value.isascii():
        raise ValueError(f"invalid domain (non-ASCII, use punycode): {value!r}")
    name = value.lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253:
        raise ValueError(f"invalid domain length: {value!r}")
    labels = name.split(".")
    if len(labels) < 2:
        raise ValueError(f"domain needs at least two labels: {value!r}")
    for label in labels:
        if _LABEL_RE.fullmatch(label) is None:
            raise ValueError(f"invalid domain label {label!r} in {value!r}")
    if labels[-1].isdigit():
        raise ValueError(f"IP literals are not domain names: {value!r}")
    return name


def new_vm_id() -> str:
    """A fresh random VM id: 8 lowercase hex chars."""
    return secrets.token_hex(4)


# --------------------------------------------------------------------------
# Host commands
# --------------------------------------------------------------------------

# Fixed environment for host tools: nothing inherited from the caller.
_COMMAND_ENV: Mapping[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}
DEFAULT_MAX_OUTPUT = 1 << 20  # bytes kept per stream
_KILL_WAIT = 5.0


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class CommandError(RuntimeError):
    """The command exited non-zero (only raised with check=True)."""

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        tail = result.stderr[-500:].decode("utf-8", "replace").strip()
        super().__init__(f"{result.argv[0]} exited {result.returncode}: {tail}")


class CommandTimeout(TimeoutError):
    """The command ran past its timeout and was killed."""

    def __init__(self, argv: tuple[str, ...], timeout: float) -> None:
        self.argv = argv
        self.timeout = timeout
        super().__init__(f"{argv[0]} timed out after {timeout}s and was killed")


def _check_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise TypeError("argv must be a sequence of str, not a single string")
    args = tuple(argv)
    if not args:
        raise ValueError("argv is empty")
    for arg in args:
        if not isinstance(arg, str):
            raise TypeError(f"argv items must be str, got {type(arg).__name__}")
        if "\x00" in arg:
            raise ValueError("argv items must not contain NUL")
    if not args[0]:
        raise ValueError("argv[0] is empty")
    return args


async def _read_capped(stream: asyncio.StreamReader, cap: int) -> tuple[bytes, bool]:
    buf = bytearray()
    truncated = False
    while chunk := await stream.read(65536):
        room = cap - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            truncated = True  # keep draining so the child never blocks
    return bytes(buf), truncated


async def _feed(stream: asyncio.StreamWriter, data: bytes | None) -> None:
    try:
        if data:
            stream.write(data)
            await stream.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        stream.close()


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def run_command(
    argv: Sequence[str],
    *,
    timeout: float,
    stdin: bytes | None = None,
    check: bool = True,
    max_output: int = DEFAULT_MAX_OUTPUT,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run one external command safely.

    - argv is a list, never a string; no shell is involved.
    - The child gets a fixed minimal environment (plus `env`, if given) and
      its own process group.
    - On timeout or cancellation the whole process group is killed and reaped.
    - stdout and stderr are each capped at `max_output` bytes.
    - With check=True a non-zero exit raises CommandError.
    """
    args = _check_argv(argv)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive and finite")
    if max_output < 0:
        raise ValueError("max_output must be >= 0")

    child_env = dict(_COMMAND_ENV)
    if env:
        child_env.update(env)

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=child_env,
        start_new_session=True,
    )
    assert proc.stdin and proc.stdout and proc.stderr
    try:
        try:
            async with asyncio.timeout(timeout):
                (out, out_trunc), (err, err_trunc), _, returncode = await asyncio.gather(
                    _read_capped(proc.stdout, max_output),
                    _read_capped(proc.stderr, max_output),
                    _feed(proc.stdin, stdin),
                    proc.wait(),
                )
        except TimeoutError:
            raise CommandTimeout(args, timeout) from None
    finally:
        if proc.returncode is None:
            _kill_group(proc)
            try:
                await asyncio.wait_for(asyncio.shield(proc.wait()), _KILL_WAIT)
            except TimeoutError:
                pass  # SIGKILL sent; nothing more we can do

    result = CommandResult(args, returncode, out, err, out_trunc, err_trunc)
    if check and returncode != 0:
        raise CommandError(result)
    return result
