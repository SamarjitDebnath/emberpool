"""vsock wire format between host and guest agent. Frozen contract.

Standard library only, no emberpool imports: the guest agent vendors an exact
copy of this file.

A frame is a 4-byte big-endian unsigned length followed by that many bytes of
UTF-8 JSON. The length is checked against MAX_FRAME before anything is read
or allocated.

Request  {"v": 1, "code": str, "timeout": number, "files": null}
Response {"v": 1, "stdout": str, "stderr": str, "exit_code": int}

"files" is reserved for v0.2. In v0.1 it may be absent or null; anything else
is rejected. Decoding is strict: exact key sets, exact types, no NaN or
Infinity, no duplicate keys, unknown versions rejected.
"""

from __future__ import annotations

import asyncio
import json
import math
import socket
import struct
from dataclasses import dataclass
from typing import Any

__all__ = [
    "PROTOCOL_VERSION",
    "HEADER_SIZE",
    "MAX_FRAME",
    "MAX_CODE_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_TIMEOUT",
    "ProtocolError",
    "Request",
    "Response",
    "frame",
    "parse_header",
    "encode_request",
    "decode_request",
    "encode_response",
    "decode_response",
    "read_frame",
    "recv_frame",
]

PROTOCOL_VERSION = 1
HEADER_SIZE = 4
_HEADER = struct.Struct(">I")

# Hard ceiling on one frame's payload.
MAX_FRAME = 16 * 1024 * 1024
# Limits on the content. The agent must truncate stdout and stderr to
# MAX_OUTPUT_BYTES of UTF-8 each so a response always fits in MAX_FRAME, even
# when every character is JSON-escaped (up to 6 bytes each).
MAX_CODE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TIMEOUT = 24 * 3600.0
_EXIT_CODE_RANGE = (-(2**31), 2**31 - 1)

_REQUEST_KEYS = frozenset({"v", "code", "timeout", "files"})
_REQUEST_REQUIRED = frozenset({"v", "code", "timeout"})
_RESPONSE_KEYS = frozenset({"v", "stdout", "stderr", "exit_code"})


class ProtocolError(ValueError):
    """Malformed, oversized or unsupported frame."""


@dataclass(frozen=True, slots=True)
class Request:
    code: str
    timeout: float


@dataclass(frozen=True, slots=True)
class Response:
    stdout: str
    stderr: str
    exit_code: int


# --------------------------------------------------------------------------
# Framing
# --------------------------------------------------------------------------


def frame(payload: bytes, max_size: int = MAX_FRAME) -> bytes:
    """Prefix a payload with its length."""
    if not 0 < len(payload) <= max_size:
        raise ProtocolError(f"frame payload size {len(payload)} out of range 1..{max_size}")
    return _HEADER.pack(len(payload)) + payload


def parse_header(header: bytes, max_size: int = MAX_FRAME) -> int:
    """Return the payload length from a 4-byte header, rejecting bad sizes."""
    if len(header) != HEADER_SIZE:
        raise ProtocolError(f"short frame header: {len(header)} bytes")
    (length,) = _HEADER.unpack(header)
    if length == 0:
        raise ProtocolError("empty frame")
    if length > max_size:
        raise ProtocolError(f"frame too large: {length} > {max_size}")
    return length


async def read_frame(reader: asyncio.StreamReader, max_size: int = MAX_FRAME) -> bytes:
    """Read one frame payload. Callers bound the wait with a timeout."""
    try:
        header = await reader.readexactly(HEADER_SIZE)
        length = parse_header(header, max_size)
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise ProtocolError(f"short read: got {len(e.partial)} of {e.expected} bytes") from None


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ProtocolError(f"short read: got {len(buf)} of {n} bytes")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket, max_size: int = MAX_FRAME) -> bytes:
    """Blocking read of one frame payload. Callers set a socket timeout."""
    length = parse_header(_recv_exactly(sock, HEADER_SIZE), max_size)
    return _recv_exactly(sock, length)


# --------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------


def _reject_constant(value: str) -> Any:
    raise ProtocolError(f"non-finite number: {value}")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ProtocolError(f"duplicate key: {key!r}")
        out[key] = value
    return out


def _loads(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("payload is not valid UTF-8") from None
    try:
        data = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"invalid JSON: {e.msg}") from None
    except RecursionError:
        raise ProtocolError("JSON nested too deeply") from None
    if not isinstance(data, dict):
        raise ProtocolError("payload must be a JSON object")
    return data


def _dumps(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _check_version(data: dict[str, Any]) -> None:
    v = data["v"]
    if isinstance(v, bool) or v != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {v!r}")


def _check_str(name: str, value: object, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be a string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ProtocolError(f"{name} contains lone surrogates") from None
    if size > max_bytes:
        raise ProtocolError(f"{name} too large: {size} > {max_bytes} bytes")
    return value


def _check_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProtocolError("timeout must be a number")
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT:
        raise ProtocolError(f"timeout out of range: {value!r}")
    return float(value)


def _check_exit_code(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError("exit_code must be an integer")
    lo, hi = _EXIT_CODE_RANGE
    if not lo <= value <= hi:
        raise ProtocolError(f"exit_code out of range: {value}")
    return value


def encode_request(code: str, timeout: float) -> bytes:
    """Build a complete request frame (header included)."""
    req = Request(_check_str("code", code, MAX_CODE_BYTES), _check_timeout(timeout))
    return frame(_dumps({"v": PROTOCOL_VERSION, "code": req.code, "timeout": req.timeout, "files": None}))


def decode_request(payload: bytes) -> Request:
    """Validate a request payload (header already stripped)."""
    data = _loads(payload)
    keys = set(data)
    if not _REQUEST_REQUIRED <= keys or not keys <= _REQUEST_KEYS:
        raise ProtocolError(f"bad request keys: {sorted(keys)}")
    _check_version(data)
    if data.get("files") is not None:
        raise ProtocolError("files is not supported in protocol v1")
    return Request(_check_str("code", data["code"], MAX_CODE_BYTES), _check_timeout(data["timeout"]))


def encode_response(stdout: str, stderr: str, exit_code: int) -> bytes:
    """Build a complete response frame (header included). The caller truncates
    stdout and stderr to MAX_OUTPUT_BYTES first."""
    resp = Response(
        _check_str("stdout", stdout, MAX_OUTPUT_BYTES),
        _check_str("stderr", stderr, MAX_OUTPUT_BYTES),
        _check_exit_code(exit_code),
    )
    return frame(
        _dumps(
            {
                "v": PROTOCOL_VERSION,
                "stdout": resp.stdout,
                "stderr": resp.stderr,
                "exit_code": resp.exit_code,
            }
        )
    )


def decode_response(payload: bytes) -> Response:
    """Validate a response payload (header already stripped). Untrusted input."""
    data = _loads(payload)
    if set(data) != _RESPONSE_KEYS:
        raise ProtocolError(f"bad response keys: {sorted(data)}")
    _check_version(data)
    return Response(
        _check_str("stdout", data["stdout"], MAX_OUTPUT_BYTES),
        _check_str("stderr", data["stderr"], MAX_OUTPUT_BYTES),
        _check_exit_code(data["exit_code"]),
    )
