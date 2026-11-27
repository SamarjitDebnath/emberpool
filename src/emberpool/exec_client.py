"""Host side of the vsock exec channel.

Firecracker exposes the guest's vsock device as a Unix socket on the host. To
reach a guest port, the host connects to that socket, sends "CONNECT <port>\\n"
and gets "OK <host port>\\n" back once the guest has accepted. After that the
stream carries length-prefixed frames (emberpool._protocol): one request out,
one response back.

Everything read from the socket is untrusted guest data (docs/40-rules.md rule
1): the handshake line is length-limited and matched exactly, the frame length
is checked before reading, and the reply is decoded strictly. Every wait is
bounded (rule 13) and the connection is closed on every path (rule 12).

Readiness: a guest agent is ready when a CONNECT to its port succeeds.
`wait_ready` probes for that by connecting and closing without sending a
frame; the engine uses it to know when to snapshot the template.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from emberpool._protocol import ProtocolError, decode_response, encode_request, read_frame
from emberpool._types import VSOCK_PORT, ExecError, ExecResult

__all__ = ["VsockExecClient", "wait_ready", "REPLY_MARGIN"]

# Extra time on top of the run's own timeout for the guest to reply.
REPLY_MARGIN = 5.0
_CLOSE_TIMEOUT = 1.0
_HANDSHAKE_MAX = 32
_OK_RE = re.compile(rb"OK [0-9]{1,10}\n")


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), _CLOSE_TIMEOUT)
    except (OSError, TimeoutError):
        pass


async def _open_unix(path: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        return await asyncio.open_unix_connection(str(path))
    except FileNotFoundError:
        raise ExecError(f"vsock socket not found: {path}") from None
    except ConnectionRefusedError:
        raise ExecError(f"vsock socket refused the connection: {path}") from None
    except OSError as e:
        raise ExecError(f"cannot connect to vsock socket {path}: {e.strerror or e}") from None


async def _handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> None:
    try:
        writer.write(b"CONNECT %d\n" % port)
        await writer.drain()
        line = bytearray()
        while not line.endswith(b"\n"):
            if len(line) >= _HANDSHAKE_MAX:
                raise ExecError("vsock handshake reply too long")
            byte = await reader.read(1)
            if not byte:
                raise ExecError(f"connection refused: nothing listening on guest vsock port {port}")
            line += byte
    except (ConnectionError, OSError) as e:
        raise ExecError(f"vsock handshake failed: {e}") from None
    if _OK_RE.fullmatch(line) is None:
        raise ExecError(f"unexpected vsock handshake reply: {bytes(line[:_HANDSHAKE_MAX])!r}")


class VsockExecClient:
    """ExecClient over a Firecracker vsock Unix socket."""

    def __init__(self, *, port: int = VSOCK_PORT, margin: float = REPLY_MARGIN) -> None:
        self.port = port
        self.margin = margin

    async def _connect(self, vsock_path: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open the Unix socket. Tests override this to use a socketpair."""
        return await _open_unix(vsock_path)

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        """Send `code` to the guest agent and return its (untrusted) reply.

        Raises ValueError for bad `code` or `timeout`, ExecError if the channel
        fails, and TimeoutError if no reply arrives within timeout + margin.
        The caller enforces the wall-clock limit by killing the VM."""
        request = encode_request(code, timeout)  # validates code and timeout
        async with asyncio.timeout(timeout + self.margin):
            reader, writer = await self._connect(vsock_path)
            try:
                await _handshake(reader, writer, self.port)
                try:
                    writer.write(request)
                    await writer.drain()
                    payload = await read_frame(reader)
                except ProtocolError as e:
                    raise ExecError(f"bad reply from guest agent: {e}") from None
                except (ConnectionError, OSError) as e:
                    raise ExecError(f"vsock connection failed: {e}") from None
            finally:
                await _close(writer)
        try:
            resp = decode_response(payload)
        except ProtocolError as e:
            raise ExecError(f"bad reply from guest agent: {e}") from None
        return ExecResult(resp.stdout, resp.stderr, resp.exit_code)

    async def probe(self, vsock_path: Path) -> None:
        """Connect to the agent's port and close again. Raises ExecError if the
        agent is not accepting connections."""
        reader, writer = await self._connect(vsock_path)
        try:
            await _handshake(reader, writer, self.port)
        finally:
            await _close(writer)


async def wait_ready(
    vsock_path: Path,
    timeout: float,
    *,
    interval: float = 0.02,
    client: VsockExecClient | None = None,
) -> None:
    """Wait until the guest agent accepts a vsock connection.

    Polls every `interval` seconds; raises TimeoutError after `timeout`. Use it
    on the template VM before pausing it for the snapshot."""
    c = client or VsockExecClient()
    last: ExecError | None = None
    try:
        async with asyncio.timeout(timeout):
            while True:
                try:
                    await c.probe(vsock_path)
                    return
                except ExecError as e:
                    last = e
                await asyncio.sleep(interval)
    except TimeoutError:
        raise TimeoutError(f"guest agent not ready after {timeout}s: {last}") from None
