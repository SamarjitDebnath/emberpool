"""Host exec client tests. A socketpair stands in for the Firecracker vsock
Unix socket; a thread on the far end plays Firecracker (and the agent)."""

from __future__ import annotations

import asyncio
import importlib.util
import shutil
import socket
import struct
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from emberpool import _protocol as proto
from emberpool._types import ExecError, ExecResult
from emberpool.engine import ExecClient
from emberpool.exec_client import VsockExecClient, wait_ready

AGENT_PATH = Path(__file__).resolve().parent.parent / "src" / "emberpool" / "guest" / "agent.py"
DUMMY = Path("/nonexistent/vm.vsock")

Peer = Callable[[socket.socket], None]


def _load_agent():
    spec = importlib.util.spec_from_file_location("ep_guest_agent_c", AGENT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PairClient(VsockExecClient):
    """Client whose connection is one end of a socketpair; `peer` runs on the
    other end in a thread. Records whether the far end saw the close."""

    def __init__(self, peer: Peer, **kw):
        super().__init__(**kw)
        self.peer = peer
        self.peer_saw_eof = threading.Event()
        self.threads: list[threading.Thread] = []
        self.ends: list[socket.socket] = []

    async def _connect(self, vsock_path):
        mine, theirs = socket.socketpair()
        self.ends.append(theirs)

        def body():
            theirs.settimeout(10)
            try:
                self.peer(theirs)
                theirs.shutdown(socket.SHUT_WR)  # peer done: client sees EOF
                while theirs.recv(65536):  # wait for the client to close
                    pass
                self.peer_saw_eof.set()
            except OSError:
                self.peer_saw_eof.set()
            finally:
                theirs.close()

        t = threading.Thread(target=body, daemon=True)
        t.start()
        self.threads.append(t)
        return await asyncio.open_connection(sock=mine)

    def join(self):
        for t in self.threads:
            t.join(10)
            assert not t.is_alive()


def _read_connect(s: socket.socket) -> bytes:
    line = b""
    while not line.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            break
        line += b
    return line


def firecracker_ok(then: Peer) -> Peer:
    def peer(s):
        assert _read_connect(s) == b"CONNECT 1024\n"
        s.sendall(b"OK 1073741824\n")
        then(s)

    return peer


def reply_with(raw: bytes) -> Peer:
    def then(s):
        proto.recv_frame(s)
        s.sendall(raw)

    return firecracker_ok(then)


async def _run(peer: Peer, code="print(1+1)", timeout=5.0, **kw):
    c = PairClient(peer, **kw)
    try:
        return await c.run(DUMMY, code, timeout)
    finally:
        await asyncio.to_thread(c.join)
        assert c.peer_saw_eof.is_set(), "client did not close the connection"


def test_satisfies_protocol():
    assert isinstance(VsockExecClient(), ExecClient)


async def test_round_trip():
    res = await _run(reply_with(proto.encode_response("2\n", "", 0)))
    assert res == ExecResult("2\n", "", 0)


async def test_sends_request_frame():
    seen = []

    def then(s):
        seen.append(proto.decode_request(proto.recv_frame(s)))
        s.sendall(proto.encode_response("", "", 0))

    await _run(firecracker_ok(then), code="x = 1", timeout=7)
    assert seen == [proto.Request("x = 1", 7.0)]


async def test_end_to_end_with_agent():
    import sys

    agent = _load_agent()

    def then(s):
        agent.handle_connection(s, lambda code, t: agent.run_code(code, t, python=sys.executable))

    res = await _run(firecracker_ok(then), code="print(1+1)")
    assert res == ExecResult("2\n", "", 0)


# --------------------------------------------------------------------------
# Fail-closed paths; every one must still close the connection.
# --------------------------------------------------------------------------


async def test_refused_when_nothing_listens():
    # Firecracker closes the stream when no guest listener accepts.
    def peer(s):
        _read_connect(s)

    with pytest.raises(ExecError, match="connection refused"):
        await _run(peer)


@pytest.mark.parametrize("line", [b"NO\n", b"OK\n", b"OK 12x\n", b"ok 1\n", b"OK 1"])
async def test_bad_handshake(line):
    def peer(s):
        _read_connect(s)
        s.sendall(line)
        if not line.endswith(b"\n"):
            s.shutdown(socket.SHUT_WR)

    with pytest.raises(ExecError):
        await _run(peer)


async def test_handshake_too_long():
    def peer(s):
        _read_connect(s)
        s.sendall(b"OK " + b"1" * 100 + b"\n")

    with pytest.raises(ExecError, match="too long"):
        await _run(peer)


async def test_short_read_header():
    with pytest.raises(ExecError, match="short read"):
        await _run(reply_with(b"\x00\x00"))


async def test_short_read_payload():
    with pytest.raises(ExecError, match="short read"):
        await _run(reply_with(struct.pack(">I", 100) + b"{}"))


async def test_agent_closes_without_reply():
    def then(s):
        proto.recv_frame(s)

    with pytest.raises(ExecError, match="short read"):
        await _run(firecracker_ok(then))


async def test_oversized_frame_rejected_before_read():
    with pytest.raises(ExecError, match="too large"):
        await _run(reply_with(struct.pack(">I", proto.MAX_FRAME + 1)))


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b'{"v":2,"stdout":"","stderr":"","exit_code":0}',
        b'{"v":1,"stdout":"","stderr":"","exit_code":0,"extra":1}',
        b'{"v":1,"stdout":"","stderr":"","exit_code":true}',
        b'{"v":1,"stdout":1,"stderr":"","exit_code":0}',
    ],
)
async def test_bad_reply_payload(payload):
    with pytest.raises(ExecError, match="bad reply"):
        await _run(reply_with(proto.frame(payload)))


async def test_timeout_when_no_reply():
    def then(s):
        proto.recv_frame(s)
        s.recv(1)  # block until the client gives up and closes

    with pytest.raises(TimeoutError):
        await _run(firecracker_ok(then), timeout=0.2, margin=0.1)


async def test_bad_arguments_do_not_connect():
    def peer(s):
        raise AssertionError("connected for an invalid request")

    c = PairClient(peer)
    with pytest.raises(ValueError):
        await c.run(DUMMY, "x", 0)
    with pytest.raises(ValueError):
        await c.run(DUMMY, "x" * (proto.MAX_CODE_BYTES + 1), 1)
    assert c.threads == []


async def test_cancellation_closes_connection():
    started = threading.Event()

    def then(s):
        proto.recv_frame(s)
        started.set()
        s.recv(1)

    c = PairClient(firecracker_ok(then))
    task = asyncio.create_task(c.run(DUMMY, "x", 30))
    await asyncio.to_thread(started.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.to_thread(c.join)
    assert c.peer_saw_eof.is_set()


# --------------------------------------------------------------------------
# Real Unix socket paths
# --------------------------------------------------------------------------


@pytest.fixture
def sock_dir(test_prefix):
    d = Path(tempfile.mkdtemp(prefix=f"{test_prefix}-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def test_missing_socket_path(sock_dir):
    with pytest.raises(ExecError, match="not found"):
        await VsockExecClient().run(sock_dir / "missing.vsock", "x", 1)


async def test_refused_socket_path(sock_dir):
    path = sock_dir / "dead.vsock"
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(path))
    s.close()  # file exists, nobody listening
    with pytest.raises(ExecError, match="refused"):
        await VsockExecClient().run(path, "x", 1)


async def test_unix_socket_round_trip_and_wait_ready(sock_dir):
    path = sock_dir / "vm.vsock"
    probes = 0

    async def handle(reader, writer):
        nonlocal probes
        assert await reader.readline() == b"CONNECT 1024\n"
        writer.write(b"OK 5\n")
        await writer.drain()
        try:
            payload = await proto.read_frame(reader)
        except proto.ProtocolError:
            probes += 1  # readiness probe: closed without a frame
        else:
            req = proto.decode_request(payload)
            writer.write(proto.encode_response(f"got {req.code}", "", 0))
            await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(handle, path=str(path))
    try:
        await wait_ready(path, 5)
        res = await VsockExecClient().run(path, "abc", 5)
    finally:
        server.close()
        await server.wait_closed()
    assert res == ExecResult("got abc", "", 0)
    assert probes == 1


async def test_wait_ready_times_out(sock_dir):
    with pytest.raises(TimeoutError, match="not ready"):
        await wait_ready(sock_dir / "never.vsock", 0.2)


async def test_wait_ready_polls_until_listener_appears(sock_dir):
    path = sock_dir / "late.vsock"

    async def handle(reader, writer):
        await reader.readline()
        writer.write(b"OK 5\n")
        await writer.drain()
        writer.close()

    async def start_late():
        await asyncio.sleep(0.2)
        return await asyncio.start_unix_server(handle, path=str(path))

    starter = asyncio.create_task(start_late())
    await wait_ready(path, 5)
    server = await starter
    server.close()
    await server.wait_closed()
