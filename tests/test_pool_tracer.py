"""SandboxPool wired to the real TraceWriter, on fakes and an in-memory log
source. No root needed.

Checks the glue: register before restore, finish after kill and before net
teardown, forget on every other path, and incomplete traces fail closed.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from emberpool._types import (
    MAX_UPLINKS,
    ConnEvent,
    DnsEvent,
    ExecResult,
    IsolationError,
    NetHandle,
)
from emberpool.pool import SandboxPool
from emberpool.trace import LOG_PREFIX_ALLOWED, LogRecord, TraceWriter
from tests.fakes import FakeEngine, FakeExecClient, FakeNetPolicy

IP = "151.101.0.223"


class MemSource:
    """LogSource in memory. FakeNetPolicy names uplink N "ep-hN"; its ifindex is 100+N."""

    def __init__(self) -> None:
        self.lost = 0
        self.pending: list[LogRecord] = []
        self.closed = False
        self._r, self._w = socket.socketpair()
        self._r.setblocking(False)

    def fileno(self) -> int:
        return self._r.fileno()

    def ifindex(self, name: str) -> int:
        n = int(name.removeprefix("ep-h"))
        assert 0 <= n < MAX_UPLINKS
        return 100 + n

    def push(self, rec: LogRecord) -> None:
        self.pending.append(rec)
        self._w.send(b"x")

    def drain(self) -> list[LogRecord]:
        try:
            while self._r.recv(4096):
                pass
        except BlockingIOError:
            pass
        out, self.pending = self.pending, []
        return out

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._r.close()
            self._w.close()


def tcp_syn(dst: str, port: int) -> bytes:
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
        socket.inet_aton("172.16.0.2"), socket.inet_aton(dst),
    )
    tcp = struct.pack("!HHIIBBHHH", 40000, port, 0, 0, 0x50, 0x02, 1024, 0, 0)
    return ip + tcp


@dataclass
class Order:
    """Shared call log across fakes and tracer, to check ordering."""

    log: list[tuple[str, str]]


class OrderedEngine(FakeEngine):
    def __init__(self, order: Order, **kw: object) -> None:
        super().__init__(**kw)  # type: ignore[arg-type]
        self.order = order

    async def restore(self, template, vm_id, netns):  # type: ignore[no-untyped-def]
        self.order.log.append(("restore", vm_id))
        return await super().restore(template, vm_id, netns)

    async def kill(self, vm):  # type: ignore[no-untyped-def]
        self.order.log.append(("kill", vm.vm_id))
        await super().kill(vm)


class OrderedNet(FakeNetPolicy):
    order: Order | None = None

    async def teardown(self, handle: NetHandle) -> None:
        assert self.order is not None
        self.order.log.append(("teardown", handle.vm_id))
        await super().teardown(handle)


class OrderedTracer(TraceWriter):
    order: Order | None = None
    fail_register = False
    fail_finish = False

    async def register(self, net: NetHandle) -> None:
        assert self.order is not None
        self.order.log.append(("register", net.vm_id))
        if self.fail_register:
            raise IsolationError("fake: register failed")
        await super().register(net)

    async def finish(self, vm_id, path=None):  # type: ignore[no-untyped-def]
        assert self.order is not None
        self.order.log.append(("finish", vm_id))
        if self.fail_finish:
            self.forget(vm_id)
            raise IsolationError("fake: finish failed")
        return await super().finish(vm_id, path)

    def forget(self, vm_id: str) -> None:
        assert self.order is not None
        self.order.log.append(("forget", vm_id))
        super().forget(vm_id)


@dataclass
class NetExec(FakeExecClient):
    """During a run, the host 'sees' one DNS answer and one allowed SYN."""

    net: FakeNetPolicy | None = None
    src: MemSource | None = None

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        assert self.net is not None and self.src is not None
        vm_id = vsock_path.parent.name
        index = self.net.handles[vm_id].index
        self.net.emit(DnsEvent(1.0, vm_id, "pypi.org", (IP,)))
        self.src.push(LogRecord(LOG_PREFIX_ALLOWED, 100 + index, 2.0, None, tcp_syn(IP, 443)))
        return await super().run(vsock_path, code, timeout)


@pytest.fixture
async def rig(tmp_path: Path):
    order = Order([])
    eng = OrderedEngine(order)
    net = OrderedNet(prefix="ep-fake")
    net.order = order
    src = MemSource()
    tracer = OrderedTracer(net.events(), src, settle=0)
    tracer.order = order
    ex = NetExec(net=net, src=src)
    await tracer.start()
    try:
        yield order, eng, net, src, tracer, ex, tmp_path
    finally:
        await tracer.close()
        assert src.closed


def make(rig, size: int = 1) -> SandboxPool:
    _order, eng, net, _src, tracer, ex, tmp = rig
    p = SandboxPool(size, "allow:pypi.org", _engine=eng, _netpolicy=net, _exec=ex, _workdir=tmp, _tracer=tracer)
    p._retry_min = 0.01
    p._retry_max = 0.05
    return p


def steps_for(order: Order, vm_id: str) -> list[str]:
    return [what for what, v in order.log if v == vm_id]


def assert_clean(rig) -> None:
    _order, eng, net, _src, tracer, _ex, _tmp = rig
    assert eng.leaks() == []
    assert net.leaks() == []
    assert tracer._vms == {} and tracer._by_ifindex == {}


async def test_run_trace_comes_from_tracer_in_order(rig):
    order, _eng, _net, _src, _tracer, ex, _tmp = rig
    async with make(rig) as p:
        r = await p.run("x", 5)
    assert r.exit_code == 0 and not r.timed_out
    kinds = [type(e) for e in r.trace]
    assert kinds == [DnsEvent, ConnEvent]
    conn = r.trace.events[1]
    assert isinstance(conn, ConnEvent)
    assert (conn.dst_ip, conn.dst_port, conn.verdict, conn.name) == (IP, 443, "allowed", "pypi.org")
    used = ex.calls[0][0].parent.name
    assert steps_for(order, used) == ["register", "restore", "kill", "finish", "forget", "teardown"]
    assert_clean(rig)


async def test_pool_does_not_consume_net_events_itself(rig):
    async with make(rig) as p:
        assert p._dispatcher is None
        await p.run("x", 5)


async def test_incomplete_trace_fails_closed(rig):
    _order, _eng, _net, src, _tracer, _ex, _tmp = rig
    async with make(rig) as p:
        src.lost = 1  # the log overran: every open trace is now incomplete
        with pytest.raises(IsolationError, match="incomplete"):
            await p.run("x", 5)
    assert_clean(rig)


async def test_failed_finish_fails_closed(rig):
    _order, _eng, _net, _src, tracer, _ex, _tmp = rig
    async with make(rig) as p:
        tracer.fail_finish = True
        with pytest.raises(IsolationError, match="no trace"):
            await p.run("x", 5)
    assert_clean(rig)


async def test_failed_kill_skips_finish_and_fails_closed(rig):
    order, eng, _net, _src, _tracer, ex, _tmp = rig

    async def bad_kill(vm):  # type: ignore[no-untyped-def]
        raise OSError("kill failed")

    async with make(rig) as p:
        eng.kill = bad_kill  # type: ignore[method-assign]
        with pytest.raises(IsolationError, match="no trace"):
            await p.run("x", 5)
        used = ex.calls[0][0].parent.name
        assert "finish" not in steps_for(order, used)
        assert steps_for(order, used)[-2:] == ["forget", "teardown"]
    assert_clean(rig)


async def test_failed_register_refuses_to_start_and_cleans_up(rig):
    order, eng, _net, _src, tracer, _ex, _tmp = rig
    tracer.fail_register = True
    with pytest.raises(IsolationError, match="register failed"):
        async with make(rig):
            pass
    # No VM was restored for an unregistered network.
    assert not any(what == "restore" for what, _ in order.log)
    assert eng.vms == {}
    assert_clean(rig)


async def test_failed_restore_forgets_registration(rig):
    order, eng, _net, _src, _tracer, _ex, _tmp = rig
    eng.fail_restore = True
    with pytest.raises(IsolationError):
        async with make(rig):
            pass
    vm_ids = {v for what, v in order.log if what == "register"}
    assert vm_ids
    for vm_id in vm_ids:
        assert steps_for(order, vm_id) == ["register", "restore", "forget", "teardown"]
    assert_clean(rig)


async def test_vmgenid_probe_is_traced_and_released(rig):
    order, _eng, _net, _src, _tracer, _ex, _tmp = rig
    async with make(rig):
        pass
    finished = [v for what, v in order.log if what == "finish"]
    assert len(finished) >= 1  # the probe, then the idle VM at shutdown
    assert_clean(rig)
