"""Unit tests for emberpool.trace, driven by canned nflog datagrams."""

from __future__ import annotations

import asyncio
import json
import socket
import struct
from pathlib import Path

import pytest

from emberpool._types import ConnEvent, DnsEvent, IsolationError, NetHandle, Trace
from emberpool.trace import (
    LOG_PREFIX_ALLOWED,
    LOG_PREFIX_DROPPED,
    NFLOG_GROUP,
    LogRecord,
    NflogReader,
    TraceWriter,
    build_trace,
    nft_log_statement,
    parse_ip_packet,
    parse_nflog,
    verdict_from_prefix,
    write_trace,
)
from tests.fakes import FakeNetPolicy

# --------------------------------------------------------------------------
# Canned datagram builders (mirror the kernel's nfnetlink_log layout)
# --------------------------------------------------------------------------


def nlattr(kind: int, value: bytes) -> bytes:
    raw = struct.pack("=HH", 4 + len(value), kind) + value
    return raw + b"\x00" * (-len(raw) % 4)


def nflog_packet(
    *,
    prefix: str | None = LOG_PREFIX_DROPPED,
    indev: int | None = 5,
    payload: bytes = b"",
    seq: int | None = None,
    ts: tuple[int, int] | None = None,
) -> bytes:
    attrs = nlattr(1, struct.pack(">HBB", 0x0800, 2, 0))  # NFULA_PACKET_HDR
    if prefix is not None:
        attrs += nlattr(10, prefix.encode() + b"\x00")
    if indev is not None:
        attrs += nlattr(4, struct.pack(">I", indev))
    if ts is not None:
        attrs += nlattr(3, struct.pack(">QQ", *ts))
    if seq is not None:
        attrs += nlattr(12, struct.pack(">I", seq))
    attrs += nlattr(9, payload)
    body = struct.pack("=BBH", 2, 0, socket.htons(NFLOG_GROUP)) + attrs
    return struct.pack("=IHHII", 16 + len(body), 0x0400, 0, 0, 0) + body


def nl_error(code: int) -> bytes:
    body = struct.pack("=i", code) + b"\x00" * 16
    return struct.pack("=IHHII", 16 + len(body), 2, 0, 0, 0) + body


def ipv4(dst: str, proto: int = 6, dport: int = 443, *, frag: int = 0, ihl: int = 5) -> bytes:
    hdr = bytearray(ihl * 4)
    hdr[0] = 0x40 | ihl
    struct.pack_into(">H", hdr, 6, frag)
    hdr[9] = proto
    hdr[12:16] = socket.inet_aton("172.16.0.2")
    hdr[16:20] = socket.inet_aton(dst)
    return bytes(hdr) + struct.pack(">HH", 40000, dport) + b"\x00" * 16


def ipv6(dst: str, proto: int = 17, dport: int = 53) -> bytes:
    hdr = bytearray(40)
    hdr[0] = 0x60
    hdr[6] = proto
    hdr[24:40] = socket.inet_pton(socket.AF_INET6, dst)
    return bytes(hdr) + struct.pack(">HH", 40000, dport)


# --------------------------------------------------------------------------
# Format constants
# --------------------------------------------------------------------------


def test_log_statement_uses_constants() -> None:
    assert nft_log_statement("allowed") == [
        "log", "prefix", f'"{LOG_PREFIX_ALLOWED}"', "group", str(NFLOG_GROUP), "snaplen", "128",
    ]
    assert nft_log_statement("dropped", 3)[2] == f'"{LOG_PREFIX_DROPPED}"'
    with pytest.raises(ValueError):
        nft_log_statement("accept")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        nft_log_statement("allowed", 70000)


def test_verdict_from_prefix() -> None:
    assert verdict_from_prefix(LOG_PREFIX_ALLOWED) == "allowed"
    assert verdict_from_prefix(LOG_PREFIX_DROPPED) == "dropped"
    assert verdict_from_prefix("ep-allow ") is None
    assert verdict_from_prefix("") is None


# --------------------------------------------------------------------------
# Netlink parsing
# --------------------------------------------------------------------------


def test_parse_single_packet() -> None:
    payload = ipv4("93.184.216.34")
    recs, errs = parse_nflog(nflog_packet(payload=payload, seq=7, ts=(1700000000, 250000)))
    assert errs == []
    assert recs == [LogRecord(LOG_PREFIX_DROPPED, 5, 1700000000.25, 7, payload)]


def test_parse_batch_and_errors() -> None:
    data = nflog_packet(indev=1) + nl_error(0) + nflog_packet(indev=2, prefix=LOG_PREFIX_ALLOWED)
    recs, errs = parse_nflog(data)
    assert [r.indev for r in recs] == [1, 2]
    assert [r.prefix for r in recs] == [LOG_PREFIX_DROPPED, LOG_PREFIX_ALLOWED]
    assert errs == [0]


def test_parse_missing_optional_attrs() -> None:
    (rec,), _ = parse_nflog(nflog_packet(prefix=None, indev=None))
    assert rec.prefix == "" and rec.indev is None and rec.timestamp is None and rec.seq is None


@pytest.mark.parametrize(
    "data",
    [
        struct.pack("=IHHII", 100, 0x0400, 0, 0, 0),  # length past end
        struct.pack("=IHHII", 8, 0x0400, 0, 0, 0),  # length below header
        struct.pack("=IHHII", 18, 0x0400, 0, 0, 0) + b"\x00\x00",  # short nfgenmsg
        struct.pack("=IHHII", 18, 2, 0, 0, 0) + b"\x00\x00",  # short error
        # attribute claiming more than the message holds
        struct.pack("=IHHII", 24, 0x0400, 0, 0, 0) + b"\x02\x00\x00\x00" + struct.pack("=HH", 40, 9),
        # attribute with a length below its own header
        struct.pack("=IHHII", 24, 0x0400, 0, 0, 0) + b"\x02\x00\x00\x00" + struct.pack("=HH", 2, 9),
    ],
)
def test_parse_rejects_malformed(data: bytes) -> None:
    with pytest.raises(ValueError):
        parse_nflog(data)


def test_parse_truncates_oversized_prefix_and_payload() -> None:
    (rec,), _ = parse_nflog(nflog_packet(prefix="x" * 300, payload=b"\x45" * 1000))
    assert len(rec.prefix) == 128
    assert len(rec.payload) == 128


# --------------------------------------------------------------------------
# IP header parsing (guest-controlled bytes)
# --------------------------------------------------------------------------


def test_ipv4_tcp_udp_icmp() -> None:
    p = parse_ip_packet(ipv4("1.2.3.4", 6, 443))
    assert (p.dst_ip, p.protocol, p.dst_port) == ("1.2.3.4", "tcp", 443)
    p = parse_ip_packet(ipv4("1.2.3.4", 17, 53))
    assert (p.protocol, p.dst_port) == ("udp", 53)
    p = parse_ip_packet(ipv4("1.2.3.4", 1, 0))
    assert (p.protocol, p.dst_port) == ("icmp", 0)
    p = parse_ip_packet(ipv4("1.2.3.4", 47))
    assert (p.protocol, p.dst_port) == ("ip47", 0)


def test_ipv4_options_and_fragments() -> None:
    p = parse_ip_packet(ipv4("1.2.3.4", 6, 8080, ihl=7))
    assert p.dst_port == 8080
    p = parse_ip_packet(ipv4("1.2.3.4", 6, 8080, frag=10))
    assert p.dst_port == 0  # non-first fragment: bytes there are not a TCP header


def test_ipv6() -> None:
    p = parse_ip_packet(ipv6("2001:db8::1", 17, 53))
    assert (p.dst_ip, p.protocol, p.dst_port) == ("2001:db8::1", "udp", 53)


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x45" * 10, b"\x44" + b"\x00" * 30, b"\x4f" + b"\x00" * 30, b"\x60" * 20, b"\x20" * 60],
)
def test_ip_rejects_garbage(payload: bytes) -> None:
    assert parse_ip_packet(payload) is None


def test_ip_header_without_l4_gives_port_zero() -> None:
    p = parse_ip_packet(ipv4("1.2.3.4", 6, 443)[:20])
    assert p is not None and p.dst_port == 0


# --------------------------------------------------------------------------
# Name attribution and ordering (pure)
# --------------------------------------------------------------------------


def _dns(t: float, vm: str, name: str, *ips: str) -> DnsEvent:
    return DnsEvent(t, vm, name, tuple(ips) if ips else None)


def _conn(t: float, vm: str, ip: str, verdict: str = "allowed", name: str | None = None) -> ConnEvent:
    return ConnEvent(t, vm, ip, 443, "tcp", name, verdict)  # type: ignore[arg-type]


def test_build_trace_orders_and_attributes() -> None:
    events = [
        (3.0, 1, _conn(3.0, "vm1", "1.1.1.1")),
        (1.0, 2, _dns(1.0, "vm1", "pypi.org", "1.1.1.1", "1.1.1.2")),
        (2.0, 3, _conn(2.0, "vm1", "9.9.9.9", "dropped")),
    ]
    trace = build_trace(events)
    assert [type(e).__name__ for e in trace] == ["DnsEvent", "ConnEvent", "ConnEvent"]
    assert trace.events[1].name is None  # never answered
    assert trace.events[2].name == "pypi.org"


def test_no_attribution_before_answer() -> None:
    trace = build_trace([(1.0, 1, _conn(1.0, "vm1", "1.1.1.1")), (2.0, 2, _dns(2.0, "vm1", "pypi.org", "1.1.1.1"))])
    assert trace.events[0].name is None


def test_latest_answer_wins_and_ties_keep_arrival() -> None:
    trace = build_trace(
        [
            (1.0, 1, _dns(1.0, "vm1", "a.example", "1.1.1.1")),
            (2.0, 2, _dns(2.0, "vm1", "b.example", "1.1.1.1")),
            (2.0, 3, _conn(2.0, "vm1", "1.1.1.1")),
        ]
    )
    assert trace.events[2].name == "b.example"


def test_nxdomain_and_odd_names_do_not_attribute() -> None:
    trace = build_trace(
        [
            (1.0, 1, _dns(1.0, "vm1", "nope.example")),
            (1.5, 2, _dns(1.5, "vm1", "x\\x00y", "1.1.1.1")),  # escaped, not a domain
            (2.0, 3, _conn(2.0, "vm1", "1.1.1.1")),
        ]
    )
    assert trace.events[2].name is None


def test_existing_conn_name_is_kept() -> None:
    trace = build_trace(
        [(1.0, 1, _dns(1.0, "vm1", "a.example", "1.1.1.1")), (2.0, 2, _conn(2.0, "vm1", "1.1.1.1", name="c.example"))]
    )
    assert trace.events[1].name == "c.example"


# --------------------------------------------------------------------------
# TraceWriter with a fake log source
# --------------------------------------------------------------------------


class FakeSource:
    """LogSource in memory. push() queues records and makes fileno() readable."""

    def __init__(self, ifindexes: dict[str, int] | None = None, *, fail_open: bool = False) -> None:
        self.ifindexes = ifindexes or {"ep-h1": 11, "ep-h2": 12}
        self.fail_open = fail_open
        self.lost = 0
        self.pending: list[LogRecord] = []
        self.closed = 0
        self._r, self._w = socket.socketpair()
        self._r.setblocking(False)

    def open(self) -> None:
        if self.fail_open:
            raise IsolationError("fake: bind refused")

    def fileno(self) -> int:
        return self._r.fileno()

    def push(self, *recs: LogRecord) -> None:
        self.pending.extend(recs)
        self._w.send(b"x")

    def drain(self) -> list[LogRecord]:
        try:
            while self._r.recv(4096):
                pass
        except BlockingIOError:
            pass
        out, self.pending = self.pending, []
        return out

    def ifindex(self, name: str) -> int:
        if name not in self.ifindexes:
            raise IsolationError(f"fake: no interface {name}")
        return self.ifindexes[name]

    def close(self) -> None:
        self.closed += 1
        if self.closed == 1:
            self._r.close()
            self._w.close()


def rec(indev: int, dst: str, *, prefix: str = LOG_PREFIX_ALLOWED, t: float | None = None, port: int = 443) -> LogRecord:
    return LogRecord(prefix, indev, t, None, ipv4(dst, 6, port))


def handle(vm: str, n: int) -> NetHandle:
    return NetHandle(vm, n, f"ep-test-{vm}", f"ep-h{n}")


async def test_writer_merges_and_separates_vms(tmp_path: Path) -> None:
    net = FakeNetPolicy()
    src = FakeSource()
    async with TraceWriter(net.events(), src, settle=0.01) as tw:
        await tw.register(handle("vm1", 1))
        await tw.register(handle("vm2", 2))
        net.emit(_dns(10.0, "vm1", "pypi.org", "151.101.0.223"))
        net.emit(_dns(10.5, "vm2", "nope.example"))
        await asyncio.sleep(0)
        src.push(
            rec(11, "151.101.0.223", t=11.0),
            rec(12, "151.101.0.223", t=11.5, prefix=LOG_PREFIX_DROPPED),
            rec(11, "8.8.8.8", t=10.2, prefix=LOG_PREFIX_DROPPED, port=53),
            rec(99, "1.1.1.1", t=12.0),  # not a registered veth
            rec(11, "1.1.1.1", t=12.0, prefix="other-rule"),  # not our prefix
        )
        r1 = await tw.finish("vm1", tmp_path / "vm1.json")
        r2 = await tw.finish("vm2")
        assert tw.discarded == 2

    assert r1.complete and r2.complete
    assert [e.to_dict()["type"] for e in r1.trace] == ["dns", "conn", "conn"]
    assert r1.trace.events[1] == ConnEvent(10.2, "vm1", "8.8.8.8", 53, "tcp", None, "dropped")
    assert r1.trace.events[2] == ConnEvent(11.0, "vm1", "151.101.0.223", 443, "tcp", "pypi.org", "allowed")
    # vm2 never got an answer for that IP, so no name leaks across VMs.
    assert r2.trace.events[1] == ConnEvent(11.5, "vm2", "151.101.0.223", 443, "tcp", None, "dropped")
    assert all(e.vm_id == "vm2" for e in r2.trace)
    assert Trace.from_json((tmp_path / "vm1.json").read_text()) == r1.trace
    assert r2.path is None
    assert src.closed >= 1


async def test_writer_uses_receive_time_without_kernel_timestamp() -> None:
    src = FakeSource()
    async with TraceWriter(None, src, settle=0) as tw:
        await tw.register(handle("vm1", 1))
        src.push(rec(11, "1.1.1.1"))
        report = await tw.finish("vm1")
    (ev,) = report.trace.events
    assert ev.time > 1_000_000_000


async def test_events_after_finish_and_before_register_are_discarded() -> None:
    net = FakeNetPolicy()
    src = FakeSource()
    async with TraceWriter(net.events(), src, settle=0) as tw:
        net.emit(_dns(1.0, "vm1", "a.example", "1.1.1.1"))
        await asyncio.sleep(0)
        await tw.register(handle("vm1", 1))
        report = await tw.finish("vm1")
        net.emit(_dns(2.0, "vm1", "a.example", "1.1.1.1"))
        src.push(rec(11, "1.1.1.1"))
        await asyncio.sleep(0.01)
        assert tw.discarded == 3
    assert len(report.trace) == 0


async def test_register_rejects_duplicates_and_missing_veth() -> None:
    src = FakeSource({"ep-h1": 11, "ep-h2": 11})
    async with TraceWriter(None, src) as tw:
        await tw.register(handle("vm1", 1))
        with pytest.raises(ValueError):
            await tw.register(handle("vm1", 1))
        with pytest.raises(IsolationError):  # same ifindex twice
            await tw.register(handle("vm2", 2))
        with pytest.raises(IsolationError):
            await tw.register(handle("vm3", 3))  # ep-h3 does not exist
        with pytest.raises(KeyError):
            await tw.finish("vm2")


# --- fail-closed and incompleteness -------------------------------------


async def test_start_fails_closed_when_log_cannot_be_bound() -> None:
    src = FakeSource(fail_open=True)
    tw = TraceWriter(None, src)
    with pytest.raises(IsolationError):
        await tw.start()
    assert src.closed == 1


async def test_start_wraps_unexpected_errors_as_isolation_error() -> None:
    class Broken(FakeSource):
        def fileno(self) -> int:
            raise OSError("boom")

    src = Broken()
    with pytest.raises(IsolationError):
        await TraceWriter(None, src).start()
    assert src.closed == 1


async def test_lost_events_mark_traces_incomplete() -> None:
    src = FakeSource()
    async with TraceWriter(None, src, settle=0) as tw:
        await tw.register(handle("vm1", 1))
        await tw.register(handle("vm2", 2))
        src.lost = 1
        src.push(rec(11, "1.1.1.1"))
        r1 = await tw.finish("vm1")
        r2 = await tw.finish("vm2")
    assert not r1.complete and not r2.complete
    assert len(r1.trace) == 1


async def test_unparsable_payload_marks_incomplete() -> None:
    src = FakeSource()
    async with TraceWriter(None, src, settle=0) as tw:
        await tw.register(handle("vm1", 1))
        src.push(LogRecord(LOG_PREFIX_DROPPED, 11, None, None, b"\x99garbage"))
        report = await tw.finish("vm1")
    assert not report.complete and len(report.trace) == 0


async def test_event_cap_marks_incomplete() -> None:
    src = FakeSource()
    async with TraceWriter(None, src, settle=0, max_events=3) as tw:
        await tw.register(handle("vm1", 1))
        src.push(*(rec(11, "1.1.1.1", t=float(i)) for i in range(10)))
        report = await tw.finish("vm1")
    assert not report.complete and len(report.trace) == 3


async def test_failed_event_stream_marks_incomplete() -> None:
    async def broken():
        yield _dns(1.0, "vm1", "a.example", "1.1.1.1")
        raise RuntimeError("resolver died")

    src = FakeSource()
    async with TraceWriter(broken(), src, settle=0) as tw:
        await tw.register(handle("vm1", 1))
        await asyncio.sleep(0.01)
        report = await tw.finish("vm1")
        await tw.register(handle("vm2", 2))
        report2 = await tw.finish("vm2")
    assert not report.complete
    assert not report2.complete  # stays incomplete for later VMs too


async def test_source_read_error_marks_incomplete() -> None:
    class Failing(FakeSource):
        def drain(self) -> list[LogRecord]:
            super().drain()
            raise OSError("recv failed")

    src = Failing()
    async with TraceWriter(None, src, settle=0) as tw:
        await tw.register(handle("vm1", 1))
        src.push(rec(11, "1.1.1.1"))
        report = await tw.finish("vm1")
    assert not report.complete


# --- teardown ----------------------------------------------------------


async def test_close_is_idempotent_and_releases_everything() -> None:
    net = FakeNetPolicy()
    src = FakeSource()
    events = net.events()
    tw = TraceWriter(events, src)
    await tw.start()
    task = tw._net_task
    await tw.close()
    await tw.close()
    assert task is not None and task.done()
    assert src.closed >= 1
    with pytest.raises(StopAsyncIteration):
        await events.__anext__()  # aclose()d


async def test_teardown_after_error_inside_context() -> None:
    src = FakeSource()
    with pytest.raises(RuntimeError):
        async with TraceWriter(FakeNetPolicy().events(), src) as tw:
            await tw.register(handle("vm1", 1))
            raise RuntimeError("run failed")
    assert src.closed >= 1


async def test_close_survives_cancellation() -> None:
    src = FakeSource()
    tw = TraceWriter(FakeNetPolicy().events(), src)
    await tw.start()

    async def closer() -> None:
        await tw.close()

    t = asyncio.create_task(closer())
    await asyncio.sleep(0)
    t.cancel()
    try:
        await t
    except asyncio.CancelledError:
        pass
    await tw.close()  # second call still safe
    assert src.closed >= 1


async def test_forget_drops_vm_without_trace() -> None:
    src = FakeSource()
    async with TraceWriter(None, src) as tw:
        await tw.register(handle("vm1", 1))
        tw.forget("vm1")
        tw.forget("vm1")
        await tw.register(handle("vm1", 1))  # ifindex freed for reuse
        await tw.finish("vm1")


async def test_finish_writes_nothing_and_unregisters_on_write_error(tmp_path: Path) -> None:
    src = FakeSource()
    async with TraceWriter(None, src, settle=0) as tw:
        await tw.register(handle("vm1", 1))
        with pytest.raises(OSError):
            await tw.finish("vm1", tmp_path / "missing-dir" / "trace.json")
        with pytest.raises(KeyError):
            await tw.finish("vm1")


# --------------------------------------------------------------------------
# write_trace
# --------------------------------------------------------------------------


def test_write_trace_atomic_and_private(tmp_path: Path) -> None:
    trace = Trace(events=(_conn(1.0, "vm1", "1.1.1.1"),))
    path = tmp_path / "trace.json"
    write_trace(trace, path)
    assert json.loads(path.read_text())["schema_version"] == 1
    assert path.stat().st_mode & 0o777 == 0o600
    write_trace(Trace(), path)  # overwrite
    assert Trace.from_json(path.read_text()) == Trace()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["trace.json"]


# --------------------------------------------------------------------------
# NflogReader argument checks (no socket needed)
# --------------------------------------------------------------------------


def test_reader_validates_arguments() -> None:
    with pytest.raises(ValueError):
        NflogReader(-1)
    with pytest.raises(ValueError):
        NflogReader(netns="bad name")
    r = NflogReader()
    assert r.drain() == []
    r.close()
    r.close()
    with pytest.raises(RuntimeError):
        r.fileno()
    with pytest.raises(ValueError):
        r.ifindex("eth0; rm")


def test_reader_open_fails_closed_for_missing_netns(test_prefix: str) -> None:
    reader = NflogReader(netns=f"{test_prefix}-missing")
    with pytest.raises(IsolationError):
        reader.open()
    with pytest.raises(RuntimeError):
        reader.fileno()  # nothing left open
