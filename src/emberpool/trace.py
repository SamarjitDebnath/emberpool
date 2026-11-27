"""Host-observed network trace per VM.

TraceWriter merges two host-side sources into one ordered Trace per VM:

- connection verdicts logged by emberpool's nftables table, read from nflog
  (`log group N`) on a netlink socket, and
- DNS events (and any connection events) from NetPolicy.events().

Why nflog and not the kernel log: nflog hands each logged packet to userspace
as structured netlink attributes (prefix, input ifindex, packet headers), so
nothing is scraped from text. The kernel log is rate limited (printk
ratelimit silently drops lines, which would make the trace incomplete), is
shared with every other kernel message, is off by default in non-initial
network namespaces, and offers no way to detect loss. With nflog a full
socket buffer shows up as ENOBUFS and kernel-side drops show up as gaps in
the per-instance sequence number, so a trace that may be incomplete is known
to be incomplete. Only the standard library is needed.

Trust: the logged packet payload is written by the guest and is parsed with
bounds checks only to read the destination address, protocol and port. The
VM a packet belongs to is taken from the input interface index, a kernel
fact, mapped to the host-side uplink veth emberpool registered for that VM
(docs/40-rules.md rules 1, 2 and 17).
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import logging
import os
import socket
import struct
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, TypeVar

from emberpool._names import validate_domain, validate_interface, validate_netns, validate_vm_id
from emberpool._types import ConnEvent, DnsEvent, Event, IsolationError, NetHandle, Trace

__all__ = [
    "NFLOG_GROUP",
    "LOG_PREFIX_ALLOWED",
    "LOG_PREFIX_DROPPED",
    "NFLOG_SNAPLEN",
    "nft_log_statement",
    "verdict_from_prefix",
    "LogRecord",
    "PacketInfo",
    "parse_nflog",
    "parse_ip_packet",
    "NflogReader",
    "TraceReport",
    "TraceWriter",
    "build_trace",
    "write_trace",
]

log = logging.getLogger(__name__)

Verdict = Literal["allowed", "dropped"]

# ==========================================================================
# Log format shared with the nftables table (ep-net). This block is the only
# place the format is defined; change it here and both sides follow.
# ==========================================================================

# nflog group emberpool's verdict rules log to. One listener per group per
# network namespace.
NFLOG_GROUP = 7
# Log prefixes, one per verdict. Constants written by the host, never built
# from guest data.
LOG_PREFIX_ALLOWED = "ep-allow"
LOG_PREFIX_DROPPED = "ep-drop"
# Bytes of each packet copied to userspace: enough for IPv4/IPv6 + L4 ports.
NFLOG_SNAPLEN = 128

_PREFIX_TO_VERDICT: dict[str, Verdict] = {
    LOG_PREFIX_ALLOWED: "allowed",
    LOG_PREFIX_DROPPED: "dropped",
}


def nft_log_statement(verdict: Verdict, group: int = NFLOG_GROUP) -> list[str]:
    """nft tokens for the log statement of an allow or drop rule, e.g.
    ['log', 'prefix', '"ep-allow"', 'group', '7', 'snaplen', '128'].
    Built only from the constants above (rule 9)."""
    prefix = {"allowed": LOG_PREFIX_ALLOWED, "dropped": LOG_PREFIX_DROPPED}.get(verdict)
    if prefix is None:
        raise ValueError(f"verdict must be 'allowed' or 'dropped': {verdict!r}")
    _check_group(group)
    return ["log", "prefix", f'"{prefix}"', "group", str(group), "snaplen", str(NFLOG_SNAPLEN)]


def verdict_from_prefix(prefix: str) -> Verdict | None:
    """The verdict a log prefix stands for, or None if it is not ours."""
    return _PREFIX_TO_VERDICT.get(prefix)


def _check_group(group: int) -> int:
    if isinstance(group, bool) or not isinstance(group, int) or not 0 <= group <= 0xFFFF:
        raise ValueError(f"nflog group must be an int in 0..65535: {group!r}")
    return group


# ==========================================================================
# nfnetlink_log wire format (pure parsing, no I/O)
# ==========================================================================

NETLINK_NETFILTER = 12
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_NLM_F_REQUEST = 0x1
_NLM_F_ACK = 0x4
_NFNL_SUBSYS_ULOG = 4
_NFULNL_MSG_PACKET = 0
_NFULNL_MSG_CONFIG = 1
_MSG_PACKET = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_PACKET
_MSG_CONFIG = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_CONFIG

# Packet attributes (linux/netfilter/nfnetlink_log.h)
_NFULA_TIMESTAMP = 3
_NFULA_IFINDEX_INDEV = 4
_NFULA_PAYLOAD = 9
_NFULA_PREFIX = 10
_NFULA_SEQ = 12
# Config attributes and values
_NFULA_CFG_CMD = 1
_NFULA_CFG_MODE = 2
_NFULA_CFG_NLBUFSIZ = 3
_NFULA_CFG_TIMEOUT = 4
_NFULA_CFG_QTHRESH = 5
_NFULA_CFG_FLAGS = 6
_CFG_CMD_BIND = 1
_CFG_CMD_UNBIND = 2
_COPY_PACKET = 2
_CFG_F_SEQ = 0x0001

_NLA_TYPE_MASK = 0x3FFF
_NLMSGHDR = struct.Struct("=IHHII")
_NFGENMSG = struct.Struct("=BBH")  # family, version, res_id (big endian, packed by hand)
_NLATTR = struct.Struct("=HH")

_MAX_PREFIX = 128  # kernel limit for nflog prefixes


def _align4(n: int) -> int:
    return (n + 3) & ~3


@dataclass(frozen=True, slots=True)
class LogRecord:
    """One packet logged to nflog, as the kernel reported it."""

    prefix: str
    indev: int | None
    timestamp: float | None
    seq: int | None
    payload: bytes


def _attrs(buf: bytes, start: int, end: int) -> Iterable[tuple[int, bytes]]:
    off = start
    while off + _NLATTR.size <= end:
        nla_len, nla_type = _NLATTR.unpack_from(buf, off)
        if nla_len < _NLATTR.size or off + nla_len > end:
            raise ValueError("malformed netlink attribute")
        yield nla_type & _NLA_TYPE_MASK, buf[off + _NLATTR.size : off + nla_len]
        off += _align4(nla_len)


def _record_from_attrs(buf: bytes, start: int, end: int) -> LogRecord:
    prefix = ""
    indev = timestamp = seq = None
    payload = b""
    for kind, value in _attrs(buf, start, end):
        if kind == _NFULA_PREFIX:
            raw = value.split(b"\x00", 1)[0][:_MAX_PREFIX]
            prefix = raw.decode("ascii", "replace")
        elif kind == _NFULA_IFINDEX_INDEV and len(value) >= 4:
            indev = struct.unpack_from(">I", value)[0]
        elif kind == _NFULA_TIMESTAMP and len(value) >= 16:
            sec, usec = struct.unpack_from(">QQ", value)
            timestamp = sec + usec / 1e6
        elif kind == _NFULA_SEQ and len(value) >= 4:
            seq = struct.unpack_from(">I", value)[0]
        elif kind == _NFULA_PAYLOAD:
            payload = bytes(value[:NFLOG_SNAPLEN])
    return LogRecord(prefix, indev, timestamp, seq, payload)


def parse_nflog(buf: bytes) -> tuple[list[LogRecord], list[int]]:
    """Parse one netlink datagram. Returns (packet records, netlink error codes).

    Error codes are the negated errno values from NLMSG_ERROR messages (0 is an
    ack). Raises ValueError on a malformed datagram."""
    records: list[LogRecord] = []
    errors: list[int] = []
    off = 0
    n = len(buf)
    while off + _NLMSGHDR.size <= n:
        length, mtype, _flags, _seq, _pid = _NLMSGHDR.unpack_from(buf, off)
        if length < _NLMSGHDR.size or off + length > n:
            raise ValueError("malformed netlink message")
        body = off + _NLMSGHDR.size
        end = off + length
        if mtype == _NLMSG_ERROR:
            if end - body < 4:
                raise ValueError("short netlink error message")
            errors.append(struct.unpack_from("=i", buf, body)[0])
        elif mtype == _MSG_PACKET:
            if end - body < _NFGENMSG.size:
                raise ValueError("short nflog packet message")
            records.append(_record_from_attrs(buf, body + _NFGENMSG.size, end))
        # NLMSG_DONE, NOOP and other types carry nothing we need.
        off += _align4(length)
    return records, errors


@dataclass(frozen=True, slots=True)
class PacketInfo:
    dst_ip: str
    protocol: str
    dst_port: int


_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp"}
_PORT_PROTOS = {6, 17, 132}


def _proto_name(num: int) -> str:
    return _PROTO_NAMES.get(num, f"ip{num}")


def parse_ip_packet(payload: bytes) -> PacketInfo | None:
    """Destination IP, protocol and port from the start of an IP packet.

    The payload comes from the guest (rule 1): every offset is bounds checked,
    and anything that does not parse returns None. The port is 0 when the
    protocol has none, the packet is a non-first fragment, or the L4 header
    was not captured."""
    if len(payload) < 1:
        return None
    version = payload[0] >> 4
    if version == 4:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        proto = payload[9]
        frag_offset = struct.unpack_from(">H", payload, 6)[0] & 0x1FFF
        dst = str(ipaddress.IPv4Address(payload[16:20]))
        l4 = ihl
        has_ports = frag_offset == 0
    elif version == 6:
        if len(payload) < 40:
            return None
        proto = payload[6]
        dst = str(ipaddress.IPv6Address(payload[24:40]))
        l4 = 40
        has_ports = True
    else:
        return None
    port = 0
    if has_ports and proto in _PORT_PROTOS and len(payload) >= l4 + 4:
        port = struct.unpack_from(">H", payload, l4 + 2)[0]
    return PacketInfo(dst, _proto_name(proto), port)


def _nlmsg(mtype: int, flags: int, seq: int, payload: bytes) -> bytes:
    return _NLMSGHDR.pack(_NLMSGHDR.size + len(payload), mtype, flags, seq, 0) + payload


def _nlattr(kind: int, value: bytes) -> bytes:
    raw = _NLATTR.pack(_NLATTR.size + len(value), kind) + value
    return raw + b"\x00" * (_align4(len(raw)) - len(raw))


def _config_msg(group: int, seq: int, *attrs: bytes) -> bytes:
    nfgen = struct.pack("=BB", socket.AF_UNSPEC, 0) + struct.pack(">H", group)
    return _nlmsg(_MSG_CONFIG, _NLM_F_REQUEST | _NLM_F_ACK, seq, nfgen + b"".join(attrs))


# ==========================================================================
# Network namespace helper (tests read nflog inside a prefixed namespace)
# ==========================================================================

_T = TypeVar("_T")
_NETNS_JOIN_TIMEOUT = 10.0


def _in_netns(netns: str | None, fn: Callable[[], _T]) -> _T:
    """Run fn in network namespace `netns` (root namespace if None).

    setns changes only the calling thread, so fn runs on a fresh thread that
    is discarded afterwards; no pooled thread is ever left in another
    namespace. Sockets created there stay bound to that namespace."""
    if netns is None:
        return fn()
    validate_netns(netns)
    box: dict[str, object] = {}

    def target() -> None:
        try:
            fd = os.open(f"/run/netns/{netns}", os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.setns(fd, os.CLONE_NEWNET)
            finally:
                os.close(fd)
            box["value"] = fn()
        except BaseException as exc:  # handed to the caller
            box["error"] = exc

    t = threading.Thread(target=target, name=f"netns-{netns}", daemon=True)
    t.start()
    t.join(_NETNS_JOIN_TIMEOUT)  # rule 13; the thread is discarded either way
    if t.is_alive():
        raise IsolationError(f"timed out working in network namespace {netns}")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]  # type: ignore[return-value]


# ==========================================================================
# nflog reader
# ==========================================================================


class LogSource(Protocol):
    """What TraceWriter needs from a log reader. NflogReader is the real one."""

    def fileno(self) -> int: ...
    def drain(self) -> list[LogRecord]: ...
    def ifindex(self, name: str) -> int: ...
    def close(self) -> None: ...

    lost: int


_RCVBUF = 8 * 1024 * 1024
_RECV_SIZE = 256 * 1024
_MAX_DRAIN = 4096  # datagrams per drain call, so one flood cannot starve the loop


class NflogReader:
    """A bound nfnetlink_log listener for one group.

    `lost` counts events known to be lost: socket overruns (ENOBUFS),
    sequence gaps and datagrams that failed to parse."""

    def __init__(self, group: int = NFLOG_GROUP, *, netns: str | None = None) -> None:
        self.group = _check_group(group)
        self.netns = None if netns is None else validate_netns(netns)
        self.lost = 0
        self._last_seq: int | None = None
        self._sock: socket.socket | None = None

    def open(self) -> None:
        """Create the socket and bind the group. Raises IsolationError on any
        failure, leaving nothing open (fail closed)."""
        if self._sock is not None:
            return
        try:
            sock = _in_netns(self.netns, self._make_socket)
        except IsolationError:
            raise
        except OSError as exc:
            raise IsolationError(f"cannot open nflog group {self.group}: {exc}") from exc
        try:
            self._configure(sock)
        except BaseException:
            sock.close()
            raise
        sock.setblocking(False)
        self._sock = sock

    @staticmethod
    def _make_socket() -> socket.socket:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, NETLINK_NETFILTER)
        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, 33, _RCVBUF)  # SO_RCVBUFFORCE, needs CAP_NET_ADMIN
            except OSError:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF)
            sock.bind((0, 0))
        except BaseException:
            sock.close()
            raise
        return sock

    def _configure(self, sock: socket.socket) -> None:
        g = self.group
        steps = [
            _config_msg(g, 1, _nlattr(_NFULA_CFG_CMD, bytes([_CFG_CMD_BIND]))),
            _config_msg(g, 2, _nlattr(_NFULA_CFG_MODE, struct.pack(">IBB", NFLOG_SNAPLEN, _COPY_PACKET, 0))),
            # Deliver each packet at once instead of batching for up to a second.
            _config_msg(g, 3, _nlattr(_NFULA_CFG_QTHRESH, struct.pack(">I", 1))),
            _config_msg(g, 4, _nlattr(_NFULA_CFG_TIMEOUT, struct.pack(">I", 0))),
            _config_msg(g, 5, _nlattr(_NFULA_CFG_FLAGS, struct.pack(">H", _CFG_F_SEQ))),
        ]
        sock.settimeout(5.0)  # rule 13: bounded wait for each ack
        try:
            for msg in steps:
                sock.send(msg)
                self._await_ack(sock)
        except TimeoutError as exc:
            raise IsolationError(f"nflog group {g}: no ack from kernel") from exc
        except OSError as exc:
            raise IsolationError(f"nflog group {g}: configure failed: {exc}") from exc

    def _await_ack(self, sock: socket.socket) -> None:
        while True:
            data = sock.recv(_RECV_SIZE)
            try:
                _records, errors = parse_nflog(data)
            except ValueError as exc:
                raise IsolationError(f"nflog group {self.group}: bad reply: {exc}") from exc
            # Packets that arrive before the last ack are dropped here; nothing
            # is running yet while the reader is being opened.
            for code in errors:
                if code != 0:
                    raise IsolationError(
                        f"nflog group {self.group}: bind refused: {os.strerror(-code)}"
                    )
                return

    def fileno(self) -> int:
        if self._sock is None:
            raise RuntimeError("NflogReader is not open")
        return self._sock.fileno()

    def drain(self) -> list[LogRecord]:
        """Read every datagram waiting on the socket without blocking."""
        if self._sock is None:
            return []
        out: list[LogRecord] = []
        for _ in range(_MAX_DRAIN):
            try:
                data = self._sock.recv(_RECV_SIZE)
            except (BlockingIOError, InterruptedError):
                break
            except OSError as exc:
                if exc.errno == errno.ENOBUFS:
                    self.lost += 1  # at least one event lost; count unknown
                    log.warning("nflog group %d overrun: events lost", self.group)
                    continue
                raise
            try:
                records, _errors = parse_nflog(data)
            except ValueError:
                self.lost += 1
                continue
            for rec in records:
                self._check_seq(rec.seq)
                out.append(rec)
        return out

    def _check_seq(self, seq: int | None) -> None:
        if seq is None:
            return
        if self._last_seq is not None and seq != (self._last_seq + 1) & 0xFFFFFFFF:
            self.lost += 1
        self._last_seq = seq

    def ifindex(self, name: str) -> int:
        """Interface index of `name` in this reader's namespace."""
        validate_interface(name)
        try:
            return _in_netns(self.netns, lambda: socket.if_nametoindex(name))
        except OSError as exc:
            raise IsolationError(f"interface {name} not found: {exc}") from exc

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.setblocking(True)
            sock.settimeout(1.0)
            sock.send(_config_msg(self.group, 9, _nlattr(_NFULA_CFG_CMD, bytes([_CFG_CMD_UNBIND]))))
        except OSError:
            pass  # closing the socket releases the group anyway
        finally:
            sock.close()


# ==========================================================================
# TraceWriter
# ==========================================================================

# Per-VM cap on stored events (rule 13). A guest that floods connections must
# not exhaust host memory; a capped trace is reported incomplete.
MAX_EVENTS_PER_VM = 100_000


@dataclass(frozen=True, slots=True)
class TraceReport:
    """A finished trace. complete=False means events may be missing: the log
    socket overran, the per-VM cap was hit, a logged packet did not parse, or
    the DNS event stream failed."""

    vm_id: str
    trace: Trace
    complete: bool
    path: Path | None


@dataclass
class _VMState:
    vm_id: str
    veth: str
    ifindex: int
    events: list[tuple[float, int, Event]] = field(default_factory=list)
    incomplete: bool = False


class TraceWriter:
    """Collects host-observed network events per VM and produces a Trace each.

    Usage (inside the pool):

        async with TraceWriter(netpolicy.events()) as tw:
            net = await netpolicy.setup(vm_id, index, policy)
            await tw.register(net)            # before the VM starts
            ...                               # VM runs, VM killed
            report = await tw.finish(vm_id, workdir / "trace.json")
            await netpolicy.teardown(net)

    `register` must come before the VM can send packets; `finish` after the VM
    is killed. Events for unregistered VMs or interfaces are not ours and are
    discarded.
    """

    def __init__(
        self,
        net_events: AsyncIterator[DnsEvent | ConnEvent] | None,
        source: LogSource | None = None,
        *,
        settle: float = 0.05,
        max_events: int = MAX_EVENTS_PER_VM,
    ) -> None:
        self._net_events = net_events
        self._source: LogSource = source if source is not None else NflogReader()
        self._settle = settle
        self._max_events = max_events
        self._vms: dict[str, _VMState] = {}
        self._by_ifindex: dict[int, _VMState] = {}
        self._order = 0
        self._lost_seen = 0
        self._net_task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._reader_fd: int | None = None
        self._stream_failed = False
        self.discarded = 0  # events not attributable to a registered VM

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        """Bind the log source and start consuming. Fails closed: if the log
        cannot be read, no VM should start (raises IsolationError)."""
        if self._loop is not None:
            return
        loop = asyncio.get_running_loop()
        try:
            opener = getattr(self._source, "open", None)
            if opener is not None:
                await asyncio.to_thread(opener)
            fd = self._source.fileno()
            loop.add_reader(fd, self._on_readable)
        except IsolationError:
            self._source.close()
            raise
        except Exception as exc:
            self._source.close()
            raise IsolationError(f"cannot read the connection log: {exc}") from exc
        self._loop, self._reader_fd = loop, fd
        if self._net_events is not None:
            self._net_task = asyncio.create_task(self._consume_net_events())

    async def close(self) -> None:
        """Stop reading and release the socket. Idempotent, survives cancellation."""
        task, self._net_task = self._net_task, None
        try:
            if task is not None:
                task.cancel()
                try:
                    await asyncio.wait({task}, timeout=5.0)
                except asyncio.CancelledError:
                    pass
            aclose = getattr(self._net_events, "aclose", None)
            if aclose is not None:
                try:
                    await asyncio.wait_for(aclose(), 5.0)
                except (Exception, asyncio.CancelledError):
                    pass
        finally:
            if self._loop is not None and self._reader_fd is not None:
                self._loop.remove_reader(self._reader_fd)
            self._loop = self._reader_fd = None
            self._source.close()

    async def __aenter__(self) -> TraceWriter:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # -- per VM ------------------------------------------------------------

    async def register(self, net: NetHandle) -> None:
        """Start collecting for net.vm_id, attributing packets that enter on
        its host-side veth. Raises IsolationError if the veth is not there."""
        vm_id = validate_vm_id(net.vm_id)
        veth = validate_interface(net.veth_host)
        if vm_id in self._vms:
            raise ValueError(f"vm already registered: {vm_id}")
        ifindex = await asyncio.to_thread(self._source.ifindex, veth)
        if ifindex in self._by_ifindex:
            raise IsolationError(f"interface index {ifindex} already registered")
        state = _VMState(vm_id, veth, ifindex)
        self._vms[vm_id] = state
        self._by_ifindex[ifindex] = state

    async def finish(self, vm_id: str, path: Path | None = None) -> TraceReport:
        """Stop collecting for vm_id and return its ordered trace, writing it
        to `path` as trace.json when given. Call after the VM is killed."""
        validate_vm_id(vm_id)
        if vm_id not in self._vms:
            raise KeyError(f"vm not registered: {vm_id}")
        try:
            # Collect anything already logged but not yet read.
            if self._settle > 0:
                await asyncio.sleep(self._settle)
            self._on_readable()
            await asyncio.sleep(0)
        finally:
            state = self._vms.pop(vm_id)
            self._by_ifindex.pop(state.ifindex, None)
        trace = build_trace(state.events)
        complete = not (state.incomplete or self._stream_failed)
        if path is not None:
            await asyncio.to_thread(write_trace, trace, path)
        return TraceReport(vm_id, trace, complete, path)

    def forget(self, vm_id: str) -> None:
        """Drop a VM's events without producing a trace. Idempotent; for
        teardown after an error."""
        state = self._vms.pop(vm_id, None)
        if state is not None:
            self._by_ifindex.pop(state.ifindex, None)

    # -- ingestion ---------------------------------------------------------

    def _add(self, state: _VMState, time_: float, event: Event) -> None:
        if len(state.events) >= self._max_events:
            state.incomplete = True
            return
        self._order += 1
        state.events.append((time_, self._order, event))

    def _mark_all_incomplete(self) -> None:
        for state in self._vms.values():
            state.incomplete = True

    def _on_readable(self) -> None:
        try:
            records = self._source.drain()
        except OSError:
            log.exception("connection log read failed")
            self._mark_all_incomplete()
            return
        now = time.time()
        for rec in records:
            self.ingest_record(rec, now)
        if self._source.lost != self._lost_seen:
            self._lost_seen = self._source.lost
            self._mark_all_incomplete()

    def ingest_record(self, rec: LogRecord, recv_time: float) -> None:
        """Turn one logged packet into a ConnEvent for the VM whose veth it
        entered on."""
        state = self._by_ifindex.get(rec.indev) if rec.indev is not None else None
        if state is None:
            self.discarded += 1
            return
        verdict = verdict_from_prefix(rec.prefix)
        if verdict is None:
            self.discarded += 1  # another rule's log line, not a verdict of ours
            return
        info = parse_ip_packet(rec.payload)
        if info is None:
            state.incomplete = True
            return
        t = rec.timestamp if rec.timestamp is not None else recv_time
        event = ConnEvent(t, state.vm_id, info.dst_ip, info.dst_port, info.protocol, None, verdict)
        self._add(state, t, event)

    def ingest_event(self, event: DnsEvent | ConnEvent) -> None:
        """Take one event from NetPolicy.events()."""
        if not isinstance(event, (DnsEvent, ConnEvent)):
            self.discarded += 1
            return
        state = self._vms.get(event.vm_id)
        if state is None:
            self.discarded += 1
            return
        self._add(state, event.time, event)

    async def _consume_net_events(self) -> None:
        assert self._net_events is not None
        try:
            async for event in self._net_events:
                self.ingest_event(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("network event stream failed")
        # The stream should never end while the writer runs: from here on no
        # trace can be called complete.
        self._stream_failed = True
        self._mark_all_incomplete()


def _as_domain(name: str) -> str | None:
    try:
        return validate_domain(name)
    except ValueError:
        return None


def build_trace(events: Iterable[tuple[float, int, Event]]) -> Trace:
    """Order one VM's events by time (arrival order breaks ties) and attach the
    resolved name to connections whose IP the resolver answered for this VM
    before the connection. The most recent answer wins."""
    ordered = sorted(events, key=lambda item: (item[0], item[1]))
    names: dict[str, str] = {}
    out: list[Event] = []
    for _t, _n, ev in ordered:
        if isinstance(ev, DnsEvent):
            if ev.answers:
                domain = _as_domain(ev.name)
                if domain is not None:
                    for ip in ev.answers:
                        names[ip] = domain
        elif ev.name is None and ev.dst_ip in names:
            ev = ConnEvent(
                ev.time, ev.vm_id, ev.dst_ip, ev.dst_port, ev.protocol, names[ev.dst_ip], ev.verdict
            )
        out.append(ev)
    return Trace(events=tuple(out))


def write_trace(trace: Trace, path: Path) -> None:
    """Write trace.json atomically (temp file in the same directory, then
    rename), readable by the owner only."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = trace.to_json().encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
