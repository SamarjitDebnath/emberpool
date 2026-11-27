"""Fuzz the parsers that read guest-controlled bytes (docs/40-rules.md rules 1 and 16).

Every input here could come from a hostile guest: vsock frames, DNS queries,
and the packet headers nflog copies out of guest traffic. Each parser must
either return a well-formed value or raise its own documented error, never
crash with anything else and never grant anything.

Seeded and deterministic, so a failure always reproduces.
"""

from __future__ import annotations

import asyncio
import random
import struct

import dns.message
import pytest

from emberpool import _protocol as p
from emberpool import trace
from emberpool._resolver import LookupResult, Resolver, ResolverClient
from emberpool._types import DnsEvent

SEED = 0xE3B0
ROUNDS = 3000


def _rng(salt: int) -> random.Random:
    return random.Random(SEED ^ salt)


def _mutate(rng: random.Random, data: bytes) -> bytes:
    """Flip, insert, delete or truncate a few bytes."""
    buf = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(5)
        if op == 0 and buf:
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif op == 1:
            buf.insert(rng.randrange(len(buf) + 1), rng.randrange(256))
        elif op == 2 and buf:
            del buf[rng.randrange(len(buf))]
        elif op == 3 and buf:
            del buf[rng.randrange(len(buf)) :]
        else:
            buf += rng.randbytes(rng.randint(1, 16))
    return bytes(buf)


def _random_bytes(rng: random.Random, max_len: int = 512) -> bytes:
    return rng.randbytes(rng.randint(0, max_len))


# -- vsock protocol ---------------------------------------------------------------


def test_decode_response_fuzz() -> None:
    rng = _rng(1)
    good = p.encode_response("out\n", "err", 3)[4:]
    for i in range(ROUNDS):
        data = _mutate(rng, good) if i % 2 else _random_bytes(rng)
        try:
            r = p.decode_response(data)
        except p.ProtocolError:
            continue
        assert isinstance(r.stdout, str) and isinstance(r.stderr, str)
        assert type(r.exit_code) is int


def test_decode_request_fuzz() -> None:
    rng = _rng(2)
    good = p.encode_request("print(1)", 5)[4:]
    for i in range(ROUNDS):
        data = _mutate(rng, good) if i % 2 else _random_bytes(rng)
        try:
            r = p.decode_request(data)
        except p.ProtocolError:
            continue
        assert isinstance(r.code, str) and 0 < r.timeout <= p.MAX_TIMEOUT


async def test_read_frame_fuzz_never_overreads() -> None:
    rng = _rng(3)
    good = p.encode_response("x" * 100, "", 0)
    for i in range(ROUNDS // 3):
        data = _mutate(rng, good) if i % 2 else _random_bytes(rng, 64)
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        try:
            payload = await asyncio.wait_for(p.read_frame(reader, max_size=4096), 1)
        except p.ProtocolError:
            continue
        assert 0 < len(payload) <= 4096


def test_hostile_length_headers_are_rejected_before_reading() -> None:
    for length in (0, p.MAX_FRAME + 1, 2**31, 2**32 - 1):
        with pytest.raises(p.ProtocolError):
            p.parse_header(struct.pack(">I", length))


# -- DNS resolver -------------------------------------------------------------------


class _Upstream:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def __call__(self, name: str) -> LookupResult:
        self.calls.append(name)
        return LookupResult(("93.184.215.14",), 60)


async def test_resolver_fuzz_never_crashes_or_leaks_names() -> None:
    rng = _rng(4)
    events: list[DnsEvent] = []
    up = _Upstream()
    added: list[tuple[str, ...]] = []

    async def add(ips: tuple[str, ...]) -> None:
        added.append(ips)

    res = Resolver(events.append, lookup=up)
    client = ResolverClient("fuzz", 9, ifindex=42, allow=frozenset({"ok.example"}), add_ips=add)
    res.register(client)
    seeds = [
        dns.message.make_query(n, t).to_wire()
        for n in ("ok.example", "evil.example", "ok.example.evil.example", "x" * 60 + ".example")
        for t in ("A", "AAAA", "TXT", "ANY")
    ]
    for i in range(ROUNDS):
        data = _mutate(rng, rng.choice(seeds)) if i % 3 else _random_bytes(rng, 600)
        reply = await asyncio.wait_for(res.answer(data, client), 5)
        if reply is not None:
            assert isinstance(reply, bytes) and len(reply) <= 4096
    # Only the allowlisted name ever reached the upstream or the allow set.
    assert set(up.calls) <= {"ok.example"}
    assert all(ips == ("93.184.215.14",) for ips in added)
    # Every recorded name is escaped printable ASCII (DnsEvent validates it).
    assert all(isinstance(e, DnsEvent) for e in events)
    assert client.inflight == 0


# -- nflog / packet headers -----------------------------------------------------------


def _ipv4_tcp(dst: bytes, dport: int) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, b"\x0a\xc8\x00\x02", dst)
    tcp = struct.pack("!HHIIBBHHH", 40000, dport, 0, 0, 0x50, 0x02, 1024, 0, 0)
    return ip + tcp


def test_parse_ip_packet_fuzz() -> None:
    rng = _rng(5)
    good = _ipv4_tcp(b"\x97\x65\x00\xdf", 443)
    for i in range(ROUNDS):
        data = _mutate(rng, good) if i % 2 else _random_bytes(rng, 80)
        info = trace.parse_ip_packet(data)
        if info is None:
            continue
        assert 0 <= info.dst_port <= 65535
        assert info.protocol.isalnum() and info.protocol.islower()


def test_parse_nflog_fuzz() -> None:
    rng = _rng(6)
    # A minimal well-formed datagram: one NLMSG_ERROR ack.
    ack = struct.pack("=IHHII", 20, 2, 0, 1, 0) + struct.pack("=i", 0)
    for i in range(ROUNDS):
        data = _mutate(rng, ack) if i % 2 else _random_bytes(rng, 256)
        try:
            records, errors = trace.parse_nflog(data)
        except ValueError:
            continue
        assert isinstance(records, list) and isinstance(errors, list)
