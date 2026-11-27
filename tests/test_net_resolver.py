"""Unit tests for the host DNS resolver. No root needed."""

from __future__ import annotations

import asyncio
import socket

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from emberpool._resolver import (
    LookupResult,
    Resolver,
    ResolverClient,
    UpstreamError,
    answer_allowed,
    dnspython_lookup,
)
from emberpool._types import DnsEvent


class Upstream:
    def __init__(self, table: dict[str, LookupResult | Exception]) -> None:
        self.table = table
        self.calls: list[str] = []

    async def __call__(self, name: str) -> LookupResult:
        self.calls.append(name)
        r = self.table.get(name, LookupResult(None))
        if isinstance(r, Exception):
            raise r
        return r


class SetRecorder:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.added: list[tuple[str, ...]] = []

    async def __call__(self, ips: tuple[str, ...]) -> None:
        if self.fail:
            raise RuntimeError("nft failed")
        self.added.append(ips)


def make(
    table: dict[str, LookupResult | Exception] | None = None,
    allow: tuple[str, ...] = ("ok.example",),
    fail_add: bool = False,
    index: int = 7,
    vm_id: str = "vm1",
) -> tuple[Resolver, ResolverClient, list[DnsEvent], SetRecorder, Upstream]:
    events: list[DnsEvent] = []
    up = Upstream(table or {"ok.example": LookupResult(("93.184.215.14", "93.184.215.15"), 300)})
    res = Resolver(events.append, lookup=up)
    rec = SetRecorder(fail_add)
    client = ResolverClient(vm_id, index, ifindex=42, allow=frozenset(allow), add_ips=rec)
    res.register(client)
    return res, client, events, rec, up


def query(name: str, rdtype: str = "A") -> bytes:
    return dns.message.make_query(name, rdtype).to_wire()


def parse(wire: bytes | None) -> dns.message.Message:
    assert wire is not None
    return dns.message.from_wire(wire)


async def test_allowed_name_resolves_after_set_add() -> None:
    res, client, events, rec, _ = make()
    reply = parse(await res.answer(query("ok.example"), client))
    assert reply.rcode() == dns.rcode.NOERROR
    ips = sorted(r.address for rrset in reply.answer for r in rrset)
    assert ips == ["93.184.215.14", "93.184.215.15"]
    assert reply.answer[0].ttl <= 60
    assert rec.added == [("93.184.215.14", "93.184.215.15")]
    assert [(e.vm_id, e.name, e.answers) for e in events] == [
        ("vm1", "ok.example", ("93.184.215.14", "93.184.215.15"))
    ]


async def test_name_match_is_case_insensitive_and_ignores_final_dot() -> None:
    res, client, events, _, _ = make()
    reply = parse(await res.answer(query("OK.Example."), client))
    assert reply.rcode() == dns.rcode.NOERROR
    assert events[0].name == "ok.example"


async def test_unlisted_name_gets_nxdomain_without_lookup() -> None:
    res, client, events, rec, up = make()
    reply = parse(await res.answer(query("evil.example"), client))
    assert reply.rcode() == dns.rcode.NXDOMAIN
    assert not reply.answer
    assert up.calls == [] and rec.added == []
    assert events[0].name == "evil.example" and events[0].answers is None


async def test_subdomain_of_allowed_name_is_not_allowed() -> None:
    res, client, events, _, _ = make()
    reply = parse(await res.answer(query("sub.ok.example"), client))
    assert reply.rcode() == dns.rcode.NXDOMAIN


async def test_aaaa_for_allowed_name_is_empty_noerror() -> None:
    res, client, events, rec, up = make()
    reply = parse(await res.answer(query("ok.example", "AAAA"), client))
    assert reply.rcode() == dns.rcode.NOERROR and not reply.answer
    assert up.calls == [] and rec.added == []
    assert events[0].answers == ()


async def test_set_add_failure_fails_closed() -> None:
    res, client, events, _, _ = make(fail_add=True)
    reply = parse(await res.answer(query("ok.example"), client))
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert not reply.answer
    assert events[0].answers is None
    assert client.added == set()


async def test_upstream_failure_is_servfail() -> None:
    res, client, events, rec, _ = make({"ok.example": UpstreamError("timeout")})
    reply = parse(await res.answer(query("ok.example"), client))
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert rec.added == [] and events[0].answers is None


async def test_upstream_nxdomain_passes_through() -> None:
    res, client, events, _, _ = make({"ok.example": LookupResult(None)})
    reply = parse(await res.answer(query("ok.example"), client))
    assert reply.rcode() == dns.rcode.NXDOMAIN


async def test_internal_addresses_are_never_returned() -> None:
    bad = ("127.0.0.1", "169.254.169.254", "10.200.3.1", "224.0.0.1", "0.0.0.0", "1.2.3.4")
    res, client, events, rec, _ = make({"ok.example": LookupResult(bad)})
    reply = parse(await res.answer(query("ok.example"), client))
    assert [r.address for rrset in reply.answer for r in rrset] == ["1.2.3.4"]
    assert rec.added == [("1.2.3.4",)]
    assert events[0].answers == ("1.2.3.4",)


async def test_only_new_addresses_are_added_again() -> None:
    res, client, _, rec, _ = make()
    await res.answer(query("ok.example"), client)
    await res.answer(query("ok.example"), client)
    assert len(rec.added) == 1


async def test_allow_set_cap_fails_closed() -> None:
    res, client, events, rec, _ = make()
    client.max_ips = 1
    reply = parse(await res.answer(query("ok.example"), client))
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert rec.added == []


async def test_unregistered_vm_gets_no_addresses() -> None:
    res, client, events, rec, _ = make()
    res.unregister(client.index, client.vm_id)
    reply = parse(await res.answer(query("ok.example"), client))
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert rec.added == []


async def test_unregister_checks_owner() -> None:
    res, client, _, _, _ = make()
    res.unregister(client.index, "other")
    assert res.identify(client.source_ip, 42) is client


async def test_inflight_cap() -> None:
    gate = asyncio.Event()

    async def slow(name: str) -> LookupResult:
        await gate.wait()
        return LookupResult(("1.2.3.4",))

    events: list[DnsEvent] = []
    res = Resolver(events.append, lookup=slow)
    client = ResolverClient("vm1", 1, 5, frozenset({"ok.example"}), SetRecorder(), max_inflight=2)
    res.register(client)
    tasks = [asyncio.create_task(res.answer(query("ok.example"), client)) for _ in range(3)]
    await asyncio.sleep(0.01)
    assert tasks[2].done()
    assert parse(tasks[2].result()).rcode() == dns.rcode.SERVFAIL
    gate.set()
    for t in tasks[:2]:
        assert parse(await t).rcode() == dns.rcode.NOERROR
    assert client.inflight == 0


async def test_garbage_gets_formerr_and_no_event() -> None:
    res, client, events, _, _ = make()
    wire = bytes([0x12, 0x34, 0x01, 0x00]) + b"\x00\x01" + b"\x00" * 6 + b"\xff" * 20
    reply = await res.answer(wire, client)
    assert reply is not None and reply[:2] == b"\x12\x34"
    assert reply[3] & 0x0F == dns.rcode.FORMERR
    assert events == []
    assert await res.answer(b"\x00", client) is None


async def test_responses_are_never_answered() -> None:
    res, client, events, _, _ = make()
    msg = dns.message.make_response(dns.message.make_query("ok.example", "A"))
    assert await res.answer(msg.to_wire(), client) is None
    assert events == []


async def test_oversized_query_dropped() -> None:
    res, client, events, _, _ = make()
    assert await res.answer(b"\x00" * 5000, client) is None


async def test_hostile_name_is_escaped_in_event() -> None:
    res, client, events, _, _ = make()
    name = dns.name.Name([b"a b\x00\xff\n", b"example", b""])
    q = dns.message.make_query(name, "A")
    reply = parse(await res.answer(q.to_wire(), client))
    assert reply.rcode() == dns.rcode.NXDOMAIN
    assert events[0].answers is None
    assert all("\x21" <= c <= "\x7e" for c in events[0].name)


async def test_non_query_opcode_refused() -> None:
    res, client, events, _, up = make()
    q = dns.message.make_query("ok.example", "A")
    q.set_opcode(dns.opcode.UPDATE)
    reply = parse(await res.answer(q.to_wire(), client))
    assert reply.rcode() in (dns.rcode.REFUSED, dns.rcode.FORMERR)
    assert up.calls == [] and events == []


def test_identify_needs_both_source_and_interface() -> None:
    res, client, _, _, _ = make(index=7)
    assert res.identify("10.200.7.2", 42) is client
    assert res.identify("10.200.7.2", 43) is None  # wrong ingress interface
    assert res.identify("10.200.7.1", 42) is None
    assert res.identify("10.200.8.2", 42) is None
    assert res.identify("127.0.0.1", 42) is None
    assert res.identify("not-an-ip", 42) is None


def test_register_rejects_duplicate_index() -> None:
    res, client, _, _, _ = make(index=7)
    other = ResolverClient("vm2", 7, 9, frozenset(), SetRecorder())
    with pytest.raises(ValueError):
        res.register(other)


def test_client_validates_inputs() -> None:
    with pytest.raises(ValueError):
        ResolverClient("BAD ID", 1, 1, frozenset(), SetRecorder())
    with pytest.raises(ValueError):
        ResolverClient("vm1", 999, 1, frozenset(), SetRecorder())
    with pytest.raises(ValueError):
        ResolverClient("vm1", 1, 0, frozenset(), SetRecorder())
    with pytest.raises(ValueError):
        ResolverClient("vm1", 1, 1, frozenset({"*.example"}), SetRecorder())


@pytest.mark.parametrize(
    ("ip", "ok"),
    [
        ("1.1.1.1", True),
        ("192.168.1.10", True),
        ("127.0.0.53", False),
        ("169.254.169.254", False),
        ("10.200.0.1", False),
        ("239.1.1.1", False),
        ("240.0.0.1", False),
        ("::1", False),
        ("2606:4700::1", False),
        ("junk", False),
    ],
)
def test_answer_allowed(ip: str, ok: bool) -> None:
    assert answer_allowed(ip) is ok


async def test_socket_ignores_unknown_sources() -> None:
    res, client, events, _, up = make()
    port = await res.start("127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setblocking(False)
            s.sendto(query("ok.example"), ("127.0.0.1", port))
            for _ in range(50):
                if res.ignored:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            with pytest.raises(BlockingIOError):
                s.recvfrom(2048)  # no reply
        assert res.ignored == 1
        assert events == [] and up.calls == []
    finally:
        await res.close()
    await res.close()  # idempotent


class _FakeUpstream(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        q = dns.message.from_wire(data)
        r = dns.message.make_response(q)
        name = q.question[0].name.to_text(omit_final_dot=True)
        if name == "ok.example" and q.question[0].rdtype == dns.rdatatype.A:
            r.answer.append(dns.rrset.from_text(q.question[0].name, 120, "IN", "A", "1.2.3.4"))
        elif name == "empty.example":
            pass
        else:
            r.set_rcode(dns.rcode.NXDOMAIN)
        assert self.transport is not None
        self.transport.sendto(r.to_wire(), addr)


async def test_dnspython_lookup_against_local_upstream() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(_FakeUpstream, local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        lookup = dnspython_lookup(["127.0.0.1"], port=port, timeout=2.0)
        r = await lookup("ok.example")
        assert r.addresses == ("1.2.3.4",) and r.ttl == 120
        assert (await lookup("nope.example")).addresses is None
        assert (await lookup("empty.example")).addresses == ()
    finally:
        transport.close()


async def test_dnspython_lookup_times_out() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        lookup = dnspython_lookup(["127.0.0.1"], port=silent.getsockname()[1], timeout=0.3)
        with pytest.raises(UpstreamError):
            await lookup("ok.example")
