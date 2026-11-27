"""TraceWriter against a real nftables `log group` rule.

Two prefixed network namespaces stand in for the host and the VM, joined by a
veth. The "host" namespace holds a prefixed nftables table whose rules log
with nft_log_statement(), and a NflogReader bound inside it. Needs root.
"""

from __future__ import annotations

import asyncio
import errno
import socket
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from emberpool._names import run_command, validate_interface, validate_netns, validate_nft_table
from emberpool._types import ConnEvent, DnsEvent, IsolationError, NetHandle, Trace
from emberpool.trace import NflogReader, TraceWriter, _in_netns, nft_log_statement
from tests.fakes import FakeNetPolicy

pytestmark = pytest.mark.vm

HOST_IP = "10.254.77.1"
GUEST_IP = "10.254.77.2"
UDP_PORT = 5001
TCP_PORT = 5002


async def _ip(*args: str) -> None:
    await run_command(["ip", *args], timeout=10)


@pytest.fixture
async def netpair(test_prefix: str) -> AsyncIterator[tuple[str, str, str]]:
    host_ns = validate_netns(f"{test_prefix}-h")
    guest_ns = validate_netns(f"{test_prefix}-g")
    host_if = validate_interface(f"{test_prefix}-h0")
    guest_if = validate_interface(f"{test_prefix}-g0")
    table = validate_nft_table(test_prefix)
    try:
        await _ip("netns", "add", host_ns)
        await _ip("netns", "add", guest_ns)
        await _ip("-n", host_ns, "link", "add", host_if, "type", "veth", "peer", "name", guest_if, "netns", guest_ns)
        await _ip("-n", host_ns, "addr", "add", f"{HOST_IP}/30", "dev", host_if)
        await _ip("-n", guest_ns, "addr", "add", f"{GUEST_IP}/30", "dev", guest_if)
        for ns, dev in ((host_ns, host_if), (guest_ns, guest_if), (host_ns, "lo"), (guest_ns, "lo")):
            await _ip("-n", ns, "link", "set", dev, "up")
        allow = " ".join(nft_log_statement("allowed"))
        drop = " ".join(nft_log_statement("dropped"))
        ruleset = (
            f"table inet {table} {{\n"
            f"  chain input {{\n"
            f"    type filter hook input priority 0; policy accept;\n"
            f'    iifname "{host_if}" udp dport {UDP_PORT} {allow} accept\n'
            f'    iifname "{host_if}" tcp dport {TCP_PORT} {drop} drop\n'
            f"  }}\n"
            f"}}\n"
        )
        await run_command(["ip", "netns", "exec", host_ns, "nft", "-f", "-"], stdin=ruleset.encode(), timeout=10)
        yield host_ns, guest_ns, host_if
    finally:
        # Deleting the namespaces removes the veth pair and the table with them.
        for ns in (guest_ns, host_ns):
            await run_command(["ip", "netns", "del", ns], timeout=10, check=False)
        out = await run_command(["ip", "netns", "list"], timeout=10)
        assert host_ns.encode() not in out.stdout and guest_ns.encode() not in out.stdout


def _send_from_guest() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.sendto(b"hello", (HOST_IP, UDP_PORT))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
        t.setblocking(False)
        err = t.connect_ex((HOST_IP, TCP_PORT))  # SYN goes out, is logged and dropped
        assert err in (0, errno.EINPROGRESS)


async def test_real_nflog_events_reach_trace(netpair: tuple[str, str, str], tmp_path: Path) -> None:
    host_ns, guest_ns, host_if = netpair
    net = FakeNetPolicy()
    reader = NflogReader(netns=host_ns)
    async with TraceWriter(net.events(), reader, settle=0.3) as tw:
        await tw.register(NetHandle("vmtrace", 0, guest_ns, host_if))
        net.emit(DnsEvent(1.0, "vmtrace", "example.com", (HOST_IP,)))
        await asyncio.sleep(0)
        _in_netns(guest_ns, _send_from_guest)
        report = await tw.finish("vmtrace", tmp_path / "trace.json")

    assert report.complete
    conns = [e for e in report.trace if isinstance(e, ConnEvent)]
    udp = [e for e in conns if e.protocol == "udp"]
    tcp = [e for e in conns if e.protocol == "tcp"]
    assert len(udp) == 1
    assert udp[0].dst_ip == HOST_IP and udp[0].dst_port == UDP_PORT
    assert udp[0].verdict == "allowed" and udp[0].name == "example.com"
    assert tcp and all(e.verdict == "dropped" and e.dst_port == TCP_PORT for e in tcp)
    assert isinstance(report.trace.events[0], DnsEvent)
    times = [e.time for e in report.trace]
    assert times == sorted(times)
    assert Trace.from_json((tmp_path / "trace.json").read_text()) == report.trace


async def test_second_listener_on_same_group_fails_closed(netpair: tuple[str, str, str]) -> None:
    host_ns, _guest_ns, _host_if = netpair
    first = NflogReader(netns=host_ns)
    first.open()
    try:
        with pytest.raises(IsolationError):
            await TraceWriter(None, NflogReader(netns=host_ns)).start()
    finally:
        first.close()
    # Released on close: the group can be bound again.
    again = NflogReader(netns=host_ns)
    again.open()
    again.close()


async def test_register_fails_closed_for_missing_veth(netpair: tuple[str, str, str]) -> None:
    host_ns, guest_ns, _host_if = netpair
    async with TraceWriter(None, NflogReader(netns=host_ns)) as tw:
        with pytest.raises(IsolationError):
            await tw.register(NetHandle("vmtrace", 0, guest_ns, "ep-nosuchif"))
