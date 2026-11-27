"""HostNetPolicy against the real kernel: namespaces, veths, nftables, resolver.

No Firecracker. A "guest" stand-in is a separate namespace joined to the VM
namespace by an extra veth, so its traffic takes the same path a guest's
would (DNAT, masquerade, root-namespace policy). A "server" namespace on the
host side stands in for the internet.

Every resource is named with the test prefix and removed in `finally`.
"""

from __future__ import annotations

import asyncio
import json
import re
import zlib
from collections.abc import AsyncIterator, Sequence

import pytest

from emberpool._names import CommandError, CommandResult, run_command
from emberpool._resolver import LookupResult
from emberpool._types import TAP_MAC, IsolationError, NetworkPolicy
from emberpool.netpolicy import HostNetPolicy

pytestmark = pytest.mark.vm

T = 15.0


async def sh(*argv: str, check: bool = True, timeout: float = T) -> CommandResult:
    return await run_command(list(argv), timeout=timeout, check=check)


def base_index(prefix: str) -> int:
    """Uplink indexes for this session, spread by prefix to avoid other sessions."""
    return 100 + zlib.crc32(prefix.encode()) % 120


def server_octet(prefix: str) -> int:
    return zlib.crc32(prefix.encode()) % 250


async def netns_names() -> set[str]:
    r = await sh("ip", "-j", "netns", "list")
    return {e["name"] for e in json.loads(r.stdout or b"[]")}


async def link_exists(name: str) -> bool:
    return (await sh("ip", "link", "show", "dev", name, check=False)).returncode == 0


async def nft_has(*obj: str) -> bool:
    return (await sh("nft", "list", *obj, check=False)).returncode == 0


async def rule_packets(table: str, chain: str, prefix: str) -> int:
    r = await sh("nft", "-j", "list", "chain", "inet", table, chain)
    total = 0
    for item in json.loads(r.stdout)["nftables"]:
        rule = item.get("rule")
        if not rule:
            continue
        exprs = rule["expr"]
        if any(e.get("log", {}).get("prefix") == prefix for e in exprs):
            total += sum(e["counter"]["packets"] for e in exprs if "counter" in e)
    return total


async def host_forward_open() -> bool:
    """False if another firewall on the host (for example Docker's FORWARD DROP
    policy in iptables) drops forwarded traffic after our table accepts it."""
    r = await sh("iptables", "-S", "FORWARD", check=False)
    return r.returncode != 0 or b"-P FORWARD DROP" not in r.stdout


@pytest.fixture
async def policy(test_prefix: str) -> AsyncIterator[HostNetPolicy]:
    o = server_octet(test_prefix)
    table = {"ok.example": f"198.18.{o}.2", "other.example": f"198.18.{o}.3"}

    async def lookup(name: str) -> LookupResult:
        return LookupResult((table[name],) if name in table else None, 30)

    p = HostNetPolicy(prefix=test_prefix, table=test_prefix, nflog_group=7, lookup=lookup)
    await p.start()
    try:
        yield p
    finally:
        await p.close()
        assert not await nft_has("table", "inet", test_prefix)


@pytest.fixture
async def server(test_prefix: str) -> AsyncIterator[tuple[str, str]]:
    """A namespace with two addresses serving HTTP on 8080."""
    o = server_octet(test_prefix)
    ns, host_if = f"{test_prefix}-srv", f"{test_prefix}-s"
    proc: asyncio.subprocess.Process | None = None
    try:
        await sh("ip", "netns", "add", ns)
        await sh("ip", "link", "add", host_if, "type", "veth", "peer", "name", "ep-srv", "netns", ns)
        await sh("ip", "addr", "add", f"198.18.{o}.1/29", "dev", host_if)
        await sh("ip", "link", "set", host_if, "up")
        await sh("ip", "-n", ns, "addr", "add", f"198.18.{o}.2/29", "dev", "ep-srv")
        await sh("ip", "-n", ns, "addr", "add", f"198.18.{o}.3/29", "dev", "ep-srv")
        await sh("ip", "-n", ns, "link", "set", "ep-srv", "up")
        await sh("ip", "-n", ns, "link", "set", "lo", "up")
        proc = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", ns, "python3", "-c",
            "import http.server as h\n"
            "class H(h.BaseHTTPRequestHandler):\n"
            "  def do_GET(s):\n"
            "    s.send_response(200); s.end_headers(); s.wfile.write(b'hello')\n"
            "  def log_message(s,*a): pass\n"
            "h.HTTPServer(('0.0.0.0',8080),H).serve_forever()\n",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(0.5)
        yield f"198.18.{o}.2", f"198.18.{o}.3"
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        if await link_exists(host_if):
            await sh("ip", "link", "del", "dev", host_if)
        if ns in await netns_names():
            await sh("ip", "netns", "del", ns)


class Guest:
    """A namespace standing in for the guest, attached inside a VM namespace."""

    def __init__(self, ns: str, vm_ns: str) -> None:
        self.ns, self.vm_ns = ns, vm_ns

    async def __aenter__(self) -> Guest:
        await sh("ip", "netns", "add", self.ns)
        await sh("ip", "-n", self.vm_ns, "link", "add", "ep-gst", "type", "veth",
                 "peer", "name", "ep-gst", "netns", self.ns)
        await sh("ip", "-n", self.vm_ns, "addr", "add", "172.16.1.1/30", "dev", "ep-gst")
        await sh("ip", "-n", self.vm_ns, "link", "set", "ep-gst", "up")
        await sh("ip", "-n", self.ns, "addr", "add", "172.16.1.2/30", "dev", "ep-gst")
        await sh("ip", "-n", self.ns, "link", "set", "ep-gst", "up")
        await sh("ip", "-n", self.ns, "link", "set", "lo", "up")
        await sh("ip", "-n", self.ns, "route", "add", "default", "via", "172.16.1.1")
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self.ns in await netns_names():
            await sh("ip", "netns", "del", self.ns)

    async def run(self, *argv: str, timeout: float = T) -> CommandResult:
        return await sh("ip", "netns", "exec", self.ns, *argv, check=False, timeout=timeout)

    async def dig(self, name: str, server: str = "172.16.0.1") -> tuple[str, list[str]]:
        r = await self.run("dig", "+time=3", "+tries=1", f"@{server}", name, "A")
        out = r.stdout.decode()
        m = re.search(r"status: (\w+)", out)
        status = m.group(1) if m else "NOREPLY"
        answers = re.findall(r"^\S+\s+\d+\s+IN\s+A\s+(\S+)$", out, re.M)
        return status, answers

    async def http(self, ip: str) -> bool:
        r = await self.run("curl", "-s", "--connect-timeout", "2", "-m", "4", f"http://{ip}:8080/")
        return r.returncode == 0 and r.stdout == b"hello"


async def drain(policy: HostNetPolicy) -> list[tuple[str, str, tuple[str, ...] | None]]:
    out = []
    it = policy.events()
    while True:
        try:
            e = await asyncio.wait_for(anext(it), 0.2)
        except TimeoutError:
            return out
        out.append((e.vm_id, e.name, getattr(e, "answers", None)))


async def test_setup_and_teardown_leave_nothing(policy: HostNetPolicy, test_prefix: str) -> None:
    idx = base_index(test_prefix)
    h = await policy.setup("vm1", idx, NetworkPolicy.parse("allow:ok.example"))
    try:
        assert h.netns == f"{test_prefix}-vm1" and h.veth_host == f"{test_prefix}-h{idx}"
        assert h.netns in await netns_names()
        assert await link_exists(h.veth_host)
        r = await sh("ip", "-n", h.netns, "-j", "link", "show", "dev", "tap0")
        assert json.loads(r.stdout)[0]["address"] == TAP_MAC
        r = await sh("ip", "-n", h.netns, "-j", "addr", "show", "dev", "tap0")
        assert json.loads(r.stdout)[0]["addr_info"][0]["local"] == "172.16.0.1"
        assert await nft_has("set", "inet", test_prefix, "a-vm1")
        assert await nft_has("chain", "inet", test_prefix, "f-vm1")
        ruleset = (await sh("ip", "netns", "exec", h.netns, "nft", "list", "ruleset")).stdout.decode()
        assert "dnat to 10.200." in ruleset and "masquerade" in ruleset
    finally:
        await policy.teardown(h)
    assert h.netns not in await netns_names()
    assert not await link_exists(h.veth_host)
    assert not await nft_has("set", "inet", test_prefix, "a-vm1")
    assert not await nft_has("chain", "inet", test_prefix, "f-vm1")
    assert not await nft_has("chain", "inet", test_prefix, "i-vm1")
    await policy.teardown(h)  # idempotent


async def test_setup_fails_closed_and_cleans_up(test_prefix: str) -> None:
    async def failing(argv: Sequence[str], **kw: object) -> CommandResult:
        if "route" in argv:
            raise CommandError(CommandResult(tuple(argv), 2, b"", b"injected"))
        return await run_command(argv, **kw)  # type: ignore[arg-type]

    p = HostNetPolicy(prefix=test_prefix, table=test_prefix, runner=failing)
    try:
        with pytest.raises(IsolationError):
            await p.setup("vm2", base_index(test_prefix), NetworkPolicy())
        assert f"{test_prefix}-vm2" not in await netns_names()
        assert not await link_exists(f"{test_prefix}-h{base_index(test_prefix)}")
        assert not await nft_has("chain", "inet", test_prefix, "f-vm2")
        assert not await nft_has("set", "inet", test_prefix, "a-vm2")
        assert not await nft_has("map", "inet", test_prefix, "fwd_vmap") or b"vm2" not in (
            await sh("nft", "list", "map", "inet", test_prefix, "fwd_vmap")
        ).stdout
    finally:
        await p.close()


async def test_subnet_in_use_fails_closed(policy: HostNetPolicy, test_prefix: str) -> None:
    idx = base_index(test_prefix) + 2
    dummy = f"{test_prefix}-d"
    await sh("ip", "link", "add", dummy, "type", "dummy")
    try:
        await sh("ip", "addr", "add", f"10.200.{idx}.1/30", "dev", dummy)
        with pytest.raises(IsolationError, match="already in use"):
            await policy.setup("vm3", idx, NetworkPolicy())
        assert f"{test_prefix}-vm3" not in await netns_names()
    finally:
        await sh("ip", "link", "del", "dev", dummy)


async def test_existing_table_is_not_taken_over(test_prefix: str) -> None:
    await sh("nft", "add", "table", "inet", test_prefix)
    try:
        p = HostNetPolicy(prefix=test_prefix, table=test_prefix)
        with pytest.raises(IsolationError):
            await p.start()
        await p.close()
        assert await nft_has("table", "inet", test_prefix)  # left alone
    finally:
        await sh("nft", "delete", "table", "inet", test_prefix)


async def test_teardown_completes_when_cancelled(policy: HostNetPolicy, test_prefix: str) -> None:
    h = await policy.setup("vm4", base_index(test_prefix), NetworkPolicy())
    task = asyncio.create_task(policy.teardown(h))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert h.netns not in await netns_names()
    assert not await link_exists(h.veth_host)
    assert not await nft_has("chain", "inet", test_prefix, "f-vm4")


async def test_template_netns(policy: HostNetPolicy, test_prefix: str) -> None:
    async with policy.template_netns() as ns:
        assert ns.startswith(f"{test_prefix}-tmpl-")
        r = await sh("ip", "-n", ns, "-j", "link", "show", "dev", "tap0")
        assert json.loads(r.stdout)[0]["address"] == TAP_MAC
        r = await sh("ip", "-n", ns, "-j", "route", "show")
        assert all(rt.get("dst") != "default" for rt in json.loads(r.stdout))
    assert ns not in await netns_names()

    with pytest.raises(RuntimeError):
        async with policy.template_netns() as ns2:
            raise RuntimeError("boom")
    assert ns2 not in await netns_names()


async def test_dns_and_egress_per_vm(
    policy: HostNetPolicy, server: tuple[str, str], test_prefix: str
) -> None:
    ip_ok, ip_other = server
    i = base_index(test_prefix)
    forward_open = await host_forward_open()
    a = await policy.setup("vma", i, NetworkPolicy.parse("allow:ok.example"))
    b = await policy.setup("vmb", i + 1, NetworkPolicy.parse("allow:other.example"))
    try:
        async with Guest(f"{test_prefix}-ga", a.netns) as ga, Guest(f"{test_prefix}-gb", b.netns) as gb:
            # Before any lookup nothing is reachable.
            assert not await ga.http(ip_ok)
            assert await rule_packets(test_prefix, "f-vma", "ep-drop") >= 1

            # Allowed names resolve, through whatever server the guest asks.
            assert await ga.dig("ok.example") == ("NOERROR", [ip_ok])
            assert await gb.dig("other.example", server="1.1.1.1") == ("NOERROR", [ip_other])
            assert ip_ok in (await sh("nft", "list", "set", "inet", test_prefix, "a-vma")).stdout.decode()

            # Other names, including the other VM's, are NXDOMAIN.
            assert (await ga.dig("other.example"))[0] == "NXDOMAIN"
            assert (await gb.dig("ok.example"))[0] == "NXDOMAIN"
            assert (await ga.dig("evil.example"))[0] == "NXDOMAIN"

            # Each VM reaches only what it resolved.
            allowed_before = await rule_packets(test_prefix, "f-vma", "ep-allow")
            ok_a = await ga.http(ip_ok)
            assert await rule_packets(test_prefix, "f-vma", "ep-allow") > allowed_before
            if forward_open:
                assert ok_a
                assert await gb.http(ip_other)
            drop_b = await rule_packets(test_prefix, "f-vmb", "ep-drop")
            assert not await gb.http(ip_ok)
            assert not await ga.http(ip_other)
            assert await rule_packets(test_prefix, "f-vmb", "ep-drop") > drop_b

            # The guest cannot reach the host except the resolver.
            assert not await ga.http(f"10.200.{i}.1")
            assert await rule_packets(test_prefix, "i-vma", "ep-drop") >= 1

            events = await drain(policy)
            assert ("vma", "ok.example", (ip_ok,)) in events
            assert ("vmb", "other.example", (ip_other,)) in events
            assert ("vma", "other.example", None) in events
            assert ("vmb", "ok.example", None) in events
            assert ("vma", "evil.example", None) in events
            assert {e[0] for e in events} <= {"vma", "vmb"}
    finally:
        await policy.teardown(a)
        await policy.teardown(b)
    if not forward_open:
        pytest.skip("host FORWARD policy drops forwarded traffic; end-to-end connect not checked")


async def test_deny_policy_gets_nothing(
    policy: HostNetPolicy, server: tuple[str, str], test_prefix: str
) -> None:
    h = await policy.setup("vmd", base_index(test_prefix), NetworkPolicy())
    try:
        async with Guest(f"{test_prefix}-gd", h.netns) as g:
            assert (await g.dig("ok.example"))[0] == "NXDOMAIN"
            assert not await g.http(server[0])
            r = await sh("nft", "-j", "list", "set", "inet", test_prefix, "a-vmd")
            assert "elem" not in json.loads(r.stdout)["nftables"][1]["set"]
    finally:
        await policy.teardown(h)
