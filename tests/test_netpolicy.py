"""Unit tests for HostNetPolicy with a fake command runner. No root needed."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from emberpool._names import CommandError, CommandResult
from emberpool.engine import NetPolicy
from emberpool._types import IsolationError, NetHandle, NetworkPolicy
from emberpool.netpolicy import (
    DEFAULT_NFLOG_GROUP,
    LOG_PREFIX_ALLOWED,
    LOG_PREFIX_DROPPED,
    NFLOG_SNAPLEN,
    HostNetPolicy,
    log_prefix,
    parse_log_prefix,
)


@dataclass
class FakeHost:
    """Just enough of `ip`, `nft` and `sysctl` to drive HostNetPolicy."""

    fail_on: str | None = None  # fail the first command whose joined argv contains this
    netns: set[str] = field(default_factory=set)
    links: set[str] = field(default_factory=set)
    nft_docs: list[dict] = field(default_factory=list)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    delay: float = 0.0

    async def __call__(self, argv: Sequence[str], *, timeout: float, stdin: bytes | None = None,
                       check: bool = True) -> CommandResult:
        args = tuple(argv)
        self.calls.append(args)
        if self.delay:
            await asyncio.sleep(self.delay)
        line = " ".join(args)
        if self.fail_on is not None and self.fail_on in line:
            self.fail_on = None
            raise CommandError(CommandResult(args, 1, b"", b"injected failure"))

        def ok(out: bytes = b"") -> CommandResult:
            return CommandResult(args, 0, out, b"")

        if args[:2] == ("ip", "netns") and args[2:3] == ("exec",):
            args = args[4:]
        if args[0] == "nft":
            assert stdin is not None
            self.nft_docs.append(json.loads(stdin))
            return ok()
        if args[0] == "sysctl":
            return ok(b"1\n" if "-n" in args else b"")
        if args[:4] == ("ip", "-j", "-4", "addr"):
            return ok(b"[]")
        if args[:4] == ("ip", "-j", "netns", "list"):
            return ok(json.dumps([{"name": n} for n in self.netns]).encode())
        if args[:3] == ("ip", "netns", "add"):
            self.netns.add(args[3])
            return ok()
        if args[:3] == ("ip", "netns", "del"):
            self.netns.discard(args[3])
            return ok()
        if args[:3] == ("ip", "link", "add"):
            self.links.add(args[3])
            return ok()
        if args[:4] == ("ip", "-j", "link", "show"):
            return ok(json.dumps([{"ifindex": 17, "ifname": args[-1]}]).encode())
        if args[:3] == ("ip", "link", "show"):
            rc = 0 if args[-1] in self.links else 1
            return CommandResult(args, rc, b"", b"" if rc == 0 else b"Cannot find device")
        if args[:3] == ("ip", "link", "del"):
            self.links.discard(args[-1])
            return ok()
        return ok()

    def nft_text(self) -> str:
        return json.dumps(self.nft_docs)


def make(host: FakeHost, **kw: object) -> HostNetPolicy:
    return HostNetPolicy(prefix="ep-unit", table="ep-unit", runner=host, **kw)  # type: ignore[arg-type]


def test_log_prefix_format() -> None:
    assert DEFAULT_NFLOG_GROUP == 7 and NFLOG_SNAPLEN == 128
    assert log_prefix("allowed") == LOG_PREFIX_ALLOWED == "ep-allow"
    assert log_prefix("dropped") == LOG_PREFIX_DROPPED == "ep-drop"
    with pytest.raises(ValueError):
        log_prefix("maybe")  # type: ignore[arg-type]
    assert parse_log_prefix("ep-allow") == "allowed"
    assert parse_log_prefix(b"ep-drop\x00") == "dropped"
    assert parse_log_prefix("ep-dropx") is None
    assert parse_log_prefix(b"\xff") is None


def test_is_a_netpolicy() -> None:
    assert isinstance(make(FakeHost()), NetPolicy)


@pytest.mark.parametrize(
    "kw",
    [
        {"prefix": "bad"},
        {"prefix": "ep-toolong"},
        {"table": "nft table"},
        {"nflog_group": -1},
        {"nflog_group": True},
        {"tap_owner": (-1, 0)},
    ],
)
def test_constructor_validates(kw: dict[str, object]) -> None:
    args: dict[str, object] = {"prefix": "ep-unit", "table": "ep-unit", **kw}
    with pytest.raises(ValueError):
        HostNetPolicy(**args)  # type: ignore[arg-type]


async def test_setup_and_teardown() -> None:
    host = FakeHost()
    p = make(host)
    h = await p.setup("vm1", 5, NetworkPolicy.parse("allow:ok.example"))
    assert h == NetHandle("vm1", 5, "ep-unit-vm1", "ep-unit-h5")
    assert host.netns == {"ep-unit-vm1"} and host.links == {"ep-unit-h5"}
    # Policy is installed before the namespace or veth exist.
    first_nft = next(i for i, c in enumerate(host.calls) if c[0] == "nft" and i > 1)
    first_ns = next(i for i, c in enumerate(host.calls) if c[:3] == ("ip", "netns", "add"))
    assert first_nft < first_ns
    # The host end comes up last, after resolver registration.
    assert host.calls[-1] == ("ip", "link", "set", "ep-unit-h5", "up")
    assert p._resolver.identify("10.200.5.2", 17) is not None

    await p.teardown(h)
    assert host.netns == set() and host.links == set()
    assert p._resolver.identify("10.200.5.2", 17) is None
    await p.teardown(h)  # idempotent
    await p.close()
    assert '"destroy": {"table"' in host.nft_text()


async def test_ruleset_logs_every_verdict_with_shared_format() -> None:
    host = FakeHost()
    p = make(host)
    await p.setup("vm1", 5, NetworkPolicy())
    vm_doc = next(d for d in host.nft_docs if "a-vm1" in json.dumps(d))
    rules = [c["add"]["rule"] for c in vm_doc["nftables"] if "rule" in c.get("add", {})]
    for rule in rules:
        verdicts = [k for e in rule["expr"] for k in e if k in ("accept", "drop")]
        logs = [e["log"] for e in rule["expr"] if "log" in e]
        if "drop" in verdicts:
            assert logs == [{"prefix": "ep-drop", "group": 7, "snaplen": 128}]
    fwd = [r for r in rules if r["chain"] == "f-vm1"]
    assert fwd[-1]["expr"][-1] == {"drop": None}  # default drop
    assert any(e.get("log", {}).get("prefix") == "ep-allow" for r in fwd for e in r["expr"])
    elems = [c["add"]["element"] for c in vm_doc["nftables"] if "element" in c.get("add", {})]
    assert {"name": "fwd_vmap", "elem": [["ep-unit-h5", {"jump": {"target": "f-vm1"}}]]}.items() <= elems[0].items()
    await p.close()


SETUP_STEPS = [
    "nft -j -f -",  # root table (start)
    "ip -j -4 addr show",
    "ip netns add",
    "tuntap add",
    "address 02:ee",
    "type veth",
    "addr add 10.200.5.1/30",
    "route add default",
    "net.ipv4.ip_forward=1",
    "ip -j link show",
    "link set ep-unit-h5 up",
]


@pytest.mark.parametrize("step", SETUP_STEPS)
async def test_setup_fails_closed_at_every_step(step: str) -> None:
    host = FakeHost(fail_on=step)
    p = make(host)
    with pytest.raises(IsolationError):
        await p.setup("vm1", 5, NetworkPolicy.parse("allow:ok.example"))
    assert host.netns == set() and host.links == set()
    assert p._handles == {}
    assert p._resolver.identify("10.200.5.2", 17) is None
    # A later setup on the same index works.
    host.fail_on = None
    h = await p.setup("vm2", 5, NetworkPolicy())
    await p.teardown(h)
    await p.close()


async def test_vm_rule_install_failure_installs_nothing_else() -> None:
    host = FakeHost()
    p = make(host)
    await p.start()
    host.fail_on = "nft -j -f -"  # the per-VM transaction
    with pytest.raises(IsolationError):
        await p.setup("vm1", 5, NetworkPolicy())
    assert not any(c[:3] == ("ip", "netns", "add") for c in host.calls)
    await p.close()


async def test_duplicate_index_and_vm_id_rejected() -> None:
    host = FakeHost()
    p = make(host)
    h = await p.setup("vm1", 5, NetworkPolicy())
    with pytest.raises(IsolationError):
        await p.setup("vm2", 5, NetworkPolicy())
    with pytest.raises(IsolationError):
        await p.setup("vm1", 6, NetworkPolicy())
    assert p._handles == {"vm1": h}
    await p.close()


@pytest.mark.parametrize("bad", [("BAD", 1), ("vm1", 256), ("vm1", -1), ("a" * 40, 1)])
async def test_setup_validates_before_touching_host(bad: tuple[str, int]) -> None:
    host = FakeHost()
    p = make(host)
    with pytest.raises(ValueError):
        await p.setup(bad[0], bad[1], NetworkPolicy())
    assert host.calls == []


async def test_start_failure_raises_isolation_error() -> None:
    host = FakeHost(fail_on="nft")
    p = make(host)
    with pytest.raises(IsolationError):
        await p.start()
    await p.close()
    assert not any("destroy" in json.dumps(d) for d in host.nft_docs)  # never removes a table it did not create


async def test_teardown_failure_is_reported_but_other_steps_run() -> None:
    host = FakeHost()
    p = make(host)
    h = await p.setup("vm1", 5, NetworkPolicy())
    host.fail_on = "ip netns del"
    with pytest.raises(IsolationError):
        await p.teardown(h)
    assert host.links == set()  # veth still removed
    assert any("f-vm1" in json.dumps(d) and "destroy" in json.dumps(d) for d in host.nft_docs)
    await p.teardown(h)  # retry succeeds
    assert host.netns == set()
    await p.close()


async def test_teardown_survives_cancellation() -> None:
    host = FakeHost()
    p = make(host)
    h = await p.setup("vm1", 5, NetworkPolicy())
    host.delay = 0.01
    task = asyncio.create_task(p.teardown(h))
    await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert host.netns == set() and host.links == set()
    await p.close()


async def test_setup_cancelled_cleans_up() -> None:
    host = FakeHost(delay=0.01)
    p = make(host)
    task = asyncio.create_task(p.setup("vm1", 5, NetworkPolicy()))
    await asyncio.sleep(0.08)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert host.netns == set() and host.links == set() and p._handles == {}
    await p.close()


async def test_close_tears_down_everything() -> None:
    host = FakeHost()
    p = make(host)
    await p.setup("vm1", 5, NetworkPolicy())
    await p.setup("vm2", 6, NetworkPolicy())
    await p.close()
    assert host.netns == set() and host.links == set()
    with pytest.raises(IsolationError):
        await p.setup("vm3", 7, NetworkPolicy())
    await p.close()


async def test_template_netns_removed_on_exit_and_error() -> None:
    host = FakeHost()
    p = make(host)
    async with p.template_netns() as ns:
        assert ns in host.netns and ns.startswith("ep-unit-tmpl-")
    assert host.netns == set()
    with pytest.raises(RuntimeError):
        async with p.template_netns():
            raise RuntimeError("boom")
    assert host.netns == set()
    host.fail_on = "tuntap"
    with pytest.raises(IsolationError):
        async with p.template_netns():
            pass
    assert host.netns == set()
    await p.close()


async def test_events_yield_resolver_events() -> None:
    from emberpool._types import DnsEvent

    p = make(FakeHost())
    ev = DnsEvent(1.0, "vm1", "ok.example", None)
    p._emit(ev)
    assert await anext(p.events()) is ev


async def test_event_queue_overflow_is_counted() -> None:
    from emberpool._types import DnsEvent

    p = make(FakeHost(), max_events=1)
    p._emit(DnsEvent(1.0, "vm1", "a.example", None))
    p._emit(DnsEvent(1.0, "vm1", "b.example", None))
    assert p.dropped_events == 1
