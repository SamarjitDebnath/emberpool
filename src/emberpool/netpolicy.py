"""Per-VM network namespaces, the host nftables table and the shared resolver.

Layout (docs/30-decisions.md, docs/10-setup.md):

    guest ── tap0 ─┬─ netns <prefix>-<vm_id> ─ ep-up ══ veth ══ <prefix>-hN ── host
                   │  172.16.0.1/30              10.200.N.2       10.200.N.1
                   │  udp/53 from the guest  ->  DNAT to the resolver on 10.200.N.1
                   │  everything else        ->  masquerade out ep-up
                   └─ nothing else is forwarded; the namespace itself accepts nothing

All policy is in one table in the root namespace (`inet <table>`):

- `forward` and `input` base chains dispatch on the input interface through
  the verdict maps `fwd_vmap` and `in_vmap` to per-VM chains `f-<vm_id>` and
  `i-<vm_id>`. A packet from an emberpool uplink with no entry is dropped.
- `f-<vm_id>`: IPv4 only, source must be 10.200.N.2, replies pass, new flows
  to addresses in the set `a-<vm_id>` are logged and accepted, everything
  else is logged and dropped.
- `i-<vm_id>`: only DNS to the resolver on 10.200.N.1; everything else to the
  host is logged and dropped.
- `postrouting` masquerades the uplink addresses in `nat_src`.

The set, chains and map entries for a VM are installed in one nft
transaction before its veth exists, so the uplink is never up without its
policy. Rulesets are sent as nft JSON built from validated values only
(docs/40-rules.md rules 8 and 9); no text is interpolated into rule syntax.

Connection verdicts are logged to NFLOG group `nflog_group` (default 7) with
prefix "ep-allow" or "ep-drop" and snaplen 128, the format the trace stream
reads. The trace stream turns them into ConnEvents by input interface.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal

from emberpool._names import (
    CommandResult,
    run_command,
    validate_interface,
    validate_netns,
    validate_nft_set,
    validate_nft_table,
    validate_vm_id,
)
from emberpool._resolver import Lookup, Resolver, ResolverClient
from emberpool._types import (
    TAP_HOST_CIDR,
    TAP_MAC,
    TAP_NAME,
    ConnEvent,
    DnsEvent,
    IsolationError,
    NetHandle,
    NetworkPolicy,
    uplink_host_ip,
    uplink_ns_ip,
    uplink_subnet,
)

__all__ = [
    "DEFAULT_TABLE",
    "DEFAULT_NFLOG_GROUP",
    "NFLOG_SNAPLEN",
    "LOG_PREFIX_ALLOWED",
    "LOG_PREFIX_DROPPED",
    "UPLINK_NS_NAME",
    "log_prefix",
    "parse_log_prefix",
    "HostNetPolicy",
    "forward_blockers",
    "forward_block_message",
]

log = logging.getLogger(__name__)

DEFAULT_TABLE = "emberpool"

# Connection-verdict log format, shared with the trace stream (trace.py).
# Every verdict rule sits in a per-VM chain reached only through the iifname
# verdict maps, so each logged packet's input interface is the VM's host-side
# veth (NetHandle.veth_host); the trace stream attributes packets by that
# interface index. The prefix carries only the verdict, never guest data.
DEFAULT_NFLOG_GROUP = 7
NFLOG_SNAPLEN = 128
LOG_PREFIX_ALLOWED = "ep-allow"
LOG_PREFIX_DROPPED = "ep-drop"

# Namespace end of the uplink veth. It only ever exists inside a VM namespace.
UPLINK_NS_NAME = "ep-up"
# nftables table inside each VM namespace (its own namespace, so a fixed name).
_NS_TABLE = "emberpool"
_DNS_PORT = 53
# Everything the uplinks can use; the resolver and table never touch more.
_UPLINK_SPACE = "10.200.0.0/16"
_BASE_PRIO = -10  # before the default filter priority, so our drop is final

Verdict = Literal["allowed", "dropped"]
Runner = Callable[..., Awaitable[CommandResult]]


def log_prefix(verdict: Verdict) -> str:
    """The NFLOG prefix for a verdict."""
    if verdict == "allowed":
        return LOG_PREFIX_ALLOWED
    if verdict == "dropped":
        return LOG_PREFIX_DROPPED
    raise ValueError(f"invalid verdict: {verdict!r}")


def parse_log_prefix(prefix: str | bytes) -> Verdict | None:
    """The verdict from an NFLOG prefix, or None if it is not ours. Tolerates
    the trailing NUL the kernel may include."""
    if isinstance(prefix, bytes):
        prefix = prefix.rstrip(b"\x00").decode("ascii", "replace")
    prefix = prefix.rstrip("\x00")
    if prefix == LOG_PREFIX_ALLOWED:
        return "allowed"
    if prefix == LOG_PREFIX_DROPPED:
        return "dropped"
    return None


# --------------------------------------------------------------------------
# Other firewalls on the forward path
# --------------------------------------------------------------------------

# Families whose forward hook sees the guests' (IPv4-only) traffic.
_FORWARD_FAMILIES = ("ip", "inet")
_MAX_RULESET_BYTES = 16 << 20


def _strip_counters(expr: list[Any]) -> list[Any]:
    return [e for e in expr if not (isinstance(e, dict) and set(e) == {"counter"})]


def _covers_uplinks(pattern: object, prefix: str) -> bool:
    """True if an interface-name match `pattern` matches every `<prefix>-hN`."""
    if not isinstance(pattern, str):
        return False
    if pattern.endswith("*"):
        return f"{prefix}-h".startswith(pattern[:-1])
    return False


def _ifname_match(e: object, key: str, prefix: str) -> bool:
    if not isinstance(e, dict) or set(e) != {"match"}:
        return False
    m = e["match"]
    return (
        isinstance(m, dict)
        and m.get("op") == "=="
        and m.get("left") == {"meta": {"key": key}}
        and _covers_uplinks(m.get("right"), prefix)
    )


def _ct_established(e: object) -> bool:
    if not isinstance(e, dict) or set(e) != {"match"}:
        return False
    m = e["match"]
    if not isinstance(m, dict) or m.get("left") != {"ct": {"key": "state"}}:
        return False
    right = m.get("right")
    states = {right} if isinstance(right, str) else set(right) if isinstance(right, list) else set()
    return m.get("op") in ("==", "in") and bool(states) and states <= {"established", "related"}


def _uplink_accept(expr: list[Any], prefix: str) -> str | None:
    """"in" or "out" if the rule is exactly an accept of all traffic from
    (or, optionally only replies, to) emberpool uplinks; None otherwise."""
    body = _strip_counters(expr)
    if not body or body[-1] != {"accept": None}:
        return None
    conds = body[:-1]
    if len(conds) == 1 and _ifname_match(conds[0], "iifname", prefix):
        return "in"
    outs = [c for c in conds if _ifname_match(c, "oifname", prefix)]
    if len(outs) == 1 and all(c is outs[0] or _ct_established(c) for c in conds) and len(conds) <= 2:
        return "out"
    return None


_VERDICT_KEYS = frozenset({"accept", "drop", "reject", "queue", "jump", "goto", "return", "continue"})


def _only_accepts(expr: list[Any]) -> bool:
    """True if the rule can only accept (whatever it matches): it ends in
    accept and has no other verdict or target. Such a rule can never drop
    uplink traffic, so it may stand before emberpool's exemption."""
    body = _strip_counters(expr)
    if not body or body[-1] != {"accept": None}:
        return False
    for e in body[:-1]:
        if not isinstance(e, dict) or _VERDICT_KEYS & set(e):
            return False
        xt = e.get("xt")
        if xt is not None and not (isinstance(xt, dict) and xt.get("type") == "match"):
            return False
    return True


def _is_unconditional(expr: list[Any]) -> bool:
    return all(isinstance(e, dict) and not ({"match", "xt"} & set(e)) for e in expr)


def _accepts_uplinks(
    rules: dict[tuple[str, str, str], list[list[Any]]], family: str, table: str, chain: str, prefix: str
) -> bool:
    """Conservatively decide whether base chain `chain` accepts traffic from
    and back to emberpool uplinks before anything else can drop it.

    Recognised: the base chain starts with unconditional jumps to regular
    chains, and one of those begins with (counted) accept rules for
    `iifname "<prefix>-h*"` and `oifname "<prefix>-h*"` (optionally limited
    to established/related), with nothing but accept-only rules before them. Anything else, including
    iptables `xt` matches whose content nft cannot show, is not recognised."""
    for expr in rules.get((family, table, chain), []):
        body = _strip_counters(expr)
        if len(body) == 1 and isinstance(body[0], dict) and "jump" in body[0]:
            target = body[0]["jump"].get("target") if isinstance(body[0]["jump"], dict) else None
            seen: set[str] = set()
            for sub in rules.get((family, table, str(target)), []):
                kind = _uplink_accept(sub, prefix)
                if kind is None:
                    if _only_accepts(sub):
                        continue  # e.g. another prefix's exemption; cannot drop ours
                    break
                seen.add(kind)
                if seen == {"in", "out"}:
                    return True
            if seen:
                return False  # partial exemption followed by something else
            sub_rules = rules.get((family, table, str(target)), [])
            if sub_rules and not (
                len(sub_rules) == 1 and _strip_counters(sub_rules[0]) == [{"return": None}]
            ):
                return False  # the jumped-to chain may itself drop
            continue
        return False
    return False


def forward_blockers(ruleset: object, prefix: str, own_table: str) -> list[str]:
    """Base chains in other tables that would drop VM traffic our table
    accepts: a forward-hook chain (ip or inet) whose policy is drop, or whose
    last rule is an unconditional drop or reject, unless it is recognisably
    exempting emberpool uplinks. Input is `nft -j list ruleset` output.
    Raises ValueError if the input is not shaped like that."""
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        raise ValueError("not nft JSON ruleset output")
    chains: list[dict[str, Any]] = []
    rules: dict[tuple[str, str, str], list[list[Any]]] = {}
    for item in ruleset["nftables"]:
        if not isinstance(item, dict):
            raise ValueError("unexpected item in nft JSON ruleset")
        if isinstance(item.get("chain"), dict):
            chains.append(item["chain"])
        elif isinstance(item.get("rule"), dict):
            r = item["rule"]
            expr = r.get("expr")
            if not isinstance(expr, list):
                raise ValueError("nft rule without expressions")
            rules.setdefault((str(r.get("family")), str(r.get("table")), str(r.get("chain"))), []).append(expr)
    found: list[str] = []
    for c in chains:
        family, table, name = str(c.get("family")), str(c.get("table")), str(c.get("name"))
        if c.get("hook") != "forward" or family not in _FORWARD_FAMILIES:
            continue
        if family == "inet" and table == own_table:
            continue
        chain_rules = rules.get((family, table, name), [])
        last = chain_rules[-1] if chain_rules else []
        final_drop = bool(last) and _is_unconditional(last) and any(
            isinstance(e, dict) and ("drop" in e or "reject" in e) for e in last
        )
        if c.get("policy") != "drop" and not final_drop:
            continue
        if _accepts_uplinks(rules, family, table, name, prefix):
            continue
        how = "policy drop" if c.get("policy") == "drop" else "final drop rule"
        found.append(f"{family} {table} {name} ({how})")
    return found


def forward_block_message(blockers: list[str], prefix: str) -> str:
    uplinks = f"{prefix}-h+"
    return (
        "another firewall would drop forwarded sandbox traffic: "
        + ", ".join(blockers)
        + ". emberpool's table cannot override a drop in another table, and it will not"
        " change rules it does not own. Exempt the emberpool uplinks first. With Docker:"
        f" iptables -I DOCKER-USER -i {uplinks} -j ACCEPT;"
        f" iptables -I DOCKER-USER -o {uplinks} -j ACCEPT"
        " (emberpool's own table still drops new connections into sandboxes)."
        " Otherwise add equivalent accept rules for those interfaces at the start of each listed chain."
    )


# --------------------------------------------------------------------------
# nft JSON building blocks. Every string that reaches these is a validated
# name, a fixed keyword, or an address produced by ipaddress.
# --------------------------------------------------------------------------


def _meta(key: str) -> dict[str, Any]:
    return {"meta": {"key": key}}


def _payload(proto: str, fld: str) -> dict[str, Any]:
    return {"payload": {"protocol": proto, "field": fld}}


def _match(left: Any, right: Any, op: str = "==") -> dict[str, Any]:
    return {"match": {"op": op, "left": left, "right": right}}


def _ct_state(*states: str) -> dict[str, Any]:
    return _match({"ct": {"key": "state"}}, list(states), "in")


def _log(group: int, verdict: Verdict) -> dict[str, Any]:
    return {"log": {"prefix": log_prefix(verdict), "group": group, "snaplen": NFLOG_SNAPLEN}}


_COUNTER: dict[str, Any] = {"counter": None}
_ACCEPT: dict[str, Any] = {"accept": None}
_DROP: dict[str, Any] = {"drop": None}


def _ip(addr: str) -> str:
    return str(ipaddress.IPv4Address(addr))


def _net(net: str) -> dict[str, Any]:
    n = ipaddress.IPv4Network(net)
    return {"prefix": {"addr": str(n.network_address), "len": n.prefixlen}}


@dataclass(frozen=True, slots=True)
class _VmNames:
    vm_id: str
    index: int
    netns: str
    veth_host: str
    allow_set: str
    fwd_chain: str
    in_chain: str


class HostNetPolicy:
    """The real NetPolicy: network namespaces, nftables and the DNS resolver.

    Use as an async context manager (or call start() and close()). setup()
    starts it on first use. close() tears down every VM it still holds,
    removes its nftables table and stops the resolver.

    prefix:       start of every namespace and interface name (default "ep").
    table:        name of the root-namespace nftables table.
    nflog_group:  NFLOG group for connection verdicts.
    lookup:       upstream lookup for the resolver (default: dnspython with the
                  host's resolv.conf).
    tap_owner:    (uid, gid) to own tap0, for a jailed Firecracker that has
                  dropped privileges before opening it.
    runner:       command runner, for tests (default: run_command).
    """

    def __init__(
        self,
        *,
        prefix: str = "ep",
        table: str = DEFAULT_TABLE,
        nflog_group: int = DEFAULT_NFLOG_GROUP,
        lookup: Lookup | None = None,
        tap_owner: tuple[int, int] | None = None,
        runner: Runner | None = None,
        command_timeout: float = 10.0,
        max_events: int = 65536,
    ) -> None:
        # The prefix is not a name itself; check the longest names built from it.
        if not isinstance(prefix, str):
            raise ValueError(f"prefix must be a str: {prefix!r}")
        validate_netns(f"{prefix}-0")
        validate_interface(f"{prefix}-h255")
        if len(prefix) > 8:
            raise ValueError("prefix must be at most 8 chars (interface names cap at 15)")
        if isinstance(nflog_group, bool) or not isinstance(nflog_group, int) or not 0 <= nflog_group <= 65535:
            raise ValueError(f"nflog_group must be an int in 0..65535: {nflog_group!r}")
        if tap_owner is not None:
            uid, gid = tap_owner
            for v in (uid, gid):
                if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                    raise ValueError(f"invalid tap owner: {tap_owner!r}")
        self.prefix = prefix
        self.table = validate_nft_table(table)
        self.nflog_group = nflog_group
        self._tap_owner = tap_owner
        self._runner: Runner = runner if runner is not None else run_command
        self._timeout = command_timeout
        self._events: asyncio.Queue[DnsEvent | ConnEvent] = asyncio.Queue(max_events)
        self.dropped_events = 0
        self._resolver = Resolver(self._emit, lookup=lookup)
        self._handles: dict[str, NetHandle] = {}
        self._templates: set[str] = set()
        self._lock = asyncio.Lock()
        self._started = False
        self._closed = False

    # -- lifecycle -----------------------------------------------------------

    async def __aenter__(self) -> HostNetPolicy:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @property
    def resolver_port(self) -> int:
        return self._resolver.port

    async def start(self) -> None:
        """Create the root table and start the resolver. Fails closed: if the
        table already exists (another instance, or a stale one) it is left
        alone and IsolationError is raised."""
        async with self._lock:
            if self._closed:
                raise IsolationError("HostNetPolicy is closed")
            if self._started:
                return
            # Read-only check first: nothing is created if it fails.
            await self._check_forward_path()
            try:
                await self._ensure_ip_forward()
                await self._nft(self._root_table_ruleset())
            except Exception as e:
                raise IsolationError(f"could not create nftables table {self.table}: {e}") from e
            try:
                await self._resolver.start("0.0.0.0", 0)
            except Exception as e:
                await _shielded(self._destroy_table())
                raise IsolationError(f"could not start DNS resolver: {e}") from e
            self._started = True

    async def close(self) -> None:
        """Tear down every VM and template namespace, remove the table, stop
        the resolver. Idempotent; raises IsolationError at the end if any
        resource could not be removed."""
        await _shielded(self._close())

    async def _close(self) -> None:
        async with self._lock:
            self._closed = True
            errors: list[str] = []
            for handle in list(self._handles.values()):
                try:
                    await self._teardown(handle)
                except Exception as e:
                    errors.append(str(e))
            for ns in list(self._templates):
                try:
                    await self._del_netns(ns)
                    self._templates.discard(ns)
                except Exception as e:
                    errors.append(str(e))
            await self._resolver.close()
            if self._started:
                try:
                    await self._destroy_table()
                except Exception as e:
                    errors.append(str(e))
                self._started = False
            if errors:
                raise IsolationError("net cleanup incomplete: " + "; ".join(errors))

    # -- NetPolicy protocol ----------------------------------------------------

    async def setup(self, vm_id: str, index: int, policy: NetworkPolicy) -> NetHandle:
        """Create the VM's namespace, uplink, DNS forward and allow set.
        Fails closed: on any error everything created is removed and
        IsolationError propagates."""
        if not isinstance(policy, NetworkPolicy):
            raise TypeError("policy must be a NetworkPolicy")
        names = self._names(vm_id, index)
        await self.start()
        async with self._lock:
            if self._closed:
                raise IsolationError("HostNetPolicy is closed")
            if vm_id in self._handles:
                raise IsolationError(f"vm_id already set up: {vm_id}")
            if any(h.index == index for h in self._handles.values()):
                raise IsolationError(f"uplink index already in use: {index}")
            handle = NetHandle(vm_id, index, names.netns, names.veth_host)
            self._handles[vm_id] = handle
        try:
            await self._setup(names, policy)
        except BaseException as e:
            try:
                await _shielded(self._teardown(handle))
            except Exception as te:
                log.error("cleanup after failed setup of %s incomplete: %s", vm_id, te)
            if isinstance(e, Exception) and not isinstance(e, IsolationError):
                raise IsolationError(f"network setup for {vm_id} failed: {e}") from e
            raise
        return handle

    async def teardown(self, handle: NetHandle) -> None:
        """Remove the VM's namespace, veth, allow set and rules. Idempotent and
        completes even if the caller is cancelled."""
        await _shielded(self._teardown(handle))

    def template_netns(self) -> AbstractAsyncContextManager[str]:
        """A namespace with tap0 (TAP_MAC, 172.16.0.1/30) and no uplink, for
        building the template VM. Removed on exit, also after errors."""
        return self._template_netns()

    async def events(self) -> AsyncIterator[DnsEvent | ConnEvent]:
        """DnsEvents from the resolver, in arrival order. ConnEvents come from
        the trace stream reading NFLOG group `nflog_group`."""
        while True:
            yield await self._events.get()

    # -- internals -------------------------------------------------------------

    def _emit(self, event: DnsEvent | ConnEvent) -> None:
        try:
            self._events.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped_events += 1
            log.error("event queue full; dropped %s event for %s", type(event).__name__, event.vm_id)

    def _names(self, vm_id: str, index: int) -> _VmNames:
        validate_vm_id(vm_id)
        uplink_subnet(index)  # range check
        return _VmNames(
            vm_id=vm_id,
            index=index,
            netns=validate_netns(f"{self.prefix}-{vm_id}"),
            veth_host=validate_interface(f"{self.prefix}-h{index}"),
            allow_set=validate_nft_set(f"a-{vm_id}"),
            fwd_chain=validate_nft_set(f"f-{vm_id}"),
            in_chain=validate_nft_set(f"i-{vm_id}"),
        )

    async def _run(self, argv: Sequence[str], *, stdin: bytes | None = None, check: bool = True) -> CommandResult:
        return await self._runner(list(argv), timeout=self._timeout, stdin=stdin, check=check)

    async def _nft(self, commands: list[dict[str, Any]], netns: str | None = None) -> None:
        doc = json.dumps({"nftables": commands}, allow_nan=False).encode()
        argv = ["nft", "-j", "-f", "-"]
        if netns is not None:
            argv = ["ip", "netns", "exec", validate_netns(netns), *argv]
        await self._run(argv, stdin=doc)

    async def _check_forward_path(self) -> None:
        """Fail closed if another table would drop forwarded VM traffic."""
        try:
            r = await self._runner(
                ["nft", "-j", "list", "ruleset"], timeout=self._timeout, max_output=_MAX_RULESET_BYTES
            )
            if r.stdout_truncated:
                raise ValueError("ruleset too large to inspect")
            blockers = forward_blockers(json.loads(r.stdout), self.prefix, self.table)
        except Exception as e:
            raise IsolationError(f"could not inspect the host firewall: {e}") from e
        if blockers:
            raise IsolationError(forward_block_message(blockers, self.prefix))

    async def _ensure_ip_forward(self) -> None:
        r = await self._run(["sysctl", "-n", "net.ipv4.ip_forward"])
        if r.stdout.strip() != b"1":
            await self._run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])

    async def _check_subnet_free(self, index: int) -> None:
        subnet = uplink_subnet(index)
        r = await self._run(["ip", "-j", "-4", "addr", "show"])
        for link in json.loads(r.stdout or b"[]"):
            for info in link.get("addr_info", []):
                local = info.get("local")
                if local and ipaddress.ip_address(local) in subnet:
                    raise IsolationError(f"uplink subnet {subnet} already in use on {link.get('ifname')!r}")

    async def _ifindex(self, ifname: str) -> int:
        r = await self._run(["ip", "-j", "link", "show", "dev", validate_interface(ifname)])
        data = json.loads(r.stdout)
        if not isinstance(data, list) or len(data) != 1:
            raise IsolationError(f"unexpected ip link output for {ifname}")
        idx = data[0].get("ifindex")
        if isinstance(idx, bool) or not isinstance(idx, int) or idx <= 0:
            raise IsolationError(f"no ifindex for {ifname}")
        return idx

    async def _setup(self, n: _VmNames, policy: NetworkPolicy) -> None:
        await self._check_subnet_free(n.index)
        # 1. Policy first: the uplink never exists without it.
        await self._nft(self._vm_ruleset(n))
        # 2. Namespace with tap0 and the uplink.
        await self._run(["ip", "netns", "add", n.netns])
        await self._make_ns_base(n.netns)
        await self._run(
            ["ip", "link", "add", n.veth_host, "type", "veth", "peer", "name", UPLINK_NS_NAME, "netns", n.netns]
        )
        subnet = uplink_subnet(n.index)
        host_ip, ns_ip = uplink_host_ip(n.index), uplink_ns_ip(n.index)
        await self._run(["ip", "addr", "add", f"{host_ip}/{subnet.prefixlen}", "dev", n.veth_host])
        await self._run(["ip", "-n", n.netns, "addr", "add", f"{ns_ip}/{subnet.prefixlen}", "dev", UPLINK_NS_NAME])
        await self._run(["ip", "-n", n.netns, "link", "set", UPLINK_NS_NAME, "up"])
        await self._run(["ip", "-n", n.netns, "route", "add", "default", "via", host_ip])
        await self._run(["ip", "netns", "exec", n.netns, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        # 3. In-namespace DNAT and masquerade.
        await self._nft(self._ns_ruleset(n.index, self._resolver.port), netns=n.netns)
        # 4. Resolver registration, then bring the host end up.
        ifindex = await self._ifindex(n.veth_host)
        self._resolver.register(
            ResolverClient(n.vm_id, n.index, ifindex, frozenset(policy.allow), self._set_adder(n))
        )
        await self._run(["ip", "link", "set", n.veth_host, "up"])

    async def _make_ns_base(self, netns: str) -> None:
        """lo up, IPv6 off, tap0 with the fixed MAC and host address."""
        ns = validate_netns(netns)
        for key in ("net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1"):
            await self._run(["ip", "netns", "exec", ns, "sysctl", "-q", "-w", key])
        await self._run(["ip", "-n", ns, "link", "set", "lo", "up"])
        tap = ["ip", "-n", ns, "tuntap", "add", "dev", TAP_NAME, "mode", "tap"]
        if self._tap_owner is not None:
            tap += ["user", str(self._tap_owner[0]), "group", str(self._tap_owner[1])]
        await self._run(tap)
        await self._run(["ip", "-n", ns, "link", "set", TAP_NAME, "address", TAP_MAC])
        await self._run(["ip", "-n", ns, "addr", "add", TAP_HOST_CIDR, "dev", TAP_NAME])
        await self._run(["ip", "-n", ns, "link", "set", TAP_NAME, "up"])

    def _set_adder(self, n: _VmNames) -> Callable[[tuple[str, ...]], Awaitable[None]]:
        async def add(ips: tuple[str, ...]) -> None:
            elems = [_ip(ip) for ip in ips]
            await self._nft(
                [{"add": {"element": {"family": "inet", "table": self.table, "name": n.allow_set, "elem": elems}}}]
            )

        return add

    async def _teardown(self, handle: NetHandle) -> None:
        n = self._names(handle.vm_id, handle.index)
        if handle.netns != n.netns or handle.veth_host != n.veth_host:
            raise ValueError(f"handle does not belong to this NetPolicy: {handle!r}")
        self._resolver.unregister(n.index, n.vm_id)
        errors: list[str] = []
        for step in (self._del_netns(n.netns), self._del_link(n.veth_host), self._destroy_vm_rules(n)):
            try:
                await step
            except Exception as e:
                errors.append(f"{type(e).__name__}: {e}")
        if errors:
            raise IsolationError(f"teardown of {n.vm_id} incomplete: " + "; ".join(errors))
        if self._handles.get(n.vm_id) == handle:
            del self._handles[n.vm_id]

    async def _netns_exists(self, netns: str) -> bool:
        r = await self._run(["ip", "-j", "netns", "list"])
        names = {e.get("name") for e in json.loads(r.stdout or b"[]")}
        return validate_netns(netns) in names

    async def _del_netns(self, netns: str) -> None:
        if await self._netns_exists(netns):
            await self._run(["ip", "netns", "del", netns])

    async def _link_exists(self, ifname: str) -> bool:
        r = await self._run(["ip", "link", "show", "dev", validate_interface(ifname)], check=False)
        return r.returncode == 0

    async def _del_link(self, ifname: str) -> None:
        """Delete a host-side veth. Deleting its namespace removes it
        asynchronously, so a concurrent disappearance is not an error."""
        if not await self._link_exists(ifname):
            return
        r = await self._run(["ip", "link", "del", "dev", ifname], check=False)
        if r.returncode != 0 and await self._link_exists(ifname):
            raise IsolationError(f"could not delete {ifname}: {r.stderr[-300:].decode('utf-8', 'replace')}")

    async def _destroy_vm_rules(self, n: _VmNames) -> None:
        if not self._started:
            return
        t = {"family": "inet", "table": self.table}
        await self._nft(
            [
                {"destroy": {"element": {**t, "name": "fwd_vmap", "elem": [n.veth_host]}}},
                {"destroy": {"element": {**t, "name": "in_vmap", "elem": [n.veth_host]}}},
                {"destroy": {"element": {**t, "name": "nat_src", "elem": [uplink_ns_ip(n.index)]}}},
                {"destroy": {"chain": {**t, "name": n.fwd_chain}}},
                {"destroy": {"chain": {**t, "name": n.in_chain}}},
                {"destroy": {"set": {**t, "name": n.allow_set}}},
            ]
        )

    async def _destroy_table(self) -> None:
        await self._nft([{"destroy": {"table": {"family": "inet", "name": self.table}}}])

    @asynccontextmanager
    async def _template_netns(self) -> AsyncIterator[str]:
        await self.start()
        ns = validate_netns(f"{self.prefix}-tmpl-{secrets.token_hex(3)}")
        self._templates.add(ns)
        try:
            await self._run(["ip", "netns", "add", ns])
            await self._make_ns_base(ns)
            # No uplink, so no egress; drop anything forwarded regardless.
            await self._nft(self._ns_template_ruleset(), netns=ns)
        except BaseException as e:
            await _shielded(self._del_netns(ns))
            self._templates.discard(ns)
            if isinstance(e, Exception) and not isinstance(e, IsolationError):
                raise IsolationError(f"template namespace setup failed: {e}") from e
            raise
        try:
            yield ns
        finally:
            await _shielded(self._del_netns(ns))
            self._templates.discard(ns)

    # -- rulesets --------------------------------------------------------------

    def _root_table_ruleset(self) -> list[dict[str, Any]]:
        t = {"family": "inet", "table": self.table}
        uplinks = f"{self.prefix}-h*"
        return [
            # create: a table of this name must not exist yet; fail rather than share it.
            {"create": {"table": {"family": "inet", "name": self.table}}},
            {"add": {"map": {**t, "name": "fwd_vmap", "type": "ifname", "map": "verdict"}}},
            {"add": {"map": {**t, "name": "in_vmap", "type": "ifname", "map": "verdict"}}},
            {"add": {"set": {**t, "name": "nat_src", "type": "ipv4_addr"}}},
            {"add": {"chain": {**t, "name": "forward", "type": "filter", "hook": "forward",
                               "prio": _BASE_PRIO, "policy": "accept"}}},
            {"add": {"chain": {**t, "name": "input", "type": "filter", "hook": "input",
                               "prio": _BASE_PRIO, "policy": "accept"}}},
            {"add": {"chain": {**t, "name": "postrouting", "type": "nat", "hook": "postrouting",
                               "prio": 100, "policy": "accept"}}},
            {"add": {"rule": {**t, "chain": "forward", "expr": [
                {"vmap": {"key": _meta("iifname"), "data": "@fwd_vmap"}}]}}},
            {"add": {"rule": {**t, "chain": "forward", "expr": [
                _match(_meta("iifname"), uplinks), _COUNTER, _DROP]}}},
            # Into a VM: replies only.
            {"add": {"rule": {**t, "chain": "forward", "expr": [
                _match(_meta("oifname"), uplinks), _ct_state("established", "related"), _ACCEPT]}}},
            {"add": {"rule": {**t, "chain": "forward", "expr": [
                _match(_meta("oifname"), uplinks), _COUNTER, _DROP]}}},
            {"add": {"rule": {**t, "chain": "input", "expr": [
                {"vmap": {"key": _meta("iifname"), "data": "@in_vmap"}}]}}},
            {"add": {"rule": {**t, "chain": "input", "expr": [
                _match(_meta("iifname"), uplinks), _COUNTER, _DROP]}}},
            {"add": {"rule": {**t, "chain": "postrouting", "expr": [
                _match(_payload("ip", "saddr"), "@nat_src"),
                _match(_meta("oifname"), uplinks, "!="),
                {"masquerade": None}]}}},
        ]

    def _vm_ruleset(self, n: _VmNames) -> list[dict[str, Any]]:
        t = {"family": "inet", "table": self.table}
        g = self.nflog_group
        allowed: Verdict = "allowed"
        dropped: Verdict = "dropped"
        ns_ip, host_ip = uplink_ns_ip(n.index), uplink_host_ip(n.index)
        not_ours = [
            # IPv4 from the VM's own uplink address only.
            [_match(_meta("nfproto"), "ipv4", "!="), _log(g, dropped), _COUNTER, _DROP],
            [_match(_payload("ip", "saddr"), ns_ip, "!="), _log(g, dropped), _COUNTER, _DROP],
        ]
        fwd = [
            *not_ours,
            [_ct_state("established", "related"), _ACCEPT],
            [_ct_state("new"), _match(_payload("ip", "daddr"), f"@{n.allow_set}"),
             _log(g, allowed), _COUNTER, _ACCEPT],
            [_log(g, dropped), _COUNTER, _DROP],
        ]
        inp = [
            *not_ours,
            [_ct_state("established", "related"), _ACCEPT],
            [_match(_payload("ip", "daddr"), host_ip),
             _match(_payload("udp", "dport"), self._resolver.port), _COUNTER, _ACCEPT],
            [_log(g, dropped), _COUNTER, _DROP],
        ]
        cmds: list[dict[str, Any]] = [
            # create: fail if a leftover with this name exists.
            {"create": {"set": {**t, "name": n.allow_set, "type": "ipv4_addr"}}},
            {"create": {"chain": {**t, "name": n.fwd_chain}}},
            {"create": {"chain": {**t, "name": n.in_chain}}},
        ]
        cmds += [{"add": {"rule": {**t, "chain": n.fwd_chain, "expr": e}}} for e in fwd]
        cmds += [{"add": {"rule": {**t, "chain": n.in_chain, "expr": e}}} for e in inp]
        cmds += [
            {"add": {"element": {**t, "name": "fwd_vmap", "elem": [[n.veth_host, {"jump": {"target": n.fwd_chain}}]]}}},
            {"add": {"element": {**t, "name": "in_vmap", "elem": [[n.veth_host, {"jump": {"target": n.in_chain}}]]}}},
            {"add": {"element": {**t, "name": "nat_src", "elem": [ns_ip]}}},
        ]
        return cmds

    def _ns_ruleset(self, index: int, resolver_port: int) -> list[dict[str, Any]]:
        t = {"family": "ip", "table": _NS_TABLE}
        host_ip = uplink_host_ip(index)
        up = UPLINK_NS_NAME
        return [
            {"add": {"table": {"family": "ip", "name": _NS_TABLE}}},
            {"add": {"chain": {**t, "name": "pre", "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}},
            {"add": {"chain": {**t, "name": "post", "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}},
            {"add": {"chain": {**t, "name": "fwd", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}},
            {"add": {"chain": {**t, "name": "in", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}},
            # Every UDP DNS query from the guest, whatever its destination, goes
            # to the emberpool resolver.
            {"add": {"rule": {**t, "chain": "pre", "expr": [
                _match(_meta("iifname"), up, "!="),
                _match(_payload("udp", "dport"), _DNS_PORT),
                {"dnat": {"addr": host_ip, "port": resolver_port}}]}}},
            {"add": {"rule": {**t, "chain": "post", "expr": [
                _match(_meta("oifname"), up), {"masquerade": None}]}}},
            {"add": {"rule": {**t, "chain": "fwd", "expr": [
                _match(_meta("iifname"), up, "!="), _match(_meta("oifname"), up), _ACCEPT]}}},
            {"add": {"rule": {**t, "chain": "fwd", "expr": [
                _match(_meta("iifname"), up), _ct_state("established", "related"), _ACCEPT]}}},
            {"add": {"rule": {**t, "chain": "in", "expr": [_match(_meta("iifname"), "lo"), _ACCEPT]}}},
            {"add": {"rule": {**t, "chain": "in", "expr": [
                _match(_meta("iifname"), up), _ct_state("established", "related"), _ACCEPT]}}},
        ]

    def _ns_template_ruleset(self) -> list[dict[str, Any]]:
        t = {"family": "ip", "table": _NS_TABLE}
        return [
            {"add": {"table": {"family": "ip", "name": _NS_TABLE}}},
            {"add": {"chain": {**t, "name": "fwd", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}},
        ]


async def _shielded(aw: Awaitable[None]) -> None:
    """Run `aw` to completion even if the caller is cancelled, then re-raise
    the cancellation (docs/40-rules.md rule 12)."""
    task = asyncio.ensure_future(aw)
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.wait([task])
        if not task.cancelled() and task.exception() is not None:
            log.error("cleanup failed during cancellation: %s", task.exception())
        raise

