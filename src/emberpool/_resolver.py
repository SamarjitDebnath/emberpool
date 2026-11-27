"""The shared host DNS resolver every sandbox's DNS is forwarded to.

One UDP socket on the host. A query is accepted only when both host facts
agree on which VM sent it (docs/40-rules.md rule 2):

- the source address is the namespace end of an uplink, 10.200.N.2, and
- the packet arrived on the host-side veth registered for uplink N
  (from IP_PKTINFO, not from anything in the packet payload).

Queries from anywhere else are ignored without a reply.

For a registered VM the resolver answers only names in that VM's allowlist,
with IPv4 addresses looked up upstream. Before replying it adds the addresses
to the VM's nftables allow set; if that fails the guest gets SERVFAIL and no
addresses (fail closed). Every accepted query produces one DnsEvent.

Everything in a query is guest-controlled. It is parsed with dnspython, size
capped, and only ever compared against validated allowlist names. The queried
name reaches the trace only in dnspython's escaped text form.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from emberpool._names import validate_domain, validate_vm_id
from emberpool._types import DnsEvent, uplink_ns_ip, uplink_subnet

__all__ = [
    "MAX_QUERY_BYTES",
    "LookupResult",
    "Lookup",
    "UpstreamError",
    "ResolverClient",
    "Resolver",
    "dnspython_lookup",
    "answer_allowed",
]

log = logging.getLogger(__name__)

# Larger datagrams are dropped unread. Plain DNS queries are well under this.
MAX_QUERY_BYTES = 1232
_RECV_BUF = MAX_QUERY_BYTES + 1
_MAX_READS_PER_WAKEUP = 64
_MAX_ANSWERS = 16
_MAX_TTL = 60
_QNAME_RE = re.compile(r"[\x21-\x7e]{1,1024}")

# Addresses never handed to a guest, whatever upstream says: they would point
# the sandbox at the host itself, its link-local services (cloud metadata) or
# emberpool's own uplinks.
_UPLINKS = ipaddress.IPv4Network("10.200.0.0/16")


class UpstreamError(Exception):
    """The upstream lookup failed (timeout, SERVFAIL, no nameservers)."""


@dataclass(frozen=True, slots=True)
class LookupResult:
    """addresses=None means the name does not exist upstream (NXDOMAIN)."""

    addresses: tuple[str, ...] | None
    ttl: int = _MAX_TTL


Lookup = Callable[[str], Awaitable[LookupResult]]
AddIps = Callable[[tuple[str, ...]], Awaitable[None]]


@dataclass(eq=False, slots=True)
class ResolverClient:
    """One VM as the resolver sees it. Built by NetPolicy from host facts."""

    vm_id: str
    index: int
    ifindex: int
    allow: frozenset[str]
    add_ips: AddIps
    max_ips: int = 1024
    max_inflight: int = 8
    added: set[str] = field(default_factory=set)
    inflight: int = 0

    def __post_init__(self) -> None:
        validate_vm_id(self.vm_id)
        uplink_subnet(self.index)
        if isinstance(self.ifindex, bool) or not isinstance(self.ifindex, int) or self.ifindex <= 0:
            raise ValueError(f"invalid ifindex: {self.ifindex!r}")
        self.allow = frozenset(validate_domain(n) for n in self.allow)

    @property
    def source_ip(self) -> str:
        return uplink_ns_ip(self.index)


def answer_allowed(ip: str) -> bool:
    """True if `ip` may be returned to a guest and put in its allow set."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
        or addr == ipaddress.IPv4Address("255.255.255.255")
        or addr in _UPLINKS
    )


def dnspython_lookup(
    nameservers: list[str] | None = None, port: int = 53, timeout: float = 3.0
) -> Lookup:
    """Upstream A lookup with dnspython. Uses the host's resolv.conf unless
    `nameservers` is given. Every lookup is bounded by `timeout`."""
    if nameservers is None:
        res = dns.asyncresolver.Resolver(configure=True)
    else:
        res = dns.asyncresolver.Resolver(configure=False)
        res.nameservers = list(nameservers)
    res.port = port
    res.cache = None

    async def lookup(name: str) -> LookupResult:
        try:
            ans = await res.resolve(name, "A", search=False, lifetime=timeout)
        except dns.resolver.NXDOMAIN:
            return LookupResult(None)
        except dns.resolver.NoAnswer:
            return LookupResult(())
        except dns.exception.DNSException as e:
            raise UpstreamError(f"{type(e).__name__}: {e}") from None
        ips = tuple(r.address for r in ans if r.rdtype == dns.rdatatype.A)
        return LookupResult(ips, int(ans.rrset.ttl) if ans.rrset is not None else _MAX_TTL)

    return lookup


def _event_name(qname: dns.name.Name) -> str:
    """The queried name as escaped printable ASCII without spaces."""
    text = qname.to_text(omit_final_dot=True).lower()
    if _QNAME_RE.fullmatch(text) is None:
        # dnspython escapes everything outside 0x21-0x7e already; belt and braces.
        text = "".join(c if "\x21" <= c <= "\x7e" else f"\\{ord(c):03d}" for c in text)[:1024]
    return text or "."


class Resolver:
    """The shared host resolver. See the module docstring."""

    def __init__(
        self,
        emit: Callable[[DnsEvent], None],
        *,
        lookup: Lookup | None = None,
        lookup_timeout: float = 3.0,
        add_timeout: float = 5.0,
    ) -> None:
        self._emit = emit
        self._lookup = lookup if lookup is not None else dnspython_lookup(timeout=lookup_timeout)
        self._lookup_timeout = lookup_timeout
        self._add_timeout = add_timeout
        self._clients: dict[int, ResolverClient] = {}
        self._sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self.port = 0
        self.ignored = 0  # datagrams from unknown sources or oversized

    # -- lifecycle ---------------------------------------------------------

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        """Bind the UDP socket and start serving. Returns the bound port."""
        if self._sock is not None:
            return self.port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", 8), 1)
            sock.setblocking(False)
            sock.bind((host, port))
            self._loop = asyncio.get_running_loop()
            self._loop.add_reader(sock.fileno(), self._on_readable)
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        self.port = sock.getsockname()[1]
        return self.port

    async def close(self) -> None:
        """Stop serving and cancel in-flight queries. Idempotent."""
        sock, self._sock = self._sock, None
        if sock is not None:
            if self._loop is not None:
                self._loop.remove_reader(sock.fileno())
            sock.close()
        tasks = list(self._tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._clients.clear()

    def register(self, client: ResolverClient) -> None:
        if client.index in self._clients:
            raise ValueError(f"uplink {client.index} already registered")
        self._clients[client.index] = client

    def unregister(self, index: int, vm_id: str) -> None:
        """Forget uplink `index` if it still belongs to `vm_id`. Idempotent."""
        client = self._clients.get(index)
        if client is not None and client.vm_id == vm_id:
            del self._clients[index]

    def identify(self, src_ip: str, ifindex: int) -> ResolverClient | None:
        """The registered VM that both host facts point to, or None."""
        try:
            addr = ipaddress.IPv4Address(src_ip)
        except ValueError:
            return None
        if addr not in _UPLINKS:
            return None
        client = self._clients.get(int(addr.packed[2]))
        if client is None or client.source_ip != src_ip or client.ifindex != ifindex:
            return None
        return client

    # -- socket ------------------------------------------------------------

    def _on_readable(self) -> None:
        sock = self._sock
        if sock is None:
            return
        cmsg_space = socket.CMSG_SPACE(12)
        for _ in range(_MAX_READS_PER_WAKEUP):
            try:
                data, ancdata, flags, addr = sock.recvmsg(_RECV_BUF, cmsg_space)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:
                log.warning("resolver recv failed: %s", e)
                return
            ifindex = _pktinfo_ifindex(ancdata)
            if len(data) > MAX_QUERY_BYTES or flags & socket.MSG_TRUNC or ifindex is None:
                self.ignored += 1
                continue
            client = self.identify(addr[0], ifindex)
            if client is None:
                self.ignored += 1
                continue
            task = asyncio.get_running_loop().create_task(self._serve(data, addr, client))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _serve(self, data: bytes, addr: tuple[str, int], client: ResolverClient) -> None:
        try:
            reply = await self.answer(data, client)
        except Exception:
            log.exception("resolver failed on a query from %s", client.vm_id)
            return
        sock = self._sock
        if reply is None or sock is None:
            return
        try:
            sock.sendto(reply, addr)
        except OSError as e:
            log.warning("resolver reply to %s failed: %s", client.vm_id, e)

    # -- one query -----------------------------------------------------------

    async def answer(self, data: bytes, client: ResolverClient) -> bytes | None:
        """Answer one query from `client`. Returns the reply, or None to send
        nothing (unparseable input). Emits exactly one DnsEvent per query that
        has a question."""
        if len(data) > MAX_QUERY_BYTES:
            return None
        try:
            query = dns.message.from_wire(data, one_rr_per_rrset=True)
        except Exception:
            return _formerr(data)
        if query.flags & dns.flags.QR or not query.question:
            return None
        response = dns.message.make_response(query, recursion_available=True)
        response.flags &= ~dns.flags.AA
        question = query.question[0]
        name = _event_name(question.name)

        if (
            query.opcode() != dns.opcode.QUERY
            or len(query.question) != 1
            or question.rdclass != dns.rdataclass.IN
        ):
            response.set_rcode(dns.rcode.REFUSED)
            self._event(client, name, None)
            return _wire(response)

        if name not in client.allow:
            response.set_rcode(dns.rcode.NXDOMAIN)
            self._event(client, name, None)
            return _wire(response)

        if question.rdtype != dns.rdatatype.A:
            # Allowed name, other type (AAAA, HTTPS...): no data. The guest is IPv4 only.
            self._event(client, name, ())
            return _wire(response)

        if client.inflight >= client.max_inflight:
            response.set_rcode(dns.rcode.SERVFAIL)
            self._event(client, name, None)
            return _wire(response)
        client.inflight += 1
        try:
            return await self._resolve_allowed(response, question.name, name, client)
        finally:
            client.inflight -= 1

    async def _resolve_allowed(
        self, response: dns.message.Message, qname: dns.name.Name, name: str, client: ResolverClient
    ) -> bytes:
        try:
            async with asyncio.timeout(self._lookup_timeout + 1.0):
                result = await self._lookup(name)
        except (UpstreamError, TimeoutError) as e:
            log.info("upstream lookup of %s for %s failed: %s", name, client.vm_id, e)
            response.set_rcode(dns.rcode.SERVFAIL)
            self._event(client, name, None)
            return _wire(response)

        if result.addresses is None:
            response.set_rcode(dns.rcode.NXDOMAIN)
            self._event(client, name, None)
            return _wire(response)

        ips: list[str] = []
        for ip in result.addresses:
            if answer_allowed(ip) and ip not in ips:
                ips.append(str(ipaddress.IPv4Address(ip)))
            if len(ips) >= _MAX_ANSWERS:
                break
        new = [ip for ip in ips if ip not in client.added]

        try:
            if len(client.added) + len(new) > client.max_ips:
                raise RuntimeError(f"allow set cap of {client.max_ips} addresses reached")
            if self._clients.get(client.index) is not client:
                raise RuntimeError("VM no longer registered")
            if new:
                async with asyncio.timeout(self._add_timeout):
                    await client.add_ips(tuple(new))
                client.added.update(new)
        except Exception as e:
            # Fail closed: an address the allow set does not hold is never returned.
            log.warning("could not allow %s for %s: %s", name, client.vm_id, e)
            response.set_rcode(dns.rcode.SERVFAIL)
            self._event(client, name, None)
            return _wire(response)

        if ips:
            ttl = max(0, min(int(result.ttl), _MAX_TTL))
            response.answer.append(
                dns.rrset.from_text_list(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, ips)
            )
        self._event(client, name, tuple(ips))
        return _wire(response)

    def _event(self, client: ResolverClient, name: str, answers: tuple[str, ...] | None) -> None:
        try:
            self._emit(DnsEvent(time.time(), client.vm_id, name, answers))
        except Exception:
            log.exception("could not record DNS event for %s", client.vm_id)


def _wire(msg: dns.message.Message) -> bytes:
    return bytes(msg.to_wire())


def _pktinfo_ifindex(ancdata: list[tuple[int, int, bytes]]) -> int | None:
    for level, kind, value in ancdata:
        if level == socket.IPPROTO_IP and kind == getattr(socket, "IP_PKTINFO", 8):
            if len(value) >= 4:
                return int(struct.unpack_from("=i", value)[0])
    return None


def _formerr(data: bytes) -> bytes | None:
    """FORMERR echoing the query id, if there is a 12-byte header to echo."""
    if len(data) < 12:
        return None
    qid, flags = struct.unpack_from(">HH", data)
    if flags & 0x8000:  # a response, not a query: never answer it
        return None
    opcode = flags & 0x7800
    return struct.pack(">HHHHHH", qid, 0x8000 | opcode | dns.rcode.FORMERR, 0, 0, 0, 0)
