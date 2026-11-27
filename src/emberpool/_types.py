"""Shared types and network constants. Frozen contract: do not edit in a stream."""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from emberpool._names import (
    validate_domain,
    validate_interface,
    validate_netns,
    validate_vm_id,
)

__all__ = [
    "TAP_NAME",
    "TAP_MAC",
    "TAP_HOST_CIDR",
    "TAP_HOST_IP",
    "GUEST_IP",
    "GUEST_CIDR",
    "UPLINK_PREFIX_LEN",
    "MAX_UPLINKS",
    "uplink_subnet",
    "uplink_host_ip",
    "uplink_ns_ip",
    "VSOCK_PORT",
    "TRACE_SCHEMA_VERSION",
    "EmberpoolError",
    "IsolationError",
    "ExecError",
    "NetworkPolicy",
    "DnsEvent",
    "ConnEvent",
    "Event",
    "Trace",
    "ExecResult",
    "Result",
    "Template",
    "VMHandle",
    "NetHandle",
]

# --------------------------------------------------------------------------
# Network constants (identical inside every VM namespace)
# --------------------------------------------------------------------------

TAP_NAME = "tap0"
TAP_MAC = "02:ee:00:00:00:01"
TAP_HOST_IP = "172.16.0.1"
TAP_HOST_CIDR = "172.16.0.1/30"
GUEST_IP = "172.16.0.2"
GUEST_CIDR = "172.16.0.2/30"

# Uplink veth per VM: 10.200.N.0/30, host side .1 (root ns), namespace side .2.
UPLINK_PREFIX_LEN = 30
MAX_UPLINKS = 256  # N in 0..255


def uplink_subnet(index: int) -> ipaddress.IPv4Network:
    """The /30 for uplink `index` (0..255): 10.200.<index>.0/30."""
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < MAX_UPLINKS:
        raise ValueError(f"uplink index must be an int in 0..{MAX_UPLINKS - 1}: {index!r}")
    return ipaddress.IPv4Network(f"10.200.{index}.0/{UPLINK_PREFIX_LEN}")


def uplink_host_ip(index: int) -> str:
    """Root-namespace end of the uplink veth: 10.200.<index>.1."""
    return str(uplink_subnet(index).network_address + 1)


def uplink_ns_ip(index: int) -> str:
    """VM-namespace end of the uplink veth: 10.200.<index>.2."""
    return str(uplink_subnet(index).network_address + 2)


VSOCK_PORT = 1024
TRACE_SCHEMA_VERSION = 1

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class EmberpoolError(Exception):
    """Base class for emberpool errors."""


class IsolationError(EmberpoolError):
    """An isolation step failed (jailer, netns, nftables, VMGenID). Fail closed."""


class ExecError(EmberpoolError):
    """The exec channel failed: refused, short read, bad or oversized frame."""


# --------------------------------------------------------------------------
# Network policy
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Egress policy. Empty `allow` means deny everything (the default)."""

    allow: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.allow, tuple):
            raise TypeError("allow must be a tuple of domain names")
        names = tuple(validate_domain(n) for n in self.allow)
        if len(set(names)) != len(names):
            raise ValueError("duplicate domain in allow list")
        object.__setattr__(self, "allow", names)

    @property
    def is_deny(self) -> bool:
        return not self.allow

    @classmethod
    def parse(cls, spec: str = "deny") -> NetworkPolicy:
        """Parse "deny" or "allow:a.com,b.org". Names are validated and lowercased,
        duplicates dropped (first occurrence kept)."""
        if not isinstance(spec, str):
            raise ValueError(f"network policy must be a str, got {type(spec).__name__}")
        if spec == "deny":
            return cls()
        if not spec.startswith("allow:"):
            raise ValueError(f'network policy must be "deny" or "allow:<names>": {spec!r}')
        raw = spec[len("allow:") :].split(",")
        if any(not part.strip() for part in raw):
            raise ValueError(f"empty domain in network policy: {spec!r}")
        names: list[str] = []
        for part in raw:
            name = validate_domain(part.strip())
            if name not in names:
                names.append(name)
        return cls(tuple(names))

    def __str__(self) -> str:
        return "deny" if self.is_deny else "allow:" + ",".join(self.allow)


# --------------------------------------------------------------------------
# Trace events
# --------------------------------------------------------------------------

# Query names come from the guest and may be anything. Producers must escape
# them to printable ASCII without spaces (for example "\\x00") before building
# a DnsEvent; this pattern enforces that.
_QNAME_RE = re.compile(r"[\x21-\x7e]{1,1024}")
_PROTOCOL_RE = re.compile(r"[a-z0-9]{1,16}")


def _check_time(t: object) -> float:
    if isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0:
        raise ValueError(f"time must be a finite non-negative number: {t!r}")
    return float(t)


def _check_ip(ip: object) -> str:
    if not isinstance(ip, str):
        raise ValueError(f"IP must be a str: {ip!r}")
    return str(ipaddress.ip_address(ip))


@dataclass(frozen=True, slots=True)
class DnsEvent:
    """A DNS query seen by the host resolver. answers=None means NXDOMAIN."""

    time: float
    vm_id: str
    name: str
    answers: tuple[str, ...] | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "time", _check_time(self.time))
        validate_vm_id(self.vm_id)
        if not isinstance(self.name, str) or _QNAME_RE.fullmatch(self.name) is None:
            raise ValueError(f"DNS name must be escaped printable ASCII: {self.name!r}")
        if self.answers is not None:
            if not isinstance(self.answers, tuple):
                raise TypeError("answers must be a tuple or None")
            object.__setattr__(self, "answers", tuple(_check_ip(a) for a in self.answers))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "dns",
            "time": self.time,
            "vm_id": self.vm_id,
            "name": self.name,
            "rcode": "NXDOMAIN" if self.answers is None else "NOERROR",
            "answers": [] if self.answers is None else list(self.answers),
        }


@dataclass(frozen=True, slots=True)
class ConnEvent:
    """A connection verdict from the host nftables table."""

    time: float
    vm_id: str
    dst_ip: str
    dst_port: int
    protocol: str
    name: str | None
    verdict: Literal["allowed", "dropped"]

    def __post_init__(self) -> None:
        object.__setattr__(self, "time", _check_time(self.time))
        validate_vm_id(self.vm_id)
        object.__setattr__(self, "dst_ip", _check_ip(self.dst_ip))
        port = self.dst_port
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError(f"dst_port must be an int in 0..65535: {port!r}")
        if not isinstance(self.protocol, str) or _PROTOCOL_RE.fullmatch(self.protocol) is None:
            raise ValueError(f"invalid protocol: {self.protocol!r}")
        if self.name is not None:
            object.__setattr__(self, "name", validate_domain(self.name))
        if self.verdict not in ("allowed", "dropped"):
            raise ValueError(f"verdict must be 'allowed' or 'dropped': {self.verdict!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "conn",
            "time": self.time,
            "vm_id": self.vm_id,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "name": self.name,
            "verdict": self.verdict,
        }


Event = DnsEvent | ConnEvent


def _need(d: dict[str, Any], key: str) -> Any:
    if key not in d:
        raise ValueError(f"trace event missing {key!r}")
    return d[key]


def _event_from_dict(d: object) -> Event:
    # Unknown extra keys are ignored: fields may be added within schema version 1.
    if not isinstance(d, dict):
        raise ValueError("trace event must be an object")
    kind = _need(d, "type")
    if kind == "dns":
        rcode = _need(d, "rcode")
        answers = _need(d, "answers")
        if not isinstance(answers, list):
            raise ValueError("dns answers must be a list")
        if rcode == "NXDOMAIN":
            if answers:
                raise ValueError("NXDOMAIN event must have no answers")
            parsed: tuple[str, ...] | None = None
        elif rcode == "NOERROR":
            parsed = tuple(answers)
        else:
            raise ValueError(f"unknown rcode: {rcode!r}")
        return DnsEvent(_need(d, "time"), _need(d, "vm_id"), _need(d, "name"), parsed)
    if kind == "conn":
        return ConnEvent(
            _need(d, "time"),
            _need(d, "vm_id"),
            _need(d, "dst_ip"),
            _need(d, "dst_port"),
            _need(d, "protocol"),
            _need(d, "name"),
            _need(d, "verdict"),
        )
    raise ValueError(f"unknown trace event type: {kind!r}")


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite number in JSON: {value}")


@dataclass(frozen=True, slots=True)
class Trace:
    """Host-observed network events for one VM, in time order."""

    schema_version: int = TRACE_SCHEMA_VERSION
    events: tuple[Event, ...] = field(default=())

    def __post_init__(self) -> None:
        if self.schema_version != TRACE_SCHEMA_VERSION:
            raise ValueError(f"unsupported trace schema_version: {self.schema_version!r}")
        if not isinstance(self.events, tuple):
            raise TypeError("events must be a tuple")
        for e in self.events:
            if not isinstance(e, (DnsEvent, ConnEvent)):
                raise TypeError(f"not a trace event: {e!r}")

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def __len__(self) -> int:
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "events": [e.to_dict() for e in self.events]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str | bytes) -> Trace:
        data = json.loads(text, parse_constant=_reject_constant)
        if not isinstance(data, dict):
            raise ValueError("trace must be a JSON object")
        version = data.get("schema_version")
        if isinstance(version, bool) or version != TRACE_SCHEMA_VERSION:
            raise ValueError(f"unsupported trace schema_version: {version!r}")
        events = data.get("events")
        if not isinstance(events, list):
            raise ValueError("trace events must be a list")
        return cls(TRACE_SCHEMA_VERSION, tuple(_event_from_dict(e) for e in events))


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecResult:
    """What the guest agent reported. Untrusted: code can forge all of it."""

    stdout: str
    stderr: str
    exit_code: int


@dataclass(frozen=True, slots=True)
class Result:
    """What SandboxPool.run returns.

    stdout, stderr, exit_code: guest-reported, untrusted.
    timed_out, trace: host-observed.
    file_changes: advisory, end state only.
    """

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    trace: Trace
    file_changes: tuple[str, ...]


# --------------------------------------------------------------------------
# Engine and network handles
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Template:
    """A snapshot that clones are restored from."""

    state_path: Path
    mem_path: Path
    rootfs_path: Path


@dataclass(frozen=True, slots=True)
class VMHandle:
    """One running (or killed) VM, as the engine tracks it."""

    vm_id: str
    pid: int
    vsock_path: Path
    scratch_path: Path
    netns: str

    def __post_init__(self) -> None:
        validate_vm_id(self.vm_id)
        validate_netns(self.netns)


@dataclass(frozen=True, slots=True)
class NetHandle:
    """One VM's network setup: its namespace and host-side uplink veth."""

    vm_id: str
    index: int
    netns: str
    veth_host: str

    def __post_init__(self) -> None:
        validate_vm_id(self.vm_id)
        uplink_subnet(self.index)  # range check
        validate_netns(self.netns)
        validate_interface(self.veth_host)
