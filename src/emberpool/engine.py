"""Protocols the pool codes against. Frozen contract: do not edit in a stream.

Lifecycle of one sandbox, as the pool drives it:

    net = await netpolicy.setup(vm_id, index, policy)
    try:
        vm = await engine.restore(template, vm_id, net.netns)
        try:
            result = await exec_client.run(vm.vsock_path, code, timeout)
        finally:
            await engine.kill(vm)            # VM process gone, scratch drive kept
            changes = await engine.list_changes(vm)
            await engine.cleanup(vm)         # scratch drive and chroot removed
    finally:
        await netpolicy.teardown(net)

Every method that releases resources (kill, cleanup, teardown) is idempotent
and safe to call after a partial failure (docs/40-rules.md rule 12).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Protocol, runtime_checkable

from emberpool._types import (
    ConnEvent,
    DnsEvent,
    ExecResult,
    NetHandle,
    NetworkPolicy,
    Template,
    VMHandle,
)

__all__ = ["Engine", "NetPolicy", "ExecClient"]


@runtime_checkable
class Engine(Protocol):
    """Starts, snapshots, restores and kills microVMs. Firecracker-specific code
    lives only behind this protocol."""

    async def build_template(self, workdir: Path, netns: str) -> Template:
        """Cold-boot the template VM inside `netns`, wait for the guest agent to
        report ready, pause it and write a full snapshot under `workdir`. The
        template VM process is gone when this returns. Raises IsolationError
        (or another exception) on any failure; never returns a partial template."""
        ...

    async def restore(self, template: Template, vm_id: str, netns: str) -> VMHandle:
        """Restore a new VM from `template` inside `netns` under the jailer, with
        a fresh scratch drive, and resume it. On failure, everything created for
        this VM is released before the exception propagates."""
        ...

    async def kill(self, vm: VMHandle) -> None:
        """Stop the VM process and remove its API socket. Leaves the scratch drive
        in place for list_changes. Idempotent."""
        ...

    async def check_vmgenid(self, vm: VMHandle) -> bool:
        """True if the running VM has a device bound to the guest `vmgenid`
        driver. The pool calls this on the first VM restored from a new
        template and refuses to start if it returns False."""
        ...

    async def list_changes(self, vm: VMHandle) -> tuple[str, ...]:
        """Paths changed in the VM's scratch drive. Called after kill, before
        cleanup. Reads the drive with userspace tools only, never mounts it,
        and caps entries and time. Advisory: end state only."""
        ...

    async def cleanup(self, vm: VMHandle) -> None:
        """Remove the scratch drive, chroot and any other per-VM files. Kills the
        VM first if it is still running. Idempotent."""
        ...


@runtime_checkable
class NetPolicy(Protocol):
    """Per-VM network namespaces, the host nftables table and the shared DNS
    resolver."""

    async def setup(self, vm_id: str, index: int, policy: NetworkPolicy) -> NetHandle:
        """Create the VM's namespace (tap0, uplink veth `index`, forwarding,
        masquerade, DNS forward) and its allow set. Fails closed: on any error
        nothing is left behind and the exception propagates."""
        ...

    async def teardown(self, handle: NetHandle) -> None:
        """Remove the namespace, veth and allow set. Idempotent."""
        ...

    def template_netns(self) -> AbstractAsyncContextManager[str]:
        """Async context manager yielding a namespace name to build the template
        in. The namespace has tap0 with TAP_MAC and no egress. Removed on exit."""
        ...

    def events(self) -> AsyncIterator[DnsEvent | ConnEvent]:
        """Host-observed network events for all VMs, in arrival order."""
        ...


@runtime_checkable
class ExecClient(Protocol):
    """Host side of the vsock exec channel."""

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        """Send `code` to the guest agent behind the Firecracker vsock Unix socket
        at `vsock_path` and return its reply. Raises ExecError on refused
        connections, short reads and bad or oversized frames, and TimeoutError
        if no reply arrives within `timeout` plus a small margin. The pool, not
        the client, enforces the wall-clock limit by killing the VM."""
        ...
