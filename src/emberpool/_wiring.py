"""Builds the real backends for SandboxPool: FirecrackerEngine, HostNetPolicy,
VsockExecClient and TraceWriter, configured to agree with each other.

    async with real_backends(engine_config, prefix="ep") as b:
        async with SandboxPool(4, "deny", **b.pool_kwargs()) as pool:
            ...

What has to agree, and where it is set here:

- nflog group, log prefixes and snaplen: HostNetPolicy writes them into its
  nftables rules, TraceWriter's NflogReader reads them. Both modules define
  the values; `check_log_format()` refuses to start if they differ.
- tap0 owner: the jailer drops to (uid, gid) before Firecracker opens tap0,
  so HostNetPolicy makes tap0 owned by the jail identity.
- Template workdir and jailer chroot base must share a filesystem (clones get
  hard links), so the workdir is made inside the chroot base.
- The engine's VMGenID check needs an exec client: the same VsockExecClient.

Shutdown order is the reverse of start: the pool (inside) destroys its VMs,
then the tracer stops reading, then the network policy removes its table and
namespaces, then the workdir goes.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emberpool import netpolicy as _np
from emberpool import trace as _tr
from emberpool._firecracker import FirecrackerConfig, FirecrackerEngine
from emberpool._resolver import Lookup
from emberpool._types import IsolationError
from emberpool.exec_client import VsockExecClient
from emberpool.netpolicy import DEFAULT_TABLE, HostNetPolicy
from emberpool.trace import NflogReader, TraceWriter

__all__ = ["Backends", "check_log_format", "real_backends"]


def check_log_format() -> None:
    """Fail closed if the rules HostNetPolicy writes and the log TraceWriter
    reads disagree: every connection verdict would be lost from the trace."""
    written = (_np.DEFAULT_NFLOG_GROUP, _np.LOG_PREFIX_ALLOWED, _np.LOG_PREFIX_DROPPED, _np.NFLOG_SNAPLEN)
    read = (_tr.NFLOG_GROUP, _tr.LOG_PREFIX_ALLOWED, _tr.LOG_PREFIX_DROPPED, _tr.NFLOG_SNAPLEN)
    if written != read:
        raise IsolationError(f"nftables log format {written} does not match the trace reader {read}")


@dataclass(frozen=True, slots=True)
class Backends:
    engine: FirecrackerEngine
    netpolicy: HostNetPolicy
    exec_client: VsockExecClient
    tracer: TraceWriter
    workdir: Path

    def pool_kwargs(self) -> dict[str, Any]:
        """The internal SandboxPool keyword arguments for these backends."""
        return {
            "_engine": self.engine,
            "_netpolicy": self.netpolicy,
            "_exec": self.exec_client,
            "_tracer": self.tracer,
            "_workdir": self.workdir,
        }


@asynccontextmanager
async def real_backends(
    engine_config: FirecrackerConfig,
    *,
    prefix: str = "ep",
    table: str = DEFAULT_TABLE,
    lookup: Lookup | None = None,
    nflog_netns: str | None = None,
) -> AsyncIterator[Backends]:
    """Start the network policy and the trace reader, make a template workdir,
    and yield the backends. Any start failure releases what was started and
    raises (IsolationError for isolation steps).

    prefix:      start of every namespace and interface name.
    table:       the host nftables table name.
    lookup:      upstream DNS lookup for the resolver (default: the host's).
    nflog_netns: namespace the nftables table lives in, when that is not the
                 caller's root namespace (tests running in a private host
                 namespace). The log reader binds there.
    """
    check_log_format()
    jail = engine_config.jailer
    exec_client = VsockExecClient()
    engine = FirecrackerEngine(engine_config, exec_client)
    netpolicy = HostNetPolicy(
        prefix=prefix,
        table=table,
        nflog_group=_tr.NFLOG_GROUP,
        lookup=lookup,
        tap_owner=(jail.uid, jail.gid),
    )
    async with netpolicy:
        tracer = TraceWriter(netpolicy.events(), NflogReader(_tr.NFLOG_GROUP, netns=nflog_netns))
        async with tracer:
            await asyncio.to_thread(jail.chroot_base.mkdir, 0o755, True, True)
            workdir = Path(
                await asyncio.to_thread(tempfile.mkdtemp, prefix=f"{prefix}-pool-", dir=jail.chroot_base)
            )
            try:
                yield Backends(engine, netpolicy, exec_client, tracer, workdir)
            finally:
                await asyncio.shield(asyncio.to_thread(shutil.rmtree, workdir, True))
