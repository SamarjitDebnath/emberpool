"""Resource-leak tests on real VMs (docs/40-rules.md rules 12 and 15). Root and KVM only.

Many runs, and several pool lifetimes, must return the host to where it
started: open files, threads, memory of this process, namespaces, nftables
objects, jails, cgroups and VMM processes. Runs inside a private namespace
that plays the host, so the host firewall is neither needed nor touched.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from emberpool import SandboxPool
from emberpool._jailer import CGROUP_ROOT
from emberpool._wiring import Backends, real_backends
from tests.test_e2e_vm import engine_config, our_netns, private_host, sh  # noqa: F401

pytestmark = pytest.mark.vm

RUNS = 25


@dataclass(frozen=True)
class Snapshot:
    fds: int
    threads: int
    rss_kib: int
    netns: int
    nft_objects: int
    jails: int
    cgroups: int
    vmms: int
    tmp_entries: int


def _rss_kib() -> int:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise AssertionError("no VmRSS")


def _vmm_count() -> int:
    n = 0
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if Path(f"/proc/{entry}/comm").read_text().startswith("firecracker"):
                    n += 1
            except OSError:
                pass
    return n


async def _nft_objects(table: str) -> int:
    out = await sh("nft", "-j", "list", "ruleset")
    items = json.loads(out or b"{}").get("nftables", [])
    return sum(
        1 for item in items
        for kind, body in item.items()
        if kind in ("chain", "set", "map", "rule", "element") and body.get("table") == table
    )


async def snapshot(prefix: str, engine_config) -> Snapshot:  # noqa: F811
    jail_dir = engine_config.jailer.chroot_base / engine_config.jailer.exec_name
    cg = CGROUP_ROOT / prefix
    return Snapshot(
        fds=len(os.listdir("/proc/self/fd")),
        threads=len(os.listdir("/proc/self/task")),
        rss_kib=_rss_kib(),
        netns=len(await our_netns(prefix)),
        nft_objects=await _nft_objects(prefix),
        jails=len(list(jail_dir.iterdir())) if jail_dir.is_dir() else 0,
        cgroups=len([p for p in cg.iterdir() if p.is_dir()]) if cg.is_dir() else 0,
        vmms=_vmm_count(),
        tmp_entries=len([p for p in Path("/tmp").iterdir() if p.name.startswith(prefix)]),
    )


async def settle(pool: SandboxPool, size: int) -> None:
    """Wait until replacements have refilled the pool."""
    for _ in range(600):
        if len(pool._idle) == size:
            await asyncio.sleep(0.2)
            return
        await asyncio.sleep(0.1)
    raise AssertionError("pool did not refill")


async def test_many_runs_hold_host_resources_steady(engine_config, test_prefix):  # noqa: F811
    async with private_host(test_prefix) as host:
        async with real_backends(engine_config, prefix=test_prefix, table=test_prefix, nflog_netns=host) as b:
            async with SandboxPool(1, "deny", **b.pool_kwargs()) as pool:
                # Warm up: first runs allocate lazily (imports, caches, thread pools).
                for _ in range(3):
                    await pool.run("print(1)", 60)
                await settle(pool, 1)
                base = await snapshot(test_prefix, engine_config)
                for i in range(RUNS):
                    r = await pool.run(f"open('/tmp/f', 'w').write('x' * {i})\nprint({i})", 60)
                    assert r.stdout == f"{i}\n", r.stderr
                await settle(pool, 1)
                after = await snapshot(test_prefix, engine_config)
                assert b.engine.tracked() and len(b.engine.tracked()) == 1

    # Steady state: the same resources as before the runs, give or take
    # what one in-flight background task can hold.
    assert after.netns == base.netns
    assert after.nft_objects == base.nft_objects, (base, after)
    assert after.jails == base.jails == 1
    assert after.cgroups == base.cgroups
    assert after.vmms == base.vmms
    assert after.tmp_entries == base.tmp_entries
    assert after.fds <= base.fds + 2, (base.fds, after.fds)
    assert after.threads <= base.threads + 2, (base.threads, after.threads)
    assert after.rss_kib - base.rss_kib < 32 * 1024, (base.rss_kib, after.rss_kib)


async def test_pool_lifetimes_return_host_to_start(engine_config, test_prefix):  # noqa: F811
    async with private_host(test_prefix) as host:
        start = await snapshot(test_prefix, engine_config)
        for cycle in range(3):
            async with real_backends(
                engine_config, prefix=test_prefix, table=test_prefix, nflog_netns=host
            ) as b:
                async with SandboxPool(2, "deny", **b.pool_kwargs()) as pool:
                    results = await asyncio.gather(*(pool.run("print('x')", 120) for _ in range(4)))
                    assert all(r.stdout == "x\n" for r in results)
                assert b.engine.tracked() == []
            end = await snapshot(test_prefix, engine_config)
            # Everything the pool and its backends made is gone again, and the
            # nflog group is free for the next cycle (it would fail to bind otherwise).
            assert end.netns == start.netns, (cycle, start, end)
            assert end.nft_objects == 0 == start.nft_objects, (cycle, end)
            assert end.jails == 0 and end.vmms == start.vmms, (cycle, end)
            assert end.cgroups == start.cgroups, (cycle, end)
            assert end.tmp_entries == start.tmp_entries, (cycle, end)
            assert end.fds <= start.fds + 2, (cycle, start.fds, end.fds)
    assert await our_netns(test_prefix) == set()
