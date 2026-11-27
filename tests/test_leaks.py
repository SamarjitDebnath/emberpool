"""Leak checks for the pool on in-memory fakes (no root needed).

Many runs and many pool lifetimes must leave nothing behind: no VMs, networks
or uplink indexes held, no asyncio tasks, and no steady memory growth
(docs/40-rules.md rules 12 and 15).
"""

from __future__ import annotations

import asyncio
import gc
import tracemalloc
from pathlib import Path

from emberpool._types import ExecError, ExecResult
from emberpool.pool import SandboxPool
from tests.fakes import FakeEngine, FakeExecClient, FakeNetPolicy


def _pool(tmp: Path, prefix: str, size: int = 2, **ex: object) -> tuple[SandboxPool, FakeEngine, FakeNetPolicy]:
    eng, net = FakeEngine(), FakeNetPolicy(prefix=prefix)
    pool = SandboxPool(size, "deny", _engine=eng, _netpolicy=net, _exec=FakeExecClient(**ex), _workdir=tmp)
    pool._retry_min = 0.001
    pool._retry_max = 0.01
    return pool, eng, net


def _other_tasks() -> set[asyncio.Task[object]]:
    return {t for t in asyncio.all_tasks() if t is not asyncio.current_task()}


def _assert_released(pool: SandboxPool, eng: FakeEngine, net: FakeNetPolicy) -> None:
    assert eng.leaks() == [], eng.leaks()
    assert net.leaks() == [], net.leaks()
    assert len(pool._idle) == 0


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


async def test_many_runs_release_everything(tmp_path: Path, test_prefix: str) -> None:
    before = _other_tasks()
    pool, eng, net = _pool(tmp_path, test_prefix)
    async with pool:
        for i in range(300):
            r = await pool.run(f"print({i})", 5)
            assert r.exit_code == 0
        # Only the idle VMs are alive while the pool is open.
        assert len(eng.running()) == 2
        assert len(net.handles) == 2
    _assert_released(pool, eng, net)
    await _settle()
    assert _other_tasks() - before == set()
    # Every VM ever made was destroyed: one per run plus the probe and the idle ones.
    assert len(eng.vms) >= 300


async def test_concurrent_runs_with_failures_release_everything(tmp_path: Path, test_prefix: str) -> None:
    def flaky(code: str) -> ExecResult:
        if code.endswith("3"):
            raise ExecError("agent died")
        return ExecResult(code, "", 0)

    before = _other_tasks()
    pool, eng, net = _pool(tmp_path, test_prefix, size=3, behaviour=flaky)
    async with pool:
        results = await asyncio.gather(*(pool.run(f"x{i}", 5) for i in range(120)))
        timed = await asyncio.gather(
            *(pool.run("slow", 0.01) for _ in range(10)), return_exceptions=True
        )
    assert sum(r.exit_code != 0 for r in results) == 12
    assert all(not isinstance(t, BaseException) or isinstance(t, TimeoutError) for t in timed)
    _assert_released(pool, eng, net)
    await _settle()
    assert _other_tasks() - before == set()


async def test_cancelled_runs_release_everything(tmp_path: Path, test_prefix: str) -> None:
    pool, eng, net = _pool(tmp_path, test_prefix, delay=10)
    async with pool:
        tasks = [asyncio.create_task(pool.run("sleep", 30)) for _ in range(20)]
        await asyncio.sleep(0.05)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    _assert_released(pool, eng, net)


async def test_pool_lifetimes_do_not_grow_memory(tmp_path: Path, test_prefix: str) -> None:
    async def lifetime(i: int) -> None:
        pool, eng, net = _pool(tmp_path / str(i), test_prefix)
        (tmp_path / str(i)).mkdir()
        async with pool:
            for _ in range(20):
                await pool.run("print(1)", 5)
        _assert_released(pool, eng, net)

    # Warm up caches and lazy imports, then measure steady state.
    for i in range(5):
        await lifetime(i)
    gc.collect()
    tracemalloc.start()
    try:
        base = tracemalloc.take_snapshot()
        for i in range(5, 45):
            await lifetime(i)
        gc.collect()
        grown = sum(s.size_diff for s in tracemalloc.take_snapshot().compare_to(base, "filename"))
    finally:
        tracemalloc.stop()
    # 40 pools and 800 runs; anything retained per run would show up far above this.
    assert grown < 512 * 1024, f"memory grew by {grown} bytes"
