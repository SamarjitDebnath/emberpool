"""SandboxPool and Sandbox on the in-memory fakes. No real VMs."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import emberpool
from emberpool import pool as pool_mod
from emberpool._types import (
    ConnEvent,
    DnsEvent,
    ExecResult,
    IsolationError,
    NetworkPolicy,
    Result,
    VMHandle,
)
from emberpool.pool import NO_RESULT_EXIT_CODE, Sandbox, SandboxPool
from tests.fakes import FakeEngine, FakeExecClient, FakeNetPolicy


def vm_of(path: Path) -> str:
    """The fake engine puts the vm_id in the vsock path: /fake/<vm_id>/v.sock."""
    return path.parent.name


@dataclass
class EmittingExec(FakeExecClient):
    """Exec client that makes the fake host observe network events for the VM."""

    net: FakeNetPolicy | None = None
    events_per_run: int = 1

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        assert self.net is not None
        vm_id = vm_of(vsock_path)
        for i in range(self.events_per_run):
            self.net.emit(DnsEvent(float(i), vm_id, "pypi.org", ("151.101.0.223",)))
        self.net.emit(ConnEvent(1.0, vm_id, "151.101.0.223", 443, "tcp", "pypi.org", "allowed"))
        return await super().run(vsock_path, code, timeout)


@pytest.fixture
def parts(tmp_path: Path, test_prefix: str):
    eng = FakeEngine()
    net = FakeNetPolicy(prefix=test_prefix)
    ex = EmittingExec(net=net)
    return eng, net, ex, tmp_path


def make_pool(parts, size: int = 2, network: str = "deny") -> SandboxPool:
    eng, net, ex, tmp = parts
    p = SandboxPool(size, network, _engine=eng, _netpolicy=net, _exec=ex, _workdir=tmp)
    p._retry_min = 0.01
    p._retry_max = 0.05
    return p


async def settle(p: SandboxPool) -> None:
    while p._pending:
        await asyncio.gather(*list(p._pending), return_exceptions=True)
    for _ in range(10):
        await asyncio.sleep(0)


def assert_clean(eng: FakeEngine, net: FakeNetPolicy) -> None:
    assert eng.leaks() == []
    assert net.leaks() == []


# --------------------------------------------------------------------------
# Public surface and arguments
# --------------------------------------------------------------------------


def test_public_exports():
    assert sorted(emberpool.__all__) == ["Result", "Sandbox", "SandboxPool", "Settings"]
    assert emberpool.SandboxPool is SandboxPool
    assert emberpool.Sandbox is Sandbox
    assert emberpool.Result is Result
    assert not hasattr(emberpool, "hello")


@pytest.mark.parametrize("size", [0, -1, True, 1.5, pool_mod.MAX_POOL_SIZE + 1])
def test_bad_size(parts, size):
    with pytest.raises((TypeError, ValueError)):
        make_pool(parts, size=size)


@pytest.mark.parametrize("network", ["", "allow", "allow:", "allow:bad name", "ALLOW:a.com", 3])
def test_bad_network(parts, network):
    with pytest.raises(ValueError):
        make_pool(parts, network=network)


def test_missing_engine_is_not_silently_faked(monkeypatch):
    # Without backends the pool uses the real ones, and refuses to be created
    # when their settings are missing.
    for var in ("FIRECRACKER", "JAILER", "KERNEL", "ROOTFS"):
        monkeypatch.delenv(f"EMBERPOOL_{var}", raising=False)
    with pytest.raises(ValueError, match="settings missing"):
        SandboxPool(1)


async def test_bad_run_arguments(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts) as p:
        for timeout in (0, -1, float("nan"), float("inf"), True, "5"):
            with pytest.raises((TypeError, ValueError)):
                await p.run("print(1)", timeout)
        with pytest.raises(TypeError):
            await p.run(b"print(1)", 5)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await p.run("x" * (pool_mod.MAX_CODE_BYTES + 1), 5)
        assert ex.calls == []
    assert_clean(eng, net)


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------


async def test_startup_builds_template_checks_vmgenid_and_fills(parts, test_prefix):
    eng, net, ex, tmp = parts
    async with make_pool(parts, size=3, network="allow:PyPI.org") as p:
        assert eng.calls[0] == ("build_template", f"{test_prefix}-tmpl")
        assert not net.template_active  # template namespace released after build
        checks = [vm for op, vm in eng.calls if op == "check_vmgenid"]
        assert len(checks) == 1
        probe = checks[0]
        # The probe is destroyed and never served.
        assert probe not in eng.running()
        assert ("cleanup", probe) in eng.calls and ("teardown", probe) in net.calls
        assert len(p._idle) == 3 and len(eng.running()) == 3
        assert all(pol == NetworkPolicy(("pypi.org",)) for pol in net.policies.values())
        assert p.network == "allow:pypi.org" and p.size == 3
    assert_clean(eng, net)


async def test_failed_build_refuses_to_start(parts):
    eng, net, ex, _ = parts
    eng.fail_build = True
    with pytest.raises(IsolationError):
        async with make_pool(parts):
            pytest.fail("pool started")
    assert_clean(eng, net)
    assert not any(op == "restore" for op, _ in eng.calls)


async def test_failed_vmgenid_check_refuses_to_start(parts):
    eng, net, ex, _ = parts
    eng.vmgenid_ok = False
    with pytest.raises(IsolationError, match="vmgenid"):
        async with make_pool(parts, size=4):
            pytest.fail("pool started")
    assert_clean(eng, net)
    # Only the probe was restored; no pool VM was created.
    assert sum(op == "restore" for op, _ in eng.calls) == 1


class RaisingVmgenidEngine(FakeEngine):
    async def check_vmgenid(self, vm: VMHandle) -> bool:
        raise RuntimeError("probe broke")


async def test_vmgenid_check_error_refuses_to_start(tmp_path, test_prefix):
    eng, net = RaisingVmgenidEngine(), FakeNetPolicy(prefix=test_prefix)
    p = SandboxPool(2, _engine=eng, _netpolicy=net, _exec=FakeExecClient(), _workdir=tmp_path)
    with pytest.raises(RuntimeError, match="probe broke"):
        async with p:
            pytest.fail("pool started")
    assert_clean(eng, net)


class TruthyVmgenidEngine(FakeEngine):
    async def check_vmgenid(self, vm: VMHandle) -> bool:
        return "yes"  # type: ignore[return-value]


async def test_vmgenid_check_needs_exactly_true(tmp_path, test_prefix):
    eng, net = TruthyVmgenidEngine(), FakeNetPolicy(prefix=test_prefix)
    p = SandboxPool(1, _engine=eng, _netpolicy=net, _exec=FakeExecClient(), _workdir=tmp_path)
    with pytest.raises(IsolationError):
        async with p:
            pass
    assert_clean(eng, net)


async def test_failed_initial_restore_refuses_to_start(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1):
        pass
    eng2, net2 = FakeEngine(), FakeNetPolicy(prefix=net.prefix)
    p = SandboxPool(4, _engine=eng2, _netpolicy=net2, _exec=ex, _workdir=parts[3])
    # Probe succeeds, one of the four pool restores fails.
    orig = eng2.restore
    count = 0

    async def restore(template, vm_id, netns):
        nonlocal count
        count += 1
        if count == 3:
            raise IsolationError("fake: restore failed")
        return await orig(template, vm_id, netns)

    eng2.restore = restore  # type: ignore[method-assign]
    with pytest.raises(IsolationError, match="restore failed"):
        async with p:
            pytest.fail("pool started")
    assert_clean(eng2, net2)


async def test_failed_net_setup_refuses_to_start(parts):
    eng, net, ex, _ = parts
    net.fail_setup = True
    with pytest.raises(IsolationError):
        async with make_pool(parts):
            pass
    assert_clean(eng, net)


async def test_cancelled_startup_cleans_up(parts):
    eng, net, ex, _ = parts
    eng.restore_delay = 0.05
    p = make_pool(parts, size=4)

    async def enter() -> None:
        async with p:
            await asyncio.sleep(10)

    task = asyncio.create_task(enter())
    await asyncio.sleep(0.07)  # probe done, pool restores in flight
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_clean(eng, net)


async def test_enter_twice_is_refused(parts):
    p = make_pool(parts)
    async with p:
        with pytest.raises(RuntimeError):
            await p.__aenter__()
    with pytest.raises(RuntimeError):
        async with p:
            pass


async def test_workdir_made_and_removed_when_not_given(test_prefix):
    eng, net = FakeEngine(), FakeNetPolicy(prefix=test_prefix)
    p = SandboxPool(1, _engine=eng, _netpolicy=net, _exec=FakeExecClient())
    async with p:
        workdir = p._workdir
        assert workdir is not None and workdir.is_dir()
    assert not workdir.exists()
    assert_clean(eng, net)


# --------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------


async def test_run_checks_out_and_replaces(parts):
    eng, net, ex, _ = parts
    eng.changes = ("/etc/x",)
    async with make_pool(parts, size=2) as p:
        idle_before = {vm.vm_id for vm in p._idle}
        result = await p.run("print(1)", timeout=5)
        assert isinstance(result, Result)
        assert result.stdout == "ran: print(1)\n" and result.exit_code == 0
        assert result.timed_out is False
        assert result.file_changes == ("/etc/x",)
        used = vm_of(ex.calls[0][0])
        assert used in idle_before
        # The trace holds exactly the events for that VM.
        assert [e.vm_id for e in result.trace] == [used, used]
        assert isinstance(result.trace.events[0], DnsEvent)
        # Destroyed in protocol order.
        ops = [op for op, vm in eng.calls if vm == used]
        assert ops[-3:] == ["kill", "list_changes", "cleanup"]
        assert ("teardown", used) in net.calls and used not in eng.running()
        await settle(p)
        assert len(p._idle) == 2
        assert used not in {vm.vm_id for vm in p._idle}
        assert len(eng.running()) == 2
    assert_clean(eng, net)


async def test_each_run_gets_a_fresh_vm(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        for _ in range(5):
            await p.run("x", timeout=5)
        used = [vm_of(c[0]) for c in ex.calls]
        assert len(set(used)) == 5
    assert_clean(eng, net)


async def test_concurrent_runs_hold_pool_size(parts):
    eng, net, ex, _ = parts
    ex.delay = 0.01
    eng.restore_delay = 0.005
    async with make_pool(parts, size=3) as p:
        results = await asyncio.gather(*(p.run(f"print({i})", timeout=5) for i in range(25)))
        assert [r.stdout for r in results] == [f"ran: print({i})\n" for i in range(25)]
        used = [vm_of(c[0]) for c in ex.calls]
        assert len(set(used)) == 25
        for r in results:
            ids = {e.vm_id for e in r.trace}
            assert len(ids) == 1  # no events from another VM
        await settle(p)
        assert len(p._idle) == 3
        assert len(eng.running()) == 3
        assert len(net.handles) == 3
        # Uplink indexes were all released and reused, never doubled.
        assert len(p._free_indexes) == pool_mod.MAX_UPLINKS - 3
    assert_clean(eng, net)


async def test_timeout_kills_vm(parts):
    eng, net, ex, _ = parts
    ex.delay = 10
    async with make_pool(parts, size=1) as p:
        loop = asyncio.get_running_loop()
        start = loop.time()
        result = await p.run("while True: pass", timeout=0.1)
        assert loop.time() - start < 2
        assert result.timed_out is True
        assert result.exit_code == NO_RESULT_EXIT_CODE
        assert result.stdout == "" and result.stderr == ""
        used = vm_of(ex.calls[0][0])
        assert ("kill", used) in eng.calls
        assert used not in eng.running()
        assert [e.vm_id for e in result.trace] == [used, used]
    assert_clean(eng, net)


async def test_client_side_timeout_counts_as_timeout(parts):
    eng, net, ex, _ = parts

    class Slow(FakeExecClient):
        async def run(self, vsock_path, code, timeout):
            raise TimeoutError

    p = SandboxPool(1, _engine=eng, _netpolicy=net, _exec=Slow(), _workdir=parts[3])
    async with p:
        r = await p.run("x", 5)
        assert r.timed_out is True
    assert_clean(eng, net)


async def test_agent_failure_keeps_trace(parts):
    eng, net, ex, _ = parts
    ex.fail = True
    async with make_pool(parts, size=1) as p:
        r = await p.run("import os; os.kill(1, 9)", timeout=5)
        assert r.timed_out is False
        assert r.exit_code == NO_RESULT_EXIT_CODE
        assert r.stdout == "" and "emberpool" in r.stderr
        assert len(r.trace) == 2  # host evidence survives a dead agent
    assert_clean(eng, net)


async def test_unexpected_exec_error_propagates_after_teardown(parts):
    eng, net, ex, _ = parts
    ex.behaviour = lambda code: (_ for _ in ()).throw(KeyError("boom"))  # type: ignore[assignment]
    async with make_pool(parts, size=1) as p:
        with pytest.raises(KeyError):
            await p.run("x", 5)
        used = vm_of(ex.calls[0][0])
        assert used not in eng.running() and used not in net.handles
    assert_clean(eng, net)


async def test_cancelled_run_destroys_vm(parts):
    eng, net, ex, _ = parts
    ex.delay = 10
    async with make_pool(parts, size=1) as p:
        task = asyncio.create_task(p.run("x", 30))
        while not ex.calls:
            await asyncio.sleep(0.005)
        used = vm_of(ex.calls[0][0])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert used not in eng.running()
        assert used not in net.handles
        await settle(p)
        assert len(p._idle) == 1
    assert_clean(eng, net)


# --------------------------------------------------------------------------
# Empty pool and replacement failures
# --------------------------------------------------------------------------


async def test_empty_pool_waits_for_replacement(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        eng.restore_delay = 0.1
        a, b = await asyncio.gather(p.run("a", 5), p.run("b", 5))
        assert a.exit_code == 0 and b.exit_code == 0
    assert_clean(eng, net)


async def test_empty_pool_wait_counts_against_timeout(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        eng.restore_delay = 5
        await p.run("a", 5)  # takes the only VM; the replacement is slow
        with pytest.raises(TimeoutError, match="no idle sandbox"):
            await p.run("b", 0.1)
        assert len(ex.calls) == 1  # b never ran
    assert_clean(eng, net)


async def test_replacement_failure_does_not_wedge(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        eng.fail_restore = 3
        await p.run("a", 5)
        r = await p.run("b", 5)  # waits through three failed restores
        assert r.exit_code == 0
        await settle(p)
        assert len(p._idle) == 1
        assert eng.fail_restore == 0
    assert_clean(eng, net)


async def test_replacement_failing_forever_times_out_cleanly(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=2) as p:
        eng.fail_restore = True
        await asyncio.gather(p.run("a", 5), p.run("b", 5))
        with pytest.raises(TimeoutError, match="last restore failed"):
            await p.run("c", 0.2)
        # Retries are still going; the pool stays usable once restores recover.
        eng.fail_restore = 0
        r = await p.run("d", 5)
        assert r.exit_code == 0
    assert_clean(eng, net)


# --------------------------------------------------------------------------
# Shutdown
# --------------------------------------------------------------------------


async def test_shutdown_after_error_in_body(parts):
    eng, net, ex, _ = parts
    with pytest.raises(ZeroDivisionError):
        async with make_pool(parts, size=3) as p:
            await p.run("x", 5)
            1 / 0
    assert_clean(eng, net)
    assert p._pending == set()
    assert p._dispatcher is not None and p._dispatcher.done()


async def test_shutdown_with_runs_and_restores_in_flight(parts):
    eng, net, ex, _ = parts
    ex.delay = 10
    async with make_pool(parts, size=2) as p:
        eng.restore_delay = 10
        runs = [asyncio.create_task(p.run(str(i), 30)) for i in range(3)]
        while len(ex.calls) < 2:
            await asyncio.sleep(0.005)
        assert p._pending  # replacements in flight
    # Every VM is gone, including the ones still running code.
    assert_clean(eng, net)
    for task in runs:
        task.cancel()
    outcomes = await asyncio.gather(*runs, return_exceptions=True)
    # The waiter (no idle VM) saw the pool close.
    assert any(isinstance(o, RuntimeError) for o in outcomes)
    assert_clean(eng, net)


async def test_run_after_close_is_refused(parts):
    p = make_pool(parts)
    async with p:
        pass
    with pytest.raises(RuntimeError):
        await p.run("x", 5)


async def test_teardown_survives_failing_steps(parts, caplog):
    eng, net, ex, _ = parts

    class BadKill(FakeEngine):
        async def kill(self, vm):
            await super().kill(vm)
            raise OSError("kill failed")

    eng = BadKill()
    p = SandboxPool(1, _engine=eng, _netpolicy=net, _exec=ex, _workdir=parts[3])
    async with p:
        r = await p.run("x", 5)
        assert r.exit_code == 0
        assert r.file_changes == ()  # not read after a failed kill
        used = vm_of(ex.calls[0][0])
        assert ("cleanup", used) in eng.calls  # cleanup still runs and kills
        assert used not in net.handles
    assert_clean(eng, net)
    # cleanup succeeded (it kills too), so the uplink indexes came back.
    assert len(p._free_indexes) == pool_mod.MAX_UPLINKS
    assert "kill failed" in caplog.text


async def test_failing_net_teardown_retires_index(parts):
    eng, net, ex, _ = parts

    class BadTeardown(FakeNetPolicy):
        async def teardown(self, handle):
            await super().teardown(handle)
            raise OSError("teardown failed")

    net = BadTeardown(prefix=net.prefix)
    p = SandboxPool(1, _engine=eng, _netpolicy=net, _exec=FakeExecClient(), _workdir=parts[3])
    async with p:
        await p.run("x", 5)
    assert_clean(eng, net)
    assert p._free_indexes.isdisjoint({0, 1, 2})


# --------------------------------------------------------------------------
# Sandbox via checkout
# --------------------------------------------------------------------------


async def test_checkout_sandbox_runs_once(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        async with p.checkout(timeout=5) as sb:
            assert isinstance(sb, Sandbox)
            r = await sb.run("x", timeout=5)
            assert r.exit_code == 0
            assert sb.vm_id not in eng.running()
            with pytest.raises(RuntimeError):
                await sb.run("again", timeout=5)
        assert len(ex.calls) == 1
    assert_clean(eng, net)


async def test_unused_checkout_is_destroyed(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        async with p.checkout(timeout=5) as sb:
            vm_id = sb.vm_id
            assert vm_id in eng.running()
        assert vm_id not in eng.running() and vm_id not in net.handles
        with pytest.raises(RuntimeError):
            await sb.run("late", timeout=5)
        await settle(p)
        assert len(p._idle) == 1
    assert_clean(eng, net)


async def test_checkout_bad_timeout(parts):
    async with make_pool(parts) as p:
        with pytest.raises(ValueError):
            p.checkout(timeout=0)


# --------------------------------------------------------------------------
# Trace integrity
# --------------------------------------------------------------------------


async def test_events_for_unknown_vms_are_ignored(parts):
    eng, net, ex, _ = parts
    async with make_pool(parts, size=1) as p:
        net.emit(DnsEvent(0.0, "deadbeef", "evil.com", None))
        r = await p.run("x", 5)
        assert all(e.vm_id != "deadbeef" for e in r.trace)
    assert_clean(eng, net)


async def test_trace_overflow_fails_closed(parts, monkeypatch):
    eng, net, ex, _ = parts
    monkeypatch.setattr(pool_mod, "MAX_TRACE_EVENTS", 5)
    ex.events_per_run = 10
    async with make_pool(parts, size=1) as p:
        with pytest.raises(IsolationError, match="incomplete"):
            await p.run("flood", 5)
        ex.events_per_run = 1
        r = await p.run("ok", 5)
        assert len(r.trace) == 2
    assert_clean(eng, net)


class BrokenStream(FakeNetPolicy):
    broken: asyncio.Event | None = None

    async def events(self) -> AsyncIterator[DnsEvent | ConnEvent]:
        assert self.broken is not None
        await self.broken.wait()
        raise OSError("resolver log gone")
        yield  # pragma: no cover


async def test_event_stream_failure_fails_closed(tmp_path, test_prefix):
    eng, net = FakeEngine(), BrokenStream(prefix=test_prefix)
    net.broken = asyncio.Event()
    ex = FakeExecClient(delay=0.05)
    p = SandboxPool(2, _engine=eng, _netpolicy=net, _exec=ex, _workdir=tmp_path)
    async with p:
        running = asyncio.create_task(p.run("x", 5))
        await asyncio.sleep(0.01)
        net.broken.set()
        with pytest.raises(IsolationError, match="event stream"):
            await running
        with pytest.raises(IsolationError):
            await p.run("y", 5)
    assert_clean(eng, net)


async def test_event_stream_ending_fails_closed(tmp_path, test_prefix):
    class Ending(FakeNetPolicy):
        async def events(self):
            return
            yield  # pragma: no cover

    eng, net = FakeEngine(), Ending(prefix=test_prefix)
    p = SandboxPool(1, _engine=eng, _netpolicy=net, _exec=FakeExecClient(), _workdir=tmp_path)
    with pytest.raises(IsolationError):
        async with p:
            await p.run("x", 5)
    assert_clean(eng, net)
