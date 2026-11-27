"""The warm pool: SandboxPool and Sandbox.

The pool codes only against the protocols in `emberpool.engine`. It never talks
to Firecracker, `ip` or `nft` itself.

Lifecycle:

    enter   start the event dispatcher, build the template in a template
            namespace, restore one probe VM and refuse to start unless its
            VMGenID driver is bound, destroy the probe, restore `size` VMs.
    run     take an idle VM (waiting if none is idle), start a replacement
            restore in the background, run the code under a host deadline,
            destroy the VM, return its Result.
    exit    stop replacements, destroy every VM the pool still holds, stop
            the dispatcher, remove the work directory if the pool made it.

Every VM is destroyed through one memoised task, so a run finishing and the
pool closing at the same time release it exactly once, and the release keeps
going if the awaiting task is cancelled (docs/40-rules.md rule 12).
"""

from __future__ import annotations

import asyncio
import collections
import logging
import math
import shutil
import tempfile
from collections.abc import AsyncIterator, Coroutine
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Literal, Self, TypeVar

from emberpool._names import new_vm_id
from emberpool._protocol import MAX_CODE_BYTES, MAX_TIMEOUT
from emberpool._types import (
    MAX_UPLINKS,
    ConnEvent,
    DnsEvent,
    Event,
    ExecError,
    ExecResult,
    IsolationError,
    NetHandle,
    NetworkPolicy,
    Result,
    Template,
    Trace,
    VMHandle,
)
from emberpool.engine import Engine, ExecClient, NetPolicy

__all__ = ["SandboxPool", "Sandbox", "Result"]

log = logging.getLogger("emberpool")

T = TypeVar("T")

# Idle VMs plus running ones must fit in the uplink index space, so cap the
# idle count well below it.
MAX_POOL_SIZE = MAX_UPLINKS // 2

# Per-VM trace cap. A guest that floods past it gets an error, not a silently
# truncated trace.
MAX_TRACE_EVENTS = 100_000

# exit_code reported when there is no guest result: the host killed the VM, or
# the guest agent did not reply properly.
NO_RESULT_EXIT_CODE = -1

# Bounds on each lifecycle call (rule 13). Generous: they only stop a hang.
_BUILD_TIMEOUT = 600.0
_STEP_TIMEOUT = 120.0

# Yields given to the event dispatcher before a VM's trace is closed, so events
# already delivered by NetPolicy.events() are routed to it.
_TRACE_SETTLE_YIELDS = 5

_State = Literal["new", "starting", "open", "closed"]


async def _shielded(aw: Coroutine[Any, Any, T] | asyncio.Future[T]) -> T:
    """Await `aw` to completion even if the caller is cancelled meanwhile, then
    re-raise the cancellation."""
    task = asyncio.ensure_future(aw)
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            if task.done():
                raise
            cancelled = True
    if cancelled:
        raise asyncio.CancelledError
    return result


def _check_timeout(timeout: object) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number of seconds")
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be in (0, {MAX_TIMEOUT}] seconds: {timeout!r}")
    return float(timeout)


def _check_code(code: object) -> str:
    if not isinstance(code, str):
        raise TypeError("code must be a str")
    if len(code.encode("utf-8", "surrogatepass")) > MAX_CODE_BYTES:
        raise ValueError(f"code is larger than {MAX_CODE_BYTES} bytes")
    return code


@dataclass(eq=False)
class _VM:
    """One VM the pool holds, from net setup to final teardown."""

    vm_id: str
    index: int
    net: NetHandle | None = None
    handle: VMHandle | None = None
    events: list[Event] = field(default_factory=list)
    overflowed: bool = False
    file_changes: tuple[str, ...] = ()
    destroy_task: asyncio.Task[None] | None = None


class Sandbox:
    """One checked-out VM, used for a single run.

    Get one from `SandboxPool.checkout()`. It is destroyed when `run` returns
    or when the checkout block exits, whichever comes first.
    """

    __slots__ = ("_pool", "_vm", "_used")

    def __init__(self, pool: SandboxPool, vm: _VM) -> None:
        self._pool = pool
        self._vm = vm
        self._used = False

    @property
    def vm_id(self) -> str:
        return self._vm.vm_id

    def __repr__(self) -> str:
        return f"<Sandbox {self._vm.vm_id}{' used' if self._used else ''}>"

    async def run(self, code: str, timeout: float) -> Result:
        """Run `code` in the guest with a wall-clock limit of `timeout` seconds,
        enforced by the host killing the VM. The VM is destroyed afterwards."""
        _check_code(code)
        _check_timeout(timeout)
        return await self._run(code, timeout)

    async def _run(self, code: str, timeout: float) -> Result:
        if self._used:
            raise RuntimeError("a Sandbox runs code only once")
        self._used = True
        vm = self._vm
        pool = self._pool
        if vm.handle is None or vm.destroy_task is not None:
            raise RuntimeError("sandbox is no longer available")

        reply: ExecResult | None = None
        timed_out = False
        agent_failed = False
        try:
            try:
                async with asyncio.timeout(timeout):
                    reply = await pool._exec.run(vm.handle.vsock_path, code, max(timeout, 0.001))
            except TimeoutError:
                timed_out = True
            except ExecError as exc:
                agent_failed = True
                log.warning("vm %s: exec channel failed: %s", vm.vm_id, type(exc).__name__)
        finally:
            # The host kills: kill is the first step of destroy (rule 14).
            await _shielded(pool._destroy(vm))

        trace = pool._trace_of(vm)
        if timed_out:
            return Result("", "", NO_RESULT_EXIT_CODE, True, trace, vm.file_changes)
        if agent_failed or not isinstance(reply, ExecResult):
            return Result(
                "",
                "emberpool: the guest agent did not return a valid result\n",
                NO_RESULT_EXIT_CODE,
                False,
                trace,
                vm.file_changes,
            )
        return Result(reply.stdout, reply.stderr, reply.exit_code, False, trace, vm.file_changes)


class SandboxPool:
    """A warm pool of restored microVMs.

    `size` idle VMs are kept ready. `network` is "deny" (the default) or
    "allow:<name>,<name>,...". Use as an async context manager.

    The keyword arguments starting with an underscore are internal (tests and
    engine wiring) and not part of the public API.
    """

    _retry_min = 0.1
    _retry_max = 10.0

    def __init__(
        self,
        size: int,
        network: str = "deny",
        *,
        _engine: Engine | None = None,
        _netpolicy: NetPolicy | None = None,
        _exec: ExecClient | None = None,
        _workdir: Path | None = None,
    ) -> None:
        if isinstance(size, bool) or not isinstance(size, int):
            raise TypeError("size must be an int")
        if not 1 <= size <= MAX_POOL_SIZE:
            raise ValueError(f"size must be in 1..{MAX_POOL_SIZE}: {size}")
        self._size = size
        self._policy = NetworkPolicy.parse(network)
        if _engine is None or _netpolicy is None or _exec is None:
            raise NotImplementedError(
                "the Firecracker engine is not wired in yet; pass _engine, _netpolicy and _exec"
            )
        self._engine: Engine = _engine
        self._net: NetPolicy = _netpolicy
        self._exec: ExecClient = _exec
        self._given_workdir = _workdir
        self._workdir: Path | None = None
        self._made_workdir = False

        self._state: _State = "new"
        self._template: Template | None = None
        self._live: dict[str, _VM] = {}
        self._idle: collections.deque[_VM] = collections.deque()
        self._cond = asyncio.Condition()
        self._pending: set[asyncio.Task[None]] = set()
        self._free_indexes: set[int] = set(range(MAX_UPLINKS))
        self._index_sem = asyncio.Semaphore(MAX_UPLINKS)
        self._dispatcher: asyncio.Task[None] | None = None
        self._broken: BaseException | None = None
        self._last_restore_error: BaseException | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        return self._size

    @property
    def network(self) -> str:
        return str(self._policy)

    async def __aenter__(self) -> Self:
        if self._state != "new":
            raise RuntimeError("a SandboxPool can be entered only once")
        self._state = "starting"
        try:
            await self._start()
        except BaseException:
            await _shielded(self._shutdown())
            raise
        self._state = "open"
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await _shielded(self._shutdown())

    async def run(self, code: str, timeout: float) -> Result:
        """Run `code` in a fresh VM and return its Result.

        `timeout` is one wall-clock deadline covering both the wait for an idle
        VM and the run itself. If no VM becomes idle before the deadline,
        TimeoutError is raised and no code ran. If the deadline passes during
        the run, the host kills the VM and the Result has timed_out=True.
        """
        _check_code(code)
        timeout = _check_timeout(timeout)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        async with self.checkout(timeout) as sandbox:
            return await sandbox._run(code, deadline - loop.time())

    def checkout(self, timeout: float) -> AbstractAsyncContextManager[Sandbox]:
        """Check out one idle VM as a Sandbox, waiting up to `timeout` seconds
        for one. The VM is destroyed when the block exits."""
        return self._checkout(_check_timeout(timeout))

    # ------------------------------------------------------------------
    # Start and shutdown
    # ------------------------------------------------------------------

    async def _start(self) -> None:
        self._dispatcher = asyncio.create_task(self._dispatch_events())
        if self._given_workdir is not None:
            self._workdir = self._given_workdir
        else:
            self._workdir = Path(await asyncio.to_thread(tempfile.mkdtemp, prefix="ep-pool-"))
            self._made_workdir = True

        async with self._net.template_netns() as netns:
            async with asyncio.timeout(_BUILD_TIMEOUT):
                template = await self._engine.build_template(self._workdir, netns)
        if not isinstance(template, Template):
            raise IsolationError("engine returned no template")
        self._template = template

        await self._check_vmgenid()

        results = await asyncio.gather(
            *(self._restore_one() for _ in range(self._size)), return_exceptions=True
        )
        failures = [r for r in results if isinstance(r, BaseException)]
        for r in results:
            if isinstance(r, _VM):
                self._idle.append(r)  # destroyed by _shutdown if a sibling failed
        if failures:
            raise failures[0]
        self._raise_if_broken()

    async def _check_vmgenid(self) -> None:
        """Restore one probe VM and require its vmgenid driver to be bound. The
        probe is destroyed either way; it never serves a run (rule 15)."""
        vm = await self._restore_one()
        try:
            assert vm.handle is not None
            async with asyncio.timeout(_STEP_TIMEOUT):
                ok = await self._engine.check_vmgenid(vm.handle)
        finally:
            await _shielded(self._destroy(vm))
        if ok is not True:
            raise IsolationError(
                "the template VM has no vmgenid driver bound; refusing to start "
                "(clones would share random state)"
            )

    async def _shutdown(self) -> None:
        if self._state == "closed":
            return
        self._state = "closed"
        async with self._cond:
            self._cond.notify_all()

        pending = list(self._pending)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

        # Running sandboxes are destroyed too; their run() gets the same task.
        live = list(self._live.values())
        await asyncio.gather(*(self._destroy(vm) for vm in live), return_exceptions=True)
        self._idle.clear()

        if self._dispatcher is not None:
            self._dispatcher.cancel()
            await asyncio.gather(self._dispatcher, return_exceptions=True)

        if self._made_workdir and self._workdir is not None:
            await asyncio.to_thread(shutil.rmtree, self._workdir, True)

    # ------------------------------------------------------------------
    # Checkout and replacement
    # ------------------------------------------------------------------

    def _raise_if_broken(self) -> None:
        if self._broken is not None:
            raise IsolationError("network event stream failed; traces would be incomplete") from (
                self._broken
            )

    def _ensure_open(self) -> None:
        self._raise_if_broken()
        if self._state != "open":
            raise RuntimeError("the pool is not open")

    @asynccontextmanager
    async def _checkout(self, timeout: float) -> AsyncIterator[Sandbox]:
        vm = await self._take(timeout)
        try:
            yield Sandbox(self, vm)
        finally:
            await _shielded(self._destroy(vm))

    async def _take(self, timeout: float) -> _VM:
        self._ensure_open()
        vm: _VM | None = None
        try:
            async with asyncio.timeout(timeout):
                async with self._cond:
                    while not self._idle:
                        self._ensure_open()
                        await self._cond.wait()
                    self._ensure_open()
                    vm = self._idle.popleft()
                    self._spawn_replacement()
        except TimeoutError:
            if vm is not None:
                return vm
            msg = f"no idle sandbox within {timeout}s"
            if self._last_restore_error is not None:
                msg += f"; last restore failed: {self._last_restore_error!r}"
            raise TimeoutError(msg) from None
        except BaseException:
            if vm is not None:
                await _shielded(self._destroy(vm))
            raise
        assert vm is not None
        return vm

    def _spawn_replacement(self) -> None:
        task = asyncio.create_task(self._replace())
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _replace(self) -> None:
        """Restore one VM into the idle queue, retrying with backoff until it
        succeeds or the pool closes. A failure never blocks other restores."""
        delay = self._retry_min
        while self._state == "open" and self._broken is None:
            try:
                vm = await self._restore_one()
            except Exception as exc:
                self._last_restore_error = exc
                log.warning("replacement restore failed, retrying in %.1fs: %r", delay, exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._retry_max)
                continue
            if self._state != "open":
                await _shielded(self._destroy(vm))
                return
            async with self._cond:
                self._idle.append(vm)
                self._cond.notify()
            self._last_restore_error = None
            return

    # ------------------------------------------------------------------
    # One VM: restore and destroy
    # ------------------------------------------------------------------

    async def _alloc_index(self) -> int:
        await self._index_sem.acquire()
        return self._pop_index()

    def _pop_index(self) -> int:
        index = min(self._free_indexes)
        self._free_indexes.remove(index)
        return index

    def _release_index(self, index: int) -> None:
        self._free_indexes.add(index)
        self._index_sem.release()

    def _new_vm_id(self) -> str:
        while (vm_id := new_vm_id()) in self._live:
            pass
        return vm_id

    async def _restore_one(self) -> _VM:
        if self._template is None:
            raise RuntimeError("no template")
        index = await self._alloc_index()
        vm = _VM(self._new_vm_id(), index)
        self._live[vm.vm_id] = vm
        try:
            async with asyncio.timeout(_STEP_TIMEOUT):
                net = await self._net.setup(vm.vm_id, index, self._policy)
            vm.net = net
            if net.vm_id != vm.vm_id or net.index != index:
                raise IsolationError(f"net setup returned a handle for another VM: {net!r}")
            async with asyncio.timeout(_STEP_TIMEOUT):
                handle = await self._engine.restore(self._template, vm.vm_id, net.netns)
            vm.handle = handle
            if handle.vm_id != vm.vm_id or handle.netns != net.netns:
                raise IsolationError(f"restore returned a VM outside its namespace: {handle!r}")
        except BaseException:
            await _shielded(self._destroy(vm))
            raise
        return vm

    def _destroy(self, vm: _VM) -> asyncio.Task[None]:
        """Release one VM. Memoised: every caller awaits the same task."""
        if vm.destroy_task is None:
            vm.destroy_task = asyncio.create_task(self._destroy_steps(vm))
        return vm.destroy_task

    async def _step(self, what: str, vm: _VM, aw: Coroutine[Any, Any, T]) -> tuple[bool, T | None]:
        try:
            async with asyncio.timeout(_STEP_TIMEOUT):
                return True, await aw
        except Exception as exc:
            log.error("vm %s: %s failed: %r", vm.vm_id, what, exc)
            return False, None

    async def _destroy_steps(self, vm: _VM) -> None:
        released = True
        if vm.handle is not None:
            killed, _ = await self._step("kill", vm, self._engine.kill(vm.handle))
            if killed:
                ok, changes = await self._step("list_changes", vm, self._engine.list_changes(vm.handle))
                if ok and isinstance(changes, tuple) and all(isinstance(c, str) for c in changes):
                    vm.file_changes = changes
            cleaned, _ = await self._step("cleanup", vm, self._engine.cleanup(vm.handle))
            released = released and cleaned
        if vm.net is not None:
            torn, _ = await self._step("net teardown", vm, self._net.teardown(vm.net))
            released = released and torn

        # Let the dispatcher route events NetPolicy has already delivered.
        for _ in range(_TRACE_SETTLE_YIELDS):
            await asyncio.sleep(0)
        self._live.pop(vm.vm_id, None)
        if released:
            self._release_index(vm.index)
        else:
            # Keep the uplink index out of use: something may still hold it.
            log.error("vm %s: not fully released; uplink %d retired", vm.vm_id, vm.index)

    # ------------------------------------------------------------------
    # Trace
    # ------------------------------------------------------------------

    async def _dispatch_events(self) -> None:
        stream = self._net.events()
        try:
            async for event in stream:
                if not isinstance(event, (DnsEvent, ConnEvent)):
                    raise TypeError(f"not a trace event: {type(event).__name__}")
                vm = self._live.get(event.vm_id)
                if vm is None:
                    continue
                if len(vm.events) < MAX_TRACE_EVENTS:
                    vm.events.append(event)
                else:
                    vm.overflowed = True
            raise IsolationError("network event stream ended")
        except Exception as exc:
            log.error("network event stream failed: %r", exc)
            self._broken = exc
            async with self._cond:
                self._cond.notify_all()
        finally:
            aclose = getattr(stream, "aclose", None)
            if aclose is not None:
                try:
                    await aclose()
                except Exception:
                    pass

    def _trace_of(self, vm: _VM) -> Trace:
        """The VM's trace. Refuses to return one that is known incomplete."""
        self._raise_if_broken()
        if vm.overflowed:
            raise IsolationError(
                f"vm {vm.vm_id} produced more than {MAX_TRACE_EVENTS} network events; "
                "the trace is incomplete"
            )
        return Trace(events=tuple(vm.events))
