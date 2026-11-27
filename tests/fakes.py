"""In-memory implementations of the engine protocols, for pool tests.

Each fake records calls and has knobs to inject delays and failures. They keep
the same resource rules as the real classes: kill, cleanup and teardown are
idempotent, and `leaks()` reports anything still held.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from emberpool._names import validate_netns, validate_vm_id
from emberpool._types import (
    ConnEvent,
    DnsEvent,
    ExecError,
    ExecResult,
    IsolationError,
    NetHandle,
    NetworkPolicy,
    Template,
    VMHandle,
)

__all__ = ["FakeEngine", "FakeNetPolicy", "FakeExecClient", "FakeVM"]


@dataclass
class FakeVM:
    handle: VMHandle
    running: bool = True
    scratch: bool = True


@dataclass
class FakeEngine:
    """Engine protocol in memory.

    fail_build:    raise IsolationError from build_template.
    fail_restore:  number of upcoming restores to fail (or True for all).
    vmgenid_ok:    what check_vmgenid returns.
    restore_delay: seconds each restore takes.
    changes:       what list_changes returns.
    """

    fail_build: bool = False
    fail_restore: int | bool = 0
    vmgenid_ok: bool = True
    restore_delay: float = 0.0
    changes: tuple[str, ...] = ()

    template: Template | None = None
    vms: dict[str, FakeVM] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    _pids: itertools.count[int] = field(default_factory=lambda: itertools.count(1000))

    async def build_template(self, workdir: Path, netns: str) -> Template:
        validate_netns(netns)
        self.calls.append(("build_template", netns))
        if self.fail_build:
            raise IsolationError("fake: template build failed")
        self.template = Template(workdir / "state", workdir / "mem", workdir / "rootfs.ext4")
        return self.template

    async def restore(self, template: Template, vm_id: str, netns: str) -> VMHandle:
        validate_vm_id(vm_id)
        validate_netns(netns)
        self.calls.append(("restore", vm_id))
        if self.restore_delay:
            await asyncio.sleep(self.restore_delay)
        if self.fail_restore is True or (
            not isinstance(self.fail_restore, bool) and self.fail_restore > 0
        ):
            if not isinstance(self.fail_restore, bool):
                self.fail_restore -= 1
            raise IsolationError(f"fake: restore of {vm_id} failed")
        if vm_id in self.vms:
            raise RuntimeError(f"fake: vm_id reused: {vm_id}")
        handle = VMHandle(
            vm_id=vm_id,
            pid=next(self._pids),
            vsock_path=Path(f"/fake/{vm_id}/v.sock"),
            scratch_path=Path(f"/fake/{vm_id}/scratch.ext4"),
            netns=netns,
        )
        self.vms[vm_id] = FakeVM(handle)
        return handle

    async def kill(self, vm: VMHandle) -> None:
        self.calls.append(("kill", vm.vm_id))
        if (fake := self.vms.get(vm.vm_id)) is not None:
            fake.running = False

    async def check_vmgenid(self, vm: VMHandle) -> bool:
        self.calls.append(("check_vmgenid", vm.vm_id))
        return self.vmgenid_ok

    async def list_changes(self, vm: VMHandle) -> tuple[str, ...]:
        self.calls.append(("list_changes", vm.vm_id))
        fake = self.vms.get(vm.vm_id)
        if fake is None or not fake.scratch:
            raise RuntimeError(f"fake: no scratch drive for {vm.vm_id}")
        if fake.running:
            raise RuntimeError(f"fake: list_changes before kill for {vm.vm_id}")
        return self.changes

    async def cleanup(self, vm: VMHandle) -> None:
        self.calls.append(("cleanup", vm.vm_id))
        if (fake := self.vms.get(vm.vm_id)) is not None:
            fake.running = False
            fake.scratch = False

    def running(self) -> list[str]:
        return [vm_id for vm_id, vm in self.vms.items() if vm.running]

    def leaks(self) -> list[str]:
        """VM ids still running or holding a scratch drive."""
        return [vm_id for vm_id, vm in self.vms.items() if vm.running or vm.scratch]


@dataclass
class FakeNetPolicy:
    """NetPolicy protocol in memory.

    fail_setup: number of upcoming setups to fail (or True for all).
    Use emit() to push events into events().
    """

    fail_setup: int | bool = 0
    prefix: str = "ep-fake"

    handles: dict[str, NetHandle] = field(default_factory=dict)
    policies: dict[str, NetworkPolicy] = field(default_factory=dict)
    template_active: bool = False
    calls: list[tuple[str, str]] = field(default_factory=list)
    _queue: asyncio.Queue[DnsEvent | ConnEvent] = field(default_factory=asyncio.Queue)

    async def setup(self, vm_id: str, index: int, policy: NetworkPolicy) -> NetHandle:
        validate_vm_id(vm_id)
        self.calls.append(("setup", vm_id))
        if self.fail_setup is True or (
            not isinstance(self.fail_setup, bool) and self.fail_setup > 0
        ):
            if not isinstance(self.fail_setup, bool):
                self.fail_setup -= 1
            raise IsolationError(f"fake: net setup for {vm_id} failed")
        if any(h.index == index for h in self.handles.values()):
            raise RuntimeError(f"fake: uplink index {index} already in use")
        handle = NetHandle(vm_id, index, f"{self.prefix}-{vm_id}", f"ep-h{index}")
        self.handles[vm_id] = handle
        self.policies[vm_id] = policy
        return handle

    async def teardown(self, handle: NetHandle) -> None:
        self.calls.append(("teardown", handle.vm_id))
        self.handles.pop(handle.vm_id, None)
        self.policies.pop(handle.vm_id, None)

    @asynccontextmanager
    async def _template(self) -> AsyncIterator[str]:
        self.template_active = True
        try:
            yield f"{self.prefix}-tmpl"
        finally:
            self.template_active = False

    def template_netns(self) -> AbstractAsyncContextManager[str]:
        return self._template()

    def emit(self, event: DnsEvent | ConnEvent) -> None:
        self._queue.put_nowait(event)

    async def events(self) -> AsyncIterator[DnsEvent | ConnEvent]:
        while True:
            yield await self._queue.get()

    def leaks(self) -> list[str]:
        out = list(self.handles)
        if self.template_active:
            out.append("template-netns")
        return out


Behaviour = Callable[[str], ExecResult]


def _echo(code: str) -> ExecResult:
    return ExecResult(stdout=f"ran: {code}\n", stderr="", exit_code=0)


@dataclass
class FakeExecClient:
    """ExecClient protocol in memory.

    behaviour: maps code to an ExecResult (default echoes the code).
    delay:     seconds each run takes; longer than `timeout` raises TimeoutError.
    fail:      raise ExecError from every run.
    """

    behaviour: Behaviour = _echo
    delay: float = 0.0
    fail: bool = False
    calls: list[tuple[Path, str, float]] = field(default_factory=list)

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        self.calls.append((vsock_path, code, timeout))
        if self.fail:
            raise ExecError("fake: connection refused")
        async with asyncio.timeout(timeout):
            if self.delay:
                await asyncio.sleep(self.delay)
        return self.behaviour(code)
