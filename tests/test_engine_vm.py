"""FirecrackerEngine against real Firecracker, jailer and KVM. Root only.

Needs:
  EMBERPOOL_FC_DIR      directory with `firecracker`, `Image` and the jailer
                        (`jailer`, or `release-*/jailer-*-<arch>`)
  EMBERPOOL_TEST_ROOTFS guest image with the emberpool agent (default:
                        $EMBERPOOL_FC_DIR/ep-exec-rootfs.ext4)

Every namespace, directory and cgroup is named with the test prefix and
removed afterwards.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from emberpool import _firecracker as fcmod
from emberpool._firecracker import SCRATCH_BASE_NAME, FirecrackerConfig, FirecrackerEngine
from emberpool._jailer import CGROUP_ROOT, NETNS_DIR, JailerConfig
from emberpool._names import new_vm_id
from emberpool._protocol import decode_response, encode_request, read_frame
from emberpool._types import (
    GUEST_IP,
    TAP_HOST_CIDR,
    TAP_MAC,
    TAP_NAME,
    IsolationError,
    EmberpoolError,
    ExecResult,
    Template,
    VMHandle,
)

pytestmark = pytest.mark.vm

JAIL_UID = 10123


# -- environment ----------------------------------------------------------------


def _find_jailer(fc_dir: Path) -> Path | None:
    if (fc_dir / "jailer").is_file():
        return fc_dir / "jailer"
    arch = platform.machine()
    for path in sorted(fc_dir.glob(f"release-*/jailer-*-{arch}")):
        if path.is_file():
            return path
    return None


@dataclass(frozen=True)
class Env:
    prefix: str
    base: Path
    config: FirecrackerConfig


def _ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True, capture_output=True, timeout=10)


class Namespaces:
    """Creates prefixed namespaces with tap0 and removes only those."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.created: list[str] = []

    def make(self, tag: str) -> str:
        name = f"{self.prefix}-{tag}"
        self.created.append(name)
        _ip("netns", "add", name)
        _ip("-n", name, "link", "set", "lo", "up")
        _ip("-n", name, "tuntap", "add", "dev", TAP_NAME, "mode", "tap")
        _ip("-n", name, "link", "set", TAP_NAME, "address", TAP_MAC)
        _ip("-n", name, "addr", "add", TAP_HOST_CIDR, "dev", TAP_NAME)
        _ip("-n", name, "link", "set", TAP_NAME, "up")
        return name

    def remove(self, name: str) -> None:
        if name in self.created:
            subprocess.run(["ip", "netns", "del", name], capture_output=True, timeout=10)
            self.created.remove(name)

    def remove_all(self) -> None:
        for name in list(self.created):
            self.remove(name)


# Every VM id used in this module (tests and template builds). The jailer
# pivots into its own mount namespace, so /proc/<pid>/root cannot identify our
# processes; Firecracker's "--id <vm_id>" argument can.
KNOWN_IDS: set[str] = set()


def vid() -> str:
    vm_id = new_vm_id()
    KNOWN_IDS.add(vm_id)
    return vm_id


def _our_vmm_pids() -> list[int]:
    """PIDs of jailer/firecracker processes started for one of KNOWN_IDS."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            argv = Path(f"/proc/{entry}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        for i, arg in enumerate(argv[:-1]):
            if arg == b"--id" and argv[i + 1].decode("ascii", "replace") in KNOWN_IDS:
                pids.append(int(entry))
                break
    return pids


@pytest.fixture(scope="session")
def env(test_prefix: str) -> Iterator[Env]:
    fc_dir_text = os.environ.get("EMBERPOOL_FC_DIR")
    if not fc_dir_text:
        pytest.skip("EMBERPOOL_FC_DIR not set")
    fc_dir = Path(fc_dir_text)
    jailer = _find_jailer(fc_dir)
    rootfs = Path(os.environ.get("EMBERPOOL_TEST_ROOTFS", fc_dir / "ep-exec-rootfs.ext4"))
    for path in (fc_dir / "firecracker", fc_dir / "Image", rootfs):
        if not path.is_file():
            pytest.skip(f"missing {path}")
    if jailer is None:
        pytest.skip(f"no jailer in {fc_dir}")
    original_new_vm_id = fcmod.new_vm_id

    def recording_new_vm_id() -> str:
        vm_id = original_new_vm_id()
        KNOWN_IDS.add(f"tmpl-{vm_id}")
        return vm_id

    fcmod.new_vm_id = recording_new_vm_id  # template ids are "tmpl-<new_vm_id()>"
    base = Path(tempfile.mkdtemp(prefix=f"{test_prefix}-", dir="/tmp"))
    os.chmod(base, 0o755)
    config = FirecrackerConfig(
        jailer=JailerConfig(
            jailer_bin=jailer,
            firecracker_bin=fc_dir / "firecracker",
            chroot_base=base / "j",
            uid=JAIL_UID,
            gid=JAIL_UID,
            parent_cgroup=test_prefix,
        ),
        kernel_path=fc_dir / "Image",
        rootfs_path=rootfs,
        scratch_size_mib=64,
        boot_timeout=120,
    )
    try:
        yield Env(test_prefix, base, config)
    finally:
        fcmod.new_vm_id = original_new_vm_id
        for pid in _our_vmm_pids():
            os.kill(pid, signal.SIGKILL)
        shutil.rmtree(base, ignore_errors=True)
        try:
            os.rmdir(CGROUP_ROOT / test_prefix)
        except OSError:
            pass


@pytest.fixture
def nets(env: Env) -> Iterator[Namespaces]:
    ns = Namespaces(env.prefix)
    try:
        yield ns
    finally:
        ns.remove_all()


@pytest.fixture(scope="session")
def template(env: Env) -> Template:
    ns = Namespaces(env.prefix)
    name = ns.make("tmpl")
    try:
        engine = FirecrackerEngine(env.config)
        tmpl = asyncio.run(engine.build_template(env.base / "template", name))
        assert engine.tracked() == []
        return tmpl
    finally:
        ns.remove_all()


def assert_no_leftovers(env: Env, engine: FirecrackerEngine, pids: list[int] = ()) -> None:  # type: ignore[assignment]
    assert engine.tracked() == []
    jail_dir = env.config.jailer.chroot_base / env.config.jailer.exec_name
    assert not jail_dir.exists() or list(jail_dir.iterdir()) == []
    for pid in pids:
        assert not os.path.exists(f"/proc/{pid}"), f"process {pid} still exists"
    assert _our_vmm_pids() == []
    assert list(env.base.rglob("*.sock")) == []
    assert list(Path("/tmp").glob(f"fc-{env.prefix}*.sock")) == []


# -- a minimal exec client (the real one lives in another module) ------------------


class TestExec:
    __test__ = False

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        async with asyncio.timeout(timeout + 5):
            reader, writer = await asyncio.open_unix_connection(str(vsock_path))
            try:
                writer.write(b"CONNECT 1024\n")
                await writer.drain()
                line = await reader.readline()
                if not line.startswith(b"OK "):
                    raise ConnectionRefusedError(line[:40])
                writer.write(encode_request(code, timeout))
                await writer.drain()
                resp = decode_response(await read_frame(reader))
            finally:
                writer.close()
        return ExecResult(resp.stdout, resp.stderr, resp.exit_code)


async def _netns_ping(netns: str) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "ip", "netns", "exec", netns, "ping", "-c", "1", "-W", "2", GUEST_IP,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )  # fmt: skip
    return await proc.wait() == 0


# -- tests ---------------------------------------------------------------------------


def test_template_files_are_sealed(env: Env, template: Template) -> None:
    for path in (
        template.state_path,
        template.mem_path,
        template.rootfs_path,
        template.state_path.with_name(SCRATCH_BASE_NAME),
    ):
        st = path.stat()
        assert st.st_uid == 0 and st.st_gid == JAIL_UID and (st.st_mode & 0o777) == 0o440
    # The template jail is gone.
    assert list((env.config.jailer.chroot_base / "firecracker").iterdir()) == []


async def test_restore_three_concurrently(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config, exec_client=TestExec())
    names = [nets.make(f"c{i}") for i in range(3)]
    ids = [vid() for _ in names]
    vms: list[VMHandle] = await asyncio.gather(
        *(engine.restore(template, vm_id, ns) for vm_id, ns in zip(ids, names, strict=True))
    )
    pids = [vm.pid for vm in vms]
    try:
        assert len(set(pids)) == 3
        exec_client = TestExec()
        for vm, ns in zip(vms, names, strict=True):
            # Running, jailed, confined to its own namespace.
            assert os.path.exists(f"/proc/{vm.pid}")
            # The jailer pivots into the chroot: its root holds this VM's API socket.
            jail = env.config.jailer.layout(vm.vm_id)
            assert os.stat(f"/proc/{vm.pid}/root/api.sock").st_ino == jail.api_sock.stat().st_ino
            status = Path(f"/proc/{vm.pid}/status").read_text()
            assert any(line.split()[1:2] == [str(JAIL_UID)] for line in status.splitlines() if line.startswith("Uid:"))
            assert os.stat(f"/proc/{vm.pid}/ns/net").st_ino == os.stat(NETNS_DIR / ns).st_ino
            # The guest agent answers over vsock.
            result = await exec_client.run(vm.vsock_path, "print(6 * 7)", 30)
            assert (result.stdout, result.exit_code) == ("42\n", 0)
        # Each clone is reachable on identical addressing in its own namespace.
        assert all(await asyncio.gather(*(_netns_ping(ns) for ns in names)))
        # Clones have different kernel randomness (VMGenID).
        outs = [
            (await exec_client.run(vm.vsock_path, "import os; print(os.urandom(16).hex())", 30)).stdout
            for vm in vms
        ]
        assert len(set(outs)) == 3
    finally:
        for vm in vms:
            await engine.kill(vm)
        for vm in vms:
            assert not vm.vsock_path.exists()
            assert not env.config.jailer.layout(vm.vm_id).api_sock.exists()
            assert vm.scratch_path.exists()  # kept for list_changes
            await engine.cleanup(vm)
    assert_no_leftovers(env, engine, pids)


async def test_check_vmgenid(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config, exec_client=TestExec())
    vm = await engine.restore(template, vid(), nets.make("vg"))
    try:
        assert await engine.check_vmgenid(vm) is True
        no_exec = FirecrackerEngine(env.config)
        no_exec._vms = engine._vms
        assert await no_exec.check_vmgenid(vm) is False
    finally:
        await engine.cleanup(vm)
    assert_no_leftovers(env, engine, [vm.pid])


async def test_list_changes_reads_scratch_without_mounting(
    env: Env, template: Template, nets: Namespaces
) -> None:
    engine = FirecrackerEngine(env.config)
    vm = await engine.restore(template, vid(), nets.make("lc"))
    try:
        code = (
            "import os\n"
            "os.makedirs('/root/ep-new/deep', exist_ok=True)\n"
            "open('/root/ep-new/deep/f.txt', 'w').write('hi')\n"
            "open('/root/we ird\\nname', 'w').write('x')\n"
            "os.remove('/etc/motd') if os.path.exists('/etc/motd') else None\n"
            "os.sync()\n"
        )
        result = await TestExec().run(vm.vsock_path, code, 30)
        assert result.exit_code == 0, result.stderr
        with pytest.raises(EmberpoolError, match="before kill"):
            await engine.list_changes(vm)
        await engine.kill(vm)
        mounts_before = Path("/proc/self/mounts").read_text()
        changes = await engine.list_changes(vm)
        assert Path("/proc/self/mounts").read_text() == mounts_before
        assert "/root/ep-new/deep/f.txt" in changes
        assert "/root/ep-new" in changes
        assert "/root/we ird\\x0aname" in changes
        assert all("\n" not in c for c in changes)
    finally:
        await engine.cleanup(vm)
    assert_no_leftovers(env, engine, [vm.pid])


async def test_kill_and_cleanup_are_idempotent(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config)
    vm = await engine.restore(template, vid(), nets.make("id"))
    with pytest.raises(EmberpoolError, match="already in use"):
        await engine.restore(template, vm.vm_id, vm.netns)
    await engine.kill(vm)
    await engine.kill(vm)
    assert not os.path.exists(f"/proc/{vm.pid}")
    await engine.cleanup(vm)
    await engine.cleanup(vm)
    await engine.kill(vm)
    assert_no_leftovers(env, engine, [vm.pid])


async def test_cleanup_without_kill_kills(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config)
    vm = await engine.restore(template, vid(), nets.make("ck"))
    await engine.cleanup(vm)
    assert_no_leftovers(env, engine, [vm.pid])


async def test_cgroup_created_and_removed(env: Env, template: Template, nets: Namespaces) -> None:
    jcfg = replace(env.config.jailer, cgroups=("pids.max=64",))
    engine = FirecrackerEngine(replace(env.config, jailer=jcfg))
    vm = await engine.restore(template, vid(), nets.make("cg"))
    cg = CGROUP_ROOT / env.prefix / vm.vm_id
    try:
        assert (cg / "pids.max").read_text().strip() == "64"
        assert str(vm.pid) in (cg / "cgroup.procs").read_text().split()
    finally:
        await engine.cleanup(vm)
    assert not cg.exists()
    assert_no_leftovers(env, engine, [vm.pid])


# -- fail closed -------------------------------------------------------------------------


async def test_restore_into_missing_netns_fails_closed(env: Env, template: Template) -> None:
    engine = FirecrackerEngine(env.config)
    with pytest.raises(IsolationError, match="does not exist"):
        await engine.restore(template, vid(), f"{env.prefix}-missing")
    assert_no_leftovers(env, engine)


async def test_restore_when_netns_vanishes_fails_closed(env: Env, template: Template, nets: Namespaces) -> None:
    """The jailer cannot join a namespace that is deleted after the check."""
    engine = FirecrackerEngine(env.config)
    ns = nets.make("gone")
    original = engine._check_netns
    engine._check_netns = lambda name: (original(name), nets.remove(name))[0]  # type: ignore[method-assign]
    with pytest.raises(IsolationError):
        await engine.restore(template, vid(), ns)
    assert_no_leftovers(env, engine)


async def test_restore_from_corrupt_snapshot_fails_closed(
    env: Env, template: Template, nets: Namespaces
) -> None:
    bad = env.base / "bad-template"
    bad.mkdir()
    for src in (template.mem_path, template.rootfs_path, template.state_path.with_name(SCRATCH_BASE_NAME)):
        os.link(src, bad / src.name)
    (bad / template.state_path.name).write_bytes(b"\x00not a snapshot" * 64)
    os.chown(bad / template.state_path.name, 0, JAIL_UID)
    os.chmod(bad / template.state_path.name, 0o440)
    bad_tmpl = Template(bad / template.state_path.name, bad / template.mem_path.name, bad / template.rootfs_path.name)
    engine = FirecrackerEngine(env.config)
    try:
        with pytest.raises(IsolationError, match="snapshot/load"):
            await engine.restore(bad_tmpl, vid(), nets.make("bad"))
        assert_no_leftovers(env, engine)
    finally:
        shutil.rmtree(bad)


async def test_restore_refuses_writable_template(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config)
    os.chmod(template.state_path, 0o640)
    try:
        with pytest.raises(EmberpoolError, match="read-only"):
            await engine.restore(template, vid(), nets.make("rw"))
    finally:
        os.chmod(template.state_path, 0o440)
    assert_no_leftovers(env, engine)


async def test_restore_refuses_existing_jail(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config)
    vm_id = vid()
    foreign = env.config.jailer.layout(vm_id).id_dir
    foreign.mkdir(parents=True)
    (foreign / "keep").write_text("not ours")
    try:
        with pytest.raises(IsolationError):
            await engine.restore(template, vm_id, nets.make("ex"))
        assert (foreign / "keep").read_text() == "not ours"  # never adopted or removed
        assert engine.tracked() == []
    finally:
        shutil.rmtree(foreign)
    assert_no_leftovers(env, engine)


async def test_restore_cancelled_midway_cleans_up(env: Env, template: Template, nets: Namespaces) -> None:
    engine = FirecrackerEngine(env.config)
    vm_id = vid()
    task = asyncio.create_task(engine.restore(template, vm_id, nets.make("cx")))
    api_sock = env.config.jailer.layout(vm_id).api_sock
    async with asyncio.timeout(30):
        while not api_sock.exists():
            await asyncio.sleep(0.005)
    pid = engine._vms[vm_id].proc.pid  # type: ignore[union-attr]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_no_leftovers(env, engine, [pid])


async def test_build_template_fails_closed_when_agent_never_ready(env: Env, nets: Namespaces) -> None:
    garbage_kernel = env.base / "not-a-kernel"
    garbage_kernel.write_bytes(b"\x00" * 4096)
    cfg = replace(env.config, kernel_path=garbage_kernel, boot_timeout=10)
    engine = FirecrackerEngine(cfg)
    workdir = env.base / "failed-template"
    with pytest.raises(IsolationError):
        await engine.build_template(workdir, nets.make("bk"))
    assert list(workdir.iterdir()) == []  # no partial template
    assert_no_leftovers(env, engine)


async def test_build_template_into_missing_netns_fails_closed(env: Env) -> None:
    engine = FirecrackerEngine(env.config)
    workdir = env.base / "no-netns-template"
    with pytest.raises(IsolationError, match="does not exist"):
        await engine.build_template(workdir, f"{env.prefix}-missing")
    assert list(workdir.iterdir()) == []
    assert_no_leftovers(env, engine)


async def test_build_template_refuses_dirty_rootfs(env: Env, nets: Namespaces) -> None:
    dirty = env.base / "dirty.ext4"
    subprocess.run(["truncate", "-s", "32M", str(dirty)], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", str(dirty)], check=True)
    # Mark the journal as needing recovery with debugfs (userspace, no mount).
    subprocess.run(["debugfs", "-w", "-R", "feature needs_recovery", str(dirty)], check=True, capture_output=True)
    engine = FirecrackerEngine(replace(env.config, rootfs_path=dirty))
    with pytest.raises(EmberpoolError, match="not clean"):
        await engine.build_template(env.base / "dirty-template", nets.make("dr"))
    assert_no_leftovers(env, engine)
