"""FirecrackerEngine: the Engine protocol on Firecracker v1.18 under the jailer.

The only module (with _jailer.py) that knows about Firecracker
(docs/40-rules.md rule 18).

Template build: cold boot under the jailer in the given namespace, wait for
the guest agent to accept a vsock connection on VSOCK_PORT, pause, write a
Full snapshot, then move the snapshot and the template's scratch drive into
`workdir`.

Restore: a new jail per VM with the snapshot state, memory file and shared
rootfs hard-linked in read-only, and a private copy of the template's scratch
drive, all at the paths the snapshot recorded. The jailer joins the VM's
namespace (no network_overrides); the namespace provides `tap0` with TAP_MAC.

Teardown: kill() stops the process and removes its sockets; list_changes()
reads the scratch drive with debugfs as the jail uid, never mounting it
(rule 6); cleanup() removes the jail directory, including the scratch drive.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import logging
import os
import re
import shutil
import signal
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from emberpool._jailer import (
    IN_JAIL_KERNEL,
    IN_JAIL_MEM,
    IN_JAIL_ROOTFS,
    IN_JAIL_SCRATCH,
    IN_JAIL_STATE,
    IN_JAIL_VSOCK,
    JailerConfig,
    JailLayout,
    create_jail,
    jailer_argv,
    netns_path,
    remove_cgroup,
    remove_jail,
)
from emberpool._names import (
    CommandError,
    new_vm_id,
    run_command,
    validate_netns,
    validate_vm_id,
)
from emberpool._types import (
    TAP_NAME,
    VSOCK_PORT,
    EmberpoolError,
    IsolationError,
    Template,
    VMHandle,
)
from emberpool.engine import ExecClient

__all__ = [
    "FirecrackerConfig",
    "FirecrackerEngine",
    "DEFAULT_BOOT_ARGS",
    "GUEST_MAC",
    "GUEST_CID",
    "SCRATCH_BASE_NAME",
    "LsEntry",
    "parse_ls_sections",
    "diff_listings",
]

log = logging.getLogger("emberpool.firecracker")

GUEST_MAC = "06:00:ac:10:00:02"
GUEST_CID = 3
# Template scratch drive as of the snapshot, kept next to the snapshot state.
# Every clone starts from a copy of it: the guest kernel's view of that
# filesystem is part of the snapshot, so an empty drive would corrupt it.
SCRATCH_BASE_NAME = "scratch.ext4"
_ROOTFS_NAME = "rootfs.ext4"
_STATE_NAME = "snapshot.state"
_MEM_NAME = "snapshot.mem"

# No console: guest serial output is not needed and is guest-controlled.
# The guest image configures eth0 (GUEST_IP, default route via TAP_HOST_IP).
DEFAULT_BOOT_ARGS = "reboot=k panic=1 pci=off"

# Host-tool environment and output caps.
_ENV: Mapping[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}
_OUTPUT_TAIL_BYTES = 16 * 1024
_HTTP_MAX_HEADER = 16 * 1024
_HTTP_MAX_BODY = 64 * 1024
_FAULT_MAX_CHARS = 300
_READY_LINE_MAX = 64
_DEBUGFS_MAX_OUTPUT = 16 * 1024 * 1024
_DEBUGFS_BATCH = 256
_MAX_NAME_CHARS = 1024
_BOOT_ARGS_RE = re.compile(r"[\x20-\x7e]{1,2048}")
_UPPER_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_READY_RE = re.compile(rb"OK [0-9]{1,10}\n")


def _positive(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < 1e6:
        raise ValueError(f"{name} must be a positive number: {value!r}")
    return float(value)


@dataclass(frozen=True, slots=True)
class FirecrackerConfig:
    """Paths, VM shape and limits for FirecrackerEngine.

    `kernel_path` and `rootfs_path` are copied into the template workdir;
    the rootfs must be a clean ext4 image (no pending journal recovery),
    because every VM opens it read-only. The template workdir and
    `jailer.chroot_base` must be on the same filesystem: clones get the
    snapshot files as hard links.

    `scratch_upper_dir` is the directory on the scratch drive that the guest
    uses as its overlayfs upper layer. list_changes reports paths below it.
    If the drive has no such directory, it reports everything except
    `lost+found`.
    """

    jailer: JailerConfig
    kernel_path: Path
    rootfs_path: Path
    vcpu_count: int = 1
    mem_size_mib: int = 512
    scratch_size_mib: int = 256
    boot_args: str = DEFAULT_BOOT_ARGS
    scratch_upper_dir: str = "upper"
    boot_timeout: float = 120.0
    api_timeout: float = 10.0
    snapshot_timeout: float = 300.0
    restore_timeout: float = 60.0
    kill_timeout: float = 10.0
    copy_timeout: float = 300.0
    vmgenid_timeout: float = 30.0
    changes_timeout: float = 30.0
    max_changes: int = 10_000
    max_scan_entries: int = 100_000
    max_depth: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.jailer, JailerConfig):
            raise TypeError("jailer must be a JailerConfig")
        for name in ("kernel_path", "rootfs_path"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                object.__setattr__(self, name, Path(value))
        for name, lo, hi in (
            ("vcpu_count", 1, 32),
            ("mem_size_mib", 128, 1 << 20),
            ("scratch_size_mib", 16, 1 << 20),
            ("max_changes", 1, 10_000_000),
            ("max_scan_entries", 1, 10_000_000),
            ("max_depth", 1, 4096),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
                raise ValueError(f"{name} must be an int in {lo}..{hi}: {value!r}")
        if not isinstance(self.boot_args, str) or _BOOT_ARGS_RE.fullmatch(self.boot_args) is None:
            raise ValueError("boot_args must be printable ASCII")
        if (
            not isinstance(self.scratch_upper_dir, str)
            or _UPPER_RE.fullmatch(self.scratch_upper_dir) is None
            or self.scratch_upper_dir in (".", "..")
        ):
            raise ValueError(f"invalid scratch_upper_dir: {self.scratch_upper_dir!r}")
        for name in (
            "boot_timeout",
            "api_timeout",
            "snapshot_timeout",
            "restore_timeout",
            "kill_timeout",
            "copy_timeout",
            "vmgenid_timeout",
            "changes_timeout",
        ):
            object.__setattr__(self, name, _positive(name, getattr(self, name)))


# --------------------------------------------------------------------------
# Process output: drained continuously, last bytes kept for error messages
# --------------------------------------------------------------------------


class _Tail:
    def __init__(self, cap: int = _OUTPUT_TAIL_BYTES) -> None:
        self._buf: collections.deque[bytes] = collections.deque()
        self._size = 0
        self._cap = cap

    def add(self, chunk: bytes) -> None:
        self._buf.append(chunk)
        self._size += len(chunk)
        while self._size > self._cap and self._buf:
            self._size -= len(self._buf.popleft())

    def text(self, limit: int = 2000) -> str:
        """Escaped, printable tail. VMM output can contain guest serial
        output, so it is shown escaped and only in error messages."""
        data = b"".join(self._buf)[-limit:]
        return data.decode("ascii", "backslashreplace").encode("unicode_escape").decode("ascii")


async def _drain(stream: asyncio.StreamReader, tail: _Tail) -> None:
    with contextlib.suppress(Exception):
        while chunk := await stream.read(4096):
            tail.add(chunk)


# --------------------------------------------------------------------------
# Firecracker API over its Unix socket
# --------------------------------------------------------------------------


class _ApiError(IsolationError):
    """The Firecracker API returned an error or a malformed response. A VM
    whose VMM cannot be driven as asked is not started (fail closed)."""


def _fault_message(body: bytes) -> str:
    try:
        data = json.loads(body.decode("utf-8"))
        msg = data.get("fault_message") if isinstance(data, dict) else None
    except (UnicodeDecodeError, ValueError):
        msg = None
    if not isinstance(msg, str):
        msg = body[:_FAULT_MAX_CHARS].decode("ascii", "backslashreplace")
    return repr(msg[:_FAULT_MAX_CHARS])


def parse_http_head(head: bytes) -> tuple[int, dict[str, str]]:
    """Parse an HTTP/1.1 status line and headers (terminated by CRLFCRLF)."""
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError:
        raise _ApiError("non-ASCII HTTP response header") from None
    lines = text.split("\r\n")
    m = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?", lines[0])
    if m is None:
        raise _ApiError(f"bad HTTP status line: {lines[0][:80]!r}")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise _ApiError("bad HTTP header line")
        headers[name.strip().lower()] = value.strip()
    return int(m.group(1)), headers


async def _api_call(
    sock: Path, method: str, path: str, body: dict[str, Any] | None, timeout: float
) -> bytes:
    """One request on a fresh connection. Returns the body of a 2xx reply,
    raises _ApiError otherwise. Sizes are capped: a compromised VMM is not
    trusted either."""
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    head = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n"
    if body is not None:
        head += "Content-Type: application/json\r\n"
    head += f"Content-Length: {len(payload)}\r\n\r\n"
    async with asyncio.timeout(timeout):
        reader, writer = await asyncio.open_unix_connection(str(sock), limit=_HTTP_MAX_HEADER)
        try:
            writer.write(head.encode("ascii") + payload)
            await writer.drain()
            try:
                raw = await reader.readuntil(b"\r\n\r\n")
            except asyncio.LimitOverrunError:
                raise _ApiError("HTTP response header too large") from None
            except asyncio.IncompleteReadError:
                raise _ApiError("connection closed before HTTP response") from None
            status, headers = parse_http_head(raw[:-4])
            length_text = headers.get("content-length", "0")
            if not length_text.isdigit() or int(length_text) > _HTTP_MAX_BODY:
                raise _ApiError(f"bad Content-Length: {length_text[:20]!r}")
            try:
                data = await reader.readexactly(int(length_text))
            except asyncio.IncompleteReadError:
                raise _ApiError("short HTTP response body") from None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    if not 200 <= status < 300:
        raise _ApiError(f"{method} {path} returned {status}: {_fault_message(data)}")
    return data


# --------------------------------------------------------------------------
# Scratch drive listing with debugfs (userspace, never mounted)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LsEntry:
    """One directory entry from `debugfs ls -l`. Names are as debugfs escapes
    them (non-printable bytes become \\xNN), so they never contain newlines."""

    ino: int
    mode: int
    size: int
    mtime: str
    name: str

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)


_LS_LINE_RE = re.compile(
    r" *([0-9]{1,10}) +([0-7]{1,7}) +\(([0-9]{1,3})\) +([0-9]{1,10}) +([0-9]{1,10}) +"
    r"([0-9]{1,20}(?:, *[0-9]{1,10})?) +(\S{1,32} \S{1,16}) (.*)"
)
_LS_CMD_RE = re.compile(r"debugfs: ls -l <([0-9]{1,10})>")


def parse_ls_sections(output: str, expected: Sequence[int]) -> dict[int, list[LsEntry]]:
    """Split `debugfs -f` output for a batch of `ls -l <ino>` commands into
    entries per directory inode.

    Only sections whose echo line names an inode in `expected` are kept.
    Entry lines that do not parse are skipped (the result is advisory).
    """
    wanted = set(expected)
    out: dict[int, list[LsEntry]] = {}
    current: list[LsEntry] | None = None
    for line in output.split("\n"):
        line = line.rstrip("\r")
        cmd = _LS_CMD_RE.fullmatch(line.rstrip())
        if cmd is not None:
            ino = int(cmd.group(1))
            current = out.setdefault(ino, []) if ino in wanted else None
            continue
        if current is None:
            continue
        m = _LS_LINE_RE.fullmatch(line)
        if m is None:
            continue
        name = m.group(8)
        if not name or len(name) > _MAX_NAME_CHARS or name in (".", ".."):
            continue
        size_text = m.group(6).split(",")[0]
        current.append(
            LsEntry(
                ino=int(m.group(1)),
                mode=int(m.group(2), 8),
                size=int(size_text),
                mtime=m.group(7),
                name=name,
            )
        )
    return out


def diff_listings(
    base: Mapping[str, LsEntry], current: Mapping[str, LsEntry], limit: int
) -> tuple[str, ...]:
    """Paths that are new, changed or removed relative to `base`. Directories
    that exist in both are not reported (their mtime changes whenever a child
    does). Changes are detected by inode, mode, size and minute-resolution
    mtime: advisory, end state only."""
    changed: list[str] = []
    for path, entry in current.items():
        old = base.get(path)
        if old is None:
            changed.append(path)
        elif entry.is_dir and old.is_dir:
            continue
        elif (entry.ino, entry.mode, entry.size, entry.mtime) != (old.ino, old.mode, old.size, old.mtime):
            changed.append(path)
    changed.extend(path for path in base if path not in current)
    changed.sort()
    return tuple(changed[:limit])


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


@dataclass(eq=False)
class _VM:
    layout: JailLayout
    netns: str
    scratch_base: Path | None = None
    proc: asyncio.subprocess.Process | None = None
    drain: asyncio.Task[None] | None = None
    tail: _Tail = field(default_factory=_Tail)
    killed: bool = False


class FirecrackerEngine:
    """Engine protocol on Firecracker under the jailer. Must run as root.

    `exec_client` is used only by check_vmgenid. Without one, check_vmgenid
    returns False (fail closed).
    """

    def __init__(self, config: FirecrackerConfig, exec_client: ExecClient | None = None) -> None:
        self.config = config
        self._exec = exec_client
        self._vms: dict[str, _VM] = {}
        self._base_listings: dict[Path, dict[str, LsEntry]] = {}

    # -- public protocol --------------------------------------------------

    async def build_template(self, workdir: Path, netns: str) -> Template:
        cfg = self.config
        validate_netns(netns)
        workdir = Path(workdir)
        if not workdir.is_absolute():
            raise ValueError(f"workdir must be absolute: {workdir}")
        workdir.mkdir(parents=True, exist_ok=True, mode=0o755)
        outputs = {
            name: workdir / name for name in (_ROOTFS_NAME, _STATE_NAME, _MEM_NAME, SCRATCH_BASE_NAME)
        }
        existing = [str(p) for p in outputs.values() if os.path.lexists(p)]
        if existing:
            raise EmberpoolError(f"template workdir already holds template files: {existing}")
        self._check_netns(netns)
        cfg.jailer.chroot_base.mkdir(parents=True, exist_ok=True, mode=0o755)
        if os.stat(workdir).st_dev != os.stat(cfg.jailer.chroot_base).st_dev:
            raise EmberpoolError("template workdir and chroot base must be on the same filesystem")
        await self._check_rootfs_clean(cfg.rootfs_path)

        vm_id = f"tmpl-{new_vm_id()}"
        layout = cfg.jailer.layout(vm_id)
        created: list[Path] = []
        try:
            create_jail(layout)
            vm = self._vms[vm_id] = _VM(layout, netns)

            rootfs = outputs[_ROOTFS_NAME]
            await run_command(
                ["cp", "--sparse=always", "--", str(cfg.rootfs_path), str(rootfs)],
                timeout=cfg.copy_timeout,
            )
            created.append(rootfs)
            _seal(rootfs, cfg.jailer.gid)
            os.link(rootfs, layout.host(IN_JAIL_ROOTFS))
            await asyncio.to_thread(shutil.copyfile, cfg.kernel_path, layout.host(IN_JAIL_KERNEL))
            os.chmod(layout.host(IN_JAIL_KERNEL), 0o444)
            await self._make_scratch(layout.scratch)

            await self._spawn(vm)
            sock = layout.api_sock
            async with asyncio.timeout(cfg.api_timeout * 4):
                await self._wait_api(vm)
                for method, path, body in self._boot_requests():
                    await _api_call(sock, method, path, body, cfg.api_timeout)
            await self._wait_agent(vm, cfg.boot_timeout)
            await _api_call(sock, "PATCH", "/vm", {"state": "Paused"}, cfg.api_timeout)
            await _api_call(
                sock,
                "PUT",
                "/snapshot/create",
                {
                    "snapshot_type": "Full",
                    "snapshot_path": IN_JAIL_STATE,
                    "mem_file_path": IN_JAIL_MEM,
                },
                cfg.snapshot_timeout,
            )
            await self._stop(vm)

            for name, in_jail in (
                (_STATE_NAME, IN_JAIL_STATE),
                (_MEM_NAME, IN_JAIL_MEM),
                (SCRATCH_BASE_NAME, IN_JAIL_SCRATCH),
            ):
                src = layout.host(in_jail)
                _check_regular(src)
                os.rename(src, outputs[name])
                created.append(outputs[name])
                _seal(outputs[name], cfg.jailer.gid)
        except BaseException as e:
            for path in created:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
            await self._discard(vm_id)
            if isinstance(e, Exception) and not isinstance(e, EmberpoolError):
                raise IsolationError(f"template build failed: {type(e).__name__}: {e}") from e
            raise
        await self._discard(vm_id)
        return Template(outputs[_STATE_NAME], outputs[_MEM_NAME], outputs[_ROOTFS_NAME])

    async def restore(self, template: Template, vm_id: str, netns: str) -> VMHandle:
        cfg = self.config
        validate_vm_id(vm_id)
        validate_netns(netns)
        if vm_id in self._vms:
            raise EmberpoolError(f"vm_id already in use: {vm_id}")
        layout = cfg.jailer.layout(vm_id)
        registered = False
        try:
            self._check_netns(netns)
            scratch_base = self._check_template(template)
            create_jail(layout)  # fails if the jail exists: never reused, never adopted
            vm = self._vms[vm_id] = _VM(layout, netns, scratch_base=scratch_base)
            registered = True

            os.link(template.rootfs_path, layout.host(IN_JAIL_ROOTFS))
            os.link(template.state_path, layout.host(IN_JAIL_STATE))
            os.link(template.mem_path, layout.host(IN_JAIL_MEM))
            await run_command(
                ["cp", "--sparse=always", "--", str(scratch_base), str(layout.scratch)],
                timeout=cfg.copy_timeout,
            )
            os.chown(layout.scratch, cfg.jailer.uid, cfg.jailer.gid)
            os.chmod(layout.scratch, 0o600)

            await self._spawn(vm)
            async with asyncio.timeout(cfg.restore_timeout):
                await self._wait_api(vm)
                await _api_call(
                    layout.api_sock,
                    "PUT",
                    "/snapshot/load",
                    {
                        "snapshot_path": IN_JAIL_STATE,
                        "mem_backend": {"backend_type": "File", "backend_path": IN_JAIL_MEM},
                        "resume_vm": True,
                    },
                    cfg.restore_timeout,
                )
            assert vm.proc is not None
            if vm.proc.returncode is not None:
                raise IsolationError(f"VM {vm_id} exited right after restore: {vm.tail.text()}")
            return VMHandle(
                vm_id=vm_id,
                pid=vm.proc.pid,
                vsock_path=layout.vsock,
                scratch_path=layout.scratch,
                netns=netns,
            )
        except BaseException as e:
            if registered:
                await self._discard(vm_id)
            if isinstance(e, Exception) and not isinstance(e, EmberpoolError):
                raise IsolationError(f"restore of {vm_id} failed: {type(e).__name__}: {e}") from e
            raise

    async def kill(self, vm: VMHandle) -> None:
        state = self._vms.get(validate_vm_id(vm.vm_id))
        if state is None:
            return
        try:
            await self._stop(state)
        finally:
            for path in (state.layout.api_sock, state.layout.vsock):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)

    async def check_vmgenid(self, vm: VMHandle) -> bool:
        """Ask the guest whether a device is bound to the vmgenid driver.

        This relies on the guest's answer, so the pool must only call it on a
        freshly restored VM that has run no untrusted code, and must not hand
        that VM out afterwards. Any error or unexpected answer is False.
        """
        if self._exec is None:
            log.warning("check_vmgenid: no exec client configured; failing closed")
            return False
        state = self._vms.get(validate_vm_id(vm.vm_id))
        if state is None or state.killed:
            return False
        try:
            result = await asyncio.wait_for(
                self._exec.run(state.layout.vsock, _VMGENID_CODE, self.config.vmgenid_timeout),
                self.config.vmgenid_timeout + 5,
            )
        except Exception as e:  # noqa: BLE001 - any failure fails closed
            log.warning("check_vmgenid on %s failed: %s", vm.vm_id, type(e).__name__)
            return False
        return result.exit_code == 0 and result.stdout == "vmgenid:bound\n"

    async def list_changes(self, vm: VMHandle) -> tuple[str, ...]:
        state = self._vms.get(validate_vm_id(vm.vm_id))
        if state is None:
            raise EmberpoolError(f"unknown VM: {vm.vm_id}")
        if not state.killed:
            raise EmberpoolError(f"list_changes before kill: {vm.vm_id}")
        if state.scratch_base is None:
            raise EmberpoolError(f"VM has no scratch drive: {vm.vm_id}")
        cfg = self.config
        async with asyncio.timeout(cfg.changes_timeout):
            base = self._base_listings.get(state.scratch_base)
            if base is None:
                base = await self._scan(state.scratch_base)
                self._base_listings[state.scratch_base] = base
            current = await self._scan(state.layout.scratch)
        return diff_listings(base, current, cfg.max_changes)

    async def cleanup(self, vm: VMHandle) -> None:
        await self._discard(validate_vm_id(vm.vm_id))

    # -- introspection for the pool and tests -------------------------------

    def tracked(self) -> list[str]:
        """VM ids this engine still holds resources for."""
        return list(self._vms)

    # -- internals ------------------------------------------------------------

    def _boot_requests(self) -> list[tuple[str, str, dict[str, Any]]]:
        cfg = self.config
        return [
            ("PUT", "/boot-source", {"kernel_image_path": IN_JAIL_KERNEL, "boot_args": cfg.boot_args}),
            (
                "PUT",
                "/drives/rootfs",
                {
                    "drive_id": "rootfs",
                    "path_on_host": IN_JAIL_ROOTFS,
                    "is_root_device": True,
                    "is_read_only": True,
                },
            ),
            (
                "PUT",
                "/drives/scratch",
                {
                    "drive_id": "scratch",
                    "path_on_host": IN_JAIL_SCRATCH,
                    "is_root_device": False,
                    "is_read_only": False,
                },
            ),
            (
                "PUT",
                "/machine-config",
                {"vcpu_count": cfg.vcpu_count, "mem_size_mib": cfg.mem_size_mib},
            ),
            (
                "PUT",
                "/network-interfaces/eth0",
                {"iface_id": "eth0", "host_dev_name": TAP_NAME, "guest_mac": GUEST_MAC},
            ),
            ("PUT", "/vsock", {"guest_cid": GUEST_CID, "uds_path": IN_JAIL_VSOCK}),
            ("PUT", "/actions", {"action_type": "InstanceStart"}),
        ]

    @staticmethod
    def _check_netns(netns: str) -> None:
        path = netns_path(netns)
        if not path.exists():
            raise IsolationError(f"network namespace does not exist: {netns}")

    def _check_template(self, template: Template) -> Path:
        if not isinstance(template, Template):
            raise TypeError("template must be a Template")
        scratch_base = template.state_path.with_name(SCRATCH_BASE_NAME)
        dev = os.stat(self.config.jailer.chroot_base).st_dev
        for path in (template.state_path, template.mem_path, template.rootfs_path, scratch_base):
            st = _check_regular(path)
            if st.st_dev != dev:
                raise EmberpoolError(f"template file not on the chroot filesystem: {path}")
            if st.st_mode & 0o222 or st.st_uid != 0:
                raise EmberpoolError(f"template file must be root-owned and read-only: {path}")
        return scratch_base

    async def _check_rootfs_clean(self, rootfs: Path) -> None:
        try:
            res = await run_command(["dumpe2fs", "-h", str(rootfs)], timeout=30, max_output=1 << 16)
        except CommandError as e:
            raise EmberpoolError(f"rootfs is not a readable ext4 image: {rootfs}") from e
        text = res.stdout.decode("ascii", "replace")
        features = re.search(r"^Filesystem features:(.*)$", text, re.M)
        state = re.search(r"^Filesystem state:\s*(\S+)", text, re.M)
        if features is None or state is None:
            raise EmberpoolError(f"cannot read ext4 superblock of {rootfs}")
        if "needs_recovery" in features.group(1).split() or state.group(1) != "clean":
            raise EmberpoolError(
                f"rootfs {rootfs} is not clean (journal needs recovery); run e2fsck on it first"
            )

    async def _make_scratch(self, path: Path) -> None:
        cfg = self.config
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(fd, cfg.scratch_size_mib * 1024 * 1024)
        finally:
            os.close(fd)
        await run_command(
            ["mkfs.ext4", "-q", "-F", "-m", "0", "-L", "epscratch", "--", str(path)],
            timeout=cfg.copy_timeout,
        )
        os.chown(path, cfg.jailer.uid, cfg.jailer.gid)

    async def _spawn(self, vm: _VM) -> None:
        argv = jailer_argv(self.config.jailer, vm.layout.vm_id, vm.netns)
        vm.proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=dict(_ENV),
            start_new_session=True,
        )
        assert vm.proc.stdout is not None
        vm.drain = asyncio.create_task(_drain(vm.proc.stdout, vm.tail))

    async def _wait_api(self, vm: _VM) -> None:
        """Wait until the API socket accepts connections. Caller bounds it."""
        assert vm.proc is not None
        sock = vm.layout.api_sock
        while True:
            if vm.proc.returncode is not None:
                raise IsolationError(
                    f"jailer/firecracker for {vm.layout.vm_id} exited with "
                    f"{vm.proc.returncode}: {vm.tail.text()}"
                )
            if sock.exists():
                try:
                    _, writer = await asyncio.open_unix_connection(str(sock))
                except OSError:
                    pass
                else:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
                    return
            await asyncio.sleep(0.02)

    async def _wait_agent(self, vm: _VM, timeout: float) -> None:
        """Wait until the guest agent accepts a vsock connection on VSOCK_PORT."""
        assert vm.proc is not None
        try:
            async with asyncio.timeout(timeout):
                while True:
                    if vm.proc.returncode is not None:
                        raise IsolationError(
                            f"template VM exited during boot ({vm.proc.returncode}): {vm.tail.text()}"
                        )
                    if await _probe_agent(vm.layout.vsock):
                        return
                    await asyncio.sleep(0.1)
        except TimeoutError:
            raise IsolationError(
                f"guest agent not ready on vsock port {VSOCK_PORT} after {timeout}s"
            ) from None

    async def _stop(self, vm: _VM) -> None:
        """SIGKILL the VMM and reap it. The signal is sent synchronously, so a
        cancelled caller still leaves the process dead."""
        proc = vm.proc
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        vm.killed = True
        if proc is not None and proc.returncode is None:
            try:
                await asyncio.wait_for(asyncio.shield(proc.wait()), self.config.kill_timeout)
            except TimeoutError:
                log.warning("VM %s did not exit within %ss of SIGKILL", vm.layout.vm_id, self.config.kill_timeout)
        if vm.drain is not None and (proc is None or proc.returncode is not None):
            vm.drain.cancel()

    async def _discard(self, vm_id: str) -> None:
        """Kill the VM and remove its jail and cgroup. Idempotent; the
        removal is synchronous after the kill signal, so cancellation while
        reaping cannot leave the jail behind."""
        vm = self._vms.get(vm_id)
        if vm is None:
            return
        try:
            await self._stop(vm)
        finally:
            remove_jail(vm.layout)
            try:
                remove_cgroup(self.config.jailer, vm_id)
            except OSError as e:
                log.warning("could not remove cgroup of %s: %s", vm_id, e)
            self._vms.pop(vm_id, None)

    async def _scan(self, image: Path) -> dict[str, LsEntry]:
        """Walk the scratch filesystem with debugfs, by inode number, as the
        jail uid. Bounded by entries, depth and the caller's timeout."""
        cfg = self.config
        root = await self._debugfs_ls(image, [2])
        top = root.get(2, [])
        start: tuple[int, str] | None = None
        for entry in top:
            if entry.name == cfg.scratch_upper_dir and entry.is_dir:
                start = (entry.ino, "")
                break
        entries: dict[str, LsEntry] = {}
        visited: set[int] = {2}
        frontier: list[tuple[int, str, int]] = []
        if start is not None:
            visited.add(start[0])
            frontier.append((start[0], "", 1))
        else:
            for entry in top:
                if entry.name == "lost+found":
                    continue
                path = "/" + entry.name
                entries[path] = entry
                if entry.is_dir and entry.ino not in visited:
                    visited.add(entry.ino)
                    frontier.append((entry.ino, path, 1))
        while frontier and len(entries) < cfg.max_scan_entries:
            batch, frontier = frontier[:_DEBUGFS_BATCH], frontier[_DEBUGFS_BATCH:]
            listing = await self._debugfs_ls(image, [ino for ino, _, _ in batch])
            for ino, prefix, depth in batch:
                for entry in listing.get(ino, []):
                    if len(entries) >= cfg.max_scan_entries:
                        log.warning("scratch scan of %s capped at %d entries", image, len(entries))
                        break
                    path = f"{prefix}/{entry.name}"
                    entries[path] = entry
                    if entry.is_dir and entry.ino not in visited and depth < cfg.max_depth:
                        visited.add(entry.ino)
                        frontier.append((entry.ino, path, depth + 1))
        return entries

    async def _debugfs_ls(self, image: Path, inodes: Iterable[int]) -> dict[int, list[LsEntry]]:
        cfg = self.config.jailer
        inos = [int(i) for i in inodes]
        if any(not 0 < i < 2**32 for i in inos):
            raise ValueError("inode number out of range")
        script = "".join(f"ls -l <{i}>\n" for i in inos).encode("ascii")
        argv = [
            "setpriv",
            "--reuid", str(cfg.uid),
            "--regid", str(cfg.gid),
            "--clear-groups",
            "--no-new-privs",
            "--",
            "debugfs", "-c", "-f", "-", str(image),
        ]  # fmt: skip
        res = await run_command(
            argv, timeout=self.config.changes_timeout, stdin=script, check=False,
            max_output=_DEBUGFS_MAX_OUTPUT,
        )  # fmt: skip
        if res.returncode != 0:
            raise EmberpoolError(f"debugfs failed on {image} with exit {res.returncode}")
        if res.stdout_truncated:
            log.warning("debugfs output for %s truncated; change list is partial", image)
        return parse_ls_sections(res.stdout.decode("utf-8", "replace"), inos)


async def _probe_agent(vsock: Path) -> bool:
    """True if a host-initiated vsock connection to VSOCK_PORT is accepted."""
    if not vsock.exists():
        return False
    try:
        async with asyncio.timeout(2.0):
            reader, writer = await asyncio.open_unix_connection(str(vsock), limit=_READY_LINE_MAX * 2)
            try:
                writer.write(f"CONNECT {VSOCK_PORT}\n".encode("ascii"))
                await writer.drain()
                line = await reader.readline()
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
    except (OSError, TimeoutError, ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
        return False
    return _READY_RE.fullmatch(line) is not None


def _check_regular(path: Path) -> os.stat_result:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise EmberpoolError(f"not a regular file: {path}")
    return st


def _seal(path: Path, gid: int) -> None:
    """Make a template file root-owned and read-only, readable by the jail gid."""
    os.chown(path, 0, gid)
    os.chmod(path, 0o440)


_VMGENID_CODE = (
    "import os\n"
    "d = '/sys/bus/platform/drivers/vmgenid'\n"
    "bound = os.path.isdir(d) and any(\n"
    "    e != 'module' and os.path.islink(os.path.join(d, e)) for e in os.listdir(d))\n"
    "print('vmgenid:bound' if bound else 'vmgenid:unbound')\n"
)
