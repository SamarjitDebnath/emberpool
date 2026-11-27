"""Jailer chroot layout, command line and teardown.

Every Firecracker process emberpool starts runs under the jailer
(docs/40-rules.md rule 4): chroot, uid/gid drop, seccomp, optional cgroups and
the VM's network namespace.

The jailer puts each VM in `<chroot_base>/<exec name>/<vm_id>/root`. emberpool
creates that directory itself before starting the jailer, places the VM's
files in it, and removes the whole `<vm_id>` directory on cleanup. Every path
here is derived from the configured base and a validated VM id, never from
anything the guest reports (rule 1).
"""

from __future__ import annotations

import errno
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from emberpool._names import validate_netns, validate_vm_id

__all__ = [
    "JailerConfig",
    "JailLayout",
    "NETNS_DIR",
    "CGROUP_ROOT",
    "MAX_UNIX_PATH",
    "IN_JAIL_API_SOCK",
    "IN_JAIL_VSOCK",
    "IN_JAIL_KERNEL",
    "IN_JAIL_ROOTFS",
    "IN_JAIL_SCRATCH",
    "IN_JAIL_STATE",
    "IN_JAIL_MEM",
    "netns_path",
    "jailer_argv",
    "create_jail",
    "remove_jail",
    "remove_cgroup",
]

NETNS_DIR = Path("/var/run/netns")
CGROUP_ROOT = Path("/sys/fs/cgroup")

# sockaddr_un.sun_path is 108 bytes including the trailing NUL.
MAX_UNIX_PATH = 107

# Paths as Firecracker sees them inside the chroot. The snapshot records the
# drive and vsock paths, so they must be identical for the template and every
# clone.
IN_JAIL_API_SOCK = "/api.sock"
IN_JAIL_VSOCK = "/v.sock"
IN_JAIL_KERNEL = "/kernel"
IN_JAIL_ROOTFS = "/rootfs.ext4"
IN_JAIL_SCRATCH = "/scratch.ext4"
IN_JAIL_STATE = "/snapshot.state"
IN_JAIL_MEM = "/snapshot.mem"

_EXEC_NAME_RE = re.compile(r"[A-Za-z0-9._-]*firecracker[A-Za-z0-9._-]*")
_CGROUP_RE = re.compile(r"[a-z]+\.[a-z_.]+=[A-Za-z0-9 ._-]{1,64}")
_PARENT_CGROUP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_RLIMIT_RE = re.compile(r"(fsize|no-file)=[0-9]{1,20}")


def _check_id(kind: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**31:
        raise ValueError(f"{kind} must be a positive int (never root): {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class JailerConfig:
    """Where the binaries live and what the jailer confines the VMM to.

    uid/gid:        identity Firecracker runs as. Never 0.
    cgroups:        `<file>=<value>` entries for the VM's cgroup (cgroup v2),
                    for example "pids.max=64". Empty means no cgroup.
    parent_cgroup:  parent of the per-VM cgroups.
    resource_limits: `fsize=<n>` or `no-file=<n>` entries.
    """

    jailer_bin: Path
    firecracker_bin: Path
    chroot_base: Path = Path("/srv/jailer")
    uid: int = 10123
    gid: int = 10123
    cgroups: tuple[str, ...] = ()
    parent_cgroup: str = "emberpool"
    resource_limits: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("jailer_bin", "firecracker_bin", "chroot_base"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                object.__setattr__(self, name, Path(value))
            if not getattr(self, name).is_absolute():
                raise ValueError(f"{name} must be an absolute path: {value!r}")
        _check_id("uid", self.uid)
        _check_id("gid", self.gid)
        if _EXEC_NAME_RE.fullmatch(self.firecracker_bin.name) is None:
            raise ValueError(f"firecracker binary name must contain 'firecracker': {self.firecracker_bin.name!r}")
        if not isinstance(self.cgroups, tuple) or any(
            not isinstance(c, str) or _CGROUP_RE.fullmatch(c) is None for c in self.cgroups
        ):
            raise ValueError(f"invalid cgroups: {self.cgroups!r}")
        if not isinstance(self.parent_cgroup, str) or _PARENT_CGROUP_RE.fullmatch(self.parent_cgroup) is None:
            raise ValueError(f"invalid parent_cgroup: {self.parent_cgroup!r}")
        if not isinstance(self.resource_limits, tuple) or any(
            not isinstance(r, str) or _RLIMIT_RE.fullmatch(r) is None for r in self.resource_limits
        ):
            raise ValueError(f"invalid resource_limits: {self.resource_limits!r}")

    @property
    def exec_name(self) -> str:
        return self.firecracker_bin.name

    def layout(self, vm_id: str) -> JailLayout:
        return JailLayout(self.chroot_base, self.exec_name, validate_vm_id(vm_id))


@dataclass(frozen=True, slots=True)
class JailLayout:
    """Host paths of one VM's jail."""

    base: Path
    exec_name: str
    vm_id: str

    def __post_init__(self) -> None:
        validate_vm_id(self.vm_id)
        if _EXEC_NAME_RE.fullmatch(self.exec_name) is None:
            raise ValueError(f"invalid exec name: {self.exec_name!r}")
        # Both sockets must fit in sun_path. Firecracker also binds
        # "<vsock>_<port>" for guest-initiated vsock connections.
        for sock in (self.api_sock, Path(f"{self.vsock}_{2**32 - 1}")):
            if len(os.fsencode(sock)) > MAX_UNIX_PATH:
                raise ValueError(f"chroot base too long for Unix socket paths: {self.base}")

    @property
    def id_dir(self) -> Path:
        """`<base>/<exec>/<vm_id>`: removed as a whole on cleanup."""
        return self.base / self.exec_name / self.vm_id

    @property
    def root(self) -> Path:
        return self.id_dir / "root"

    def host(self, in_jail: str) -> Path:
        """Host path of a path as Firecracker sees it inside the chroot."""
        if not in_jail.startswith("/") or ".." in in_jail.split("/"):
            raise ValueError(f"bad in-jail path: {in_jail!r}")
        return self.root / in_jail.lstrip("/")

    @property
    def api_sock(self) -> Path:
        return self.host(IN_JAIL_API_SOCK)

    @property
    def vsock(self) -> Path:
        return self.host(IN_JAIL_VSOCK)

    @property
    def scratch(self) -> Path:
        return self.host(IN_JAIL_SCRATCH)


def netns_path(netns: str) -> Path:
    """Path the jailer joins for `netns`. The namespace must already exist."""
    return NETNS_DIR / validate_netns(netns)


def jailer_argv(cfg: JailerConfig, vm_id: str, netns: str, *, log_level: str = "Warning") -> list[str]:
    """Command line for one jailed Firecracker process."""
    validate_vm_id(vm_id)
    if log_level not in ("Error", "Warning", "Info", "Debug"):
        raise ValueError(f"invalid log level: {log_level!r}")
    argv = [
        str(cfg.jailer_bin),
        "--id", vm_id,
        "--exec-file", str(cfg.firecracker_bin),
        "--uid", str(cfg.uid),
        "--gid", str(cfg.gid),
        "--chroot-base-dir", str(cfg.chroot_base),
        "--netns", str(netns_path(netns)),
    ]  # fmt: skip
    if cfg.cgroups:
        argv += ["--cgroup-version", "2", "--parent-cgroup", cfg.parent_cgroup]
        for entry in cfg.cgroups:
            argv += ["--cgroup", entry]
    for limit in cfg.resource_limits:
        argv += ["--resource-limit", limit]
    argv += ["--", "--api-sock", IN_JAIL_API_SOCK, "--level", log_level]
    return argv


def create_jail(layout: JailLayout) -> None:
    """Create `<id_dir>/root`. Fails if `<id_dir>` already exists: a jail is
    never reused, and a directory emberpool did not just create is never
    adopted (and so never removed) by this VM."""
    exec_dir = layout.id_dir.parent
    exec_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    if exec_dir.is_symlink() or not exec_dir.is_dir():
        raise FileExistsError(f"jail parent is not a plain directory: {exec_dir}")
    layout.id_dir.mkdir(mode=0o755)  # raises FileExistsError if present
    layout.root.mkdir(mode=0o755)


def remove_jail(layout: JailLayout) -> None:
    """Remove `<id_dir>` and everything in it. Idempotent. Does not follow
    symlinks (shutil.rmtree uses fd-based traversal on Linux)."""
    path = layout.id_dir
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"jail path is not a directory: {path}")
    shutil.rmtree(path)


def remove_cgroup(cfg: JailerConfig, vm_id: str) -> None:
    """Remove the VM's cgroup directory if the jailer created one. The VM
    process must be gone. Idempotent."""
    if not cfg.cgroups:
        return
    path = CGROUP_ROOT / cfg.parent_cgroup / validate_vm_id(vm_id)
    try:
        os.rmdir(path)
    except FileNotFoundError:
        return
    except OSError as e:
        if e.errno == errno.ENOENT:
            return
        raise
