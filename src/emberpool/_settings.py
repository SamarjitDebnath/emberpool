"""Settings: where the backend files are, and how sandboxes are named.

Every field left as None is filled from an environment variable when the pool
is created. Required fields still missing after that, and any invalid value,
raise ValueError before anything is created (fail closed).

    field           variable               default
    firecracker     EMBERPOOL_FIRECRACKER  required
    jailer          EMBERPOOL_JAILER       required
    kernel          EMBERPOOL_KERNEL       required
    rootfs          EMBERPOOL_ROOTFS       required
    jail_base       EMBERPOOL_JAIL_BASE    /srv/jailer
    jail_uid        EMBERPOOL_JAIL_UID     10123
    jail_gid        EMBERPOOL_JAIL_GID     10123
    prefix          EMBERPOOL_PREFIX       ep
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from pathlib import Path

__all__ = ["Settings"]

_ENV = {
    "firecracker": "EMBERPOOL_FIRECRACKER",
    "jailer": "EMBERPOOL_JAILER",
    "kernel": "EMBERPOOL_KERNEL",
    "rootfs": "EMBERPOOL_ROOTFS",
    "jail_base": "EMBERPOOL_JAIL_BASE",
    "jail_uid": "EMBERPOOL_JAIL_UID",
    "jail_gid": "EMBERPOOL_JAIL_GID",
    "prefix": "EMBERPOOL_PREFIX",
}
_DEFAULTS: dict[str, object] = {
    "jail_base": Path("/srv/jailer"),
    "jail_uid": 10123,
    "jail_gid": 10123,
    "prefix": "ep",
}
_FILES = ("firecracker", "jailer", "kernel", "rootfs")
_EXECUTABLES = ("firecracker", "jailer")
# Names become namespace, interface, table and cgroup names: keep them short
# and plain. Interface names are "<prefix>-h<N>", at most 15 characters.
_PREFIX_RE = re.compile(r"ep(-[a-z0-9]{1,5})?")
_MAX_ID = 2**31 - 1


@dataclass(frozen=True, slots=True)
class Settings:
    """Backend paths and naming for a SandboxPool.

    firecracker, jailer: the Firecracker and jailer binaries.
    kernel:              the guest kernel image.
    rootfs:              the guest root filesystem with the emberpool agent.
    jail_base:           folder for jails and the template snapshot.
    jail_uid, jail_gid:  identity the VMM runs as (never 0).
    prefix:              start of every namespace, interface, nftables table
                         and cgroup name, so pools on one host stay apart.
    """

    firecracker: Path | None = None
    jailer: Path | None = None
    kernel: Path | None = None
    rootfs: Path | None = None
    jail_base: Path | None = None
    jail_uid: int | None = None
    jail_gid: int | None = None
    prefix: str | None = None

    def resolve(self, environ: Mapping[str, str] | None = None) -> Settings:
        """A copy with every unset field filled from the environment (then the
        defaults), validated. Raises ValueError naming what is missing or wrong."""
        env = os.environ if environ is None else environ
        values: dict[str, object] = {}
        missing: list[str] = []
        for f in fields(self):
            value = getattr(self, f.name)
            if value is None:
                text = env.get(_ENV[f.name])
                if text:
                    value = text
                elif f.name in _DEFAULTS:
                    value = _DEFAULTS[f.name]
                else:
                    missing.append(f"{f.name} (set {_ENV[f.name]})")
                    continue
            values[f.name] = value
        if missing:
            raise ValueError("emberpool settings missing: " + ", ".join(missing))
        out = replace(self, **values)  # type: ignore[arg-type]
        return out._validated()

    def _validated(self) -> Settings:
        paths: dict[str, Path] = {}
        for name in (*_FILES, "jail_base"):
            value = getattr(self, name)
            if not isinstance(value, (str, Path)):
                raise ValueError(f"settings.{name} must be a path: {value!r}")
            path = Path(value)
            if not path.is_absolute():
                raise ValueError(f"settings.{name} must be an absolute path: {str(path)!r}")
            paths[name] = path
        for name in _FILES:
            try:
                st = os.stat(paths[name])
            except OSError as e:
                raise ValueError(f"settings.{name} does not exist: {str(paths[name])!r}") from e
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"settings.{name} is not a regular file: {str(paths[name])!r}")
            if name in _EXECUTABLES and not os.access(paths[name], os.X_OK):
                raise ValueError(f"settings.{name} is not executable: {str(paths[name])!r}")
            if not os.access(paths[name], os.R_OK):
                raise ValueError(f"settings.{name} is not readable: {str(paths[name])!r}")
        base = paths["jail_base"]
        if base.exists() and not base.is_dir():
            raise ValueError(f"settings.jail_base is not a folder: {str(base)!r}")
        ids: dict[str, int] = {}
        for name in ("jail_uid", "jail_gid"):
            value = getattr(self, name)
            if isinstance(value, str):
                if not value.isdigit():
                    raise ValueError(f"settings.{name} must be a number: {value!r}")
                value = int(value)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _MAX_ID:
                raise ValueError(f"settings.{name} must be a positive id, never root: {value!r}")
            ids[name] = value
        prefix = self.prefix
        if not isinstance(prefix, str) or _PREFIX_RE.fullmatch(prefix) is None:
            raise ValueError(f'settings.prefix must be "ep" or "ep-" plus 1-5 of a-z0-9: {prefix!r}')
        return replace(self, **paths, **ids, prefix=prefix)  # type: ignore[arg-type]
