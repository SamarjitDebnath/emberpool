"""Settings: environment fallback, validation, and the pool's use of them.
No root needed."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from emberpool import SandboxPool, Settings
from emberpool import _wiring
from emberpool._types import IsolationError
from tests.fakes import FakeEngine, FakeExecClient, FakeNetPolicy

VARS = ("FIRECRACKER", "JAILER", "KERNEL", "ROOTFS", "JAIL_BASE", "JAIL_UID", "JAIL_GID", "PREFIX")


@pytest.fixture
def files(tmp_path: Path) -> dict[str, Path]:
    out = {}
    for name in ("firecracker", "jailer", "Image", "rootfs.ext4"):
        path = tmp_path / name
        path.write_bytes(b"x")
        if name in ("firecracker", "jailer"):
            path.chmod(0o755)
        out[name] = path
    return out


@pytest.fixture
def env(files: dict[str, Path], tmp_path: Path) -> dict[str, str]:
    return {
        "EMBERPOOL_FIRECRACKER": str(files["firecracker"]),
        "EMBERPOOL_JAILER": str(files["jailer"]),
        "EMBERPOOL_KERNEL": str(files["Image"]),
        "EMBERPOOL_ROOTFS": str(files["rootfs.ext4"]),
        "EMBERPOOL_JAIL_BASE": str(tmp_path / "jails"),
    }


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in VARS:
        monkeypatch.delenv(f"EMBERPOOL_{var}", raising=False)


def test_env_fills_unset_fields_and_defaults(env, files, tmp_path):
    s = Settings().resolve(env)
    assert s.firecracker == files["firecracker"] and s.rootfs == files["rootfs.ext4"]
    assert s.jail_base == tmp_path / "jails"
    assert (s.jail_uid, s.jail_gid, s.prefix) == (10123, 10123, "ep")


def test_explicit_fields_win_over_env(env, files, tmp_path):
    other = tmp_path / "other-rootfs.ext4"
    other.write_bytes(b"y")
    env["EMBERPOOL_JAIL_UID"] = "2000"
    s = Settings(rootfs=other, jail_uid=3000, prefix="ep-a1").resolve(env)
    assert s.rootfs == other and s.jail_uid == 3000 and s.prefix == "ep-a1"
    assert s.jail_gid == 10123


def test_missing_required_names_every_variable():
    with pytest.raises(ValueError) as e:
        Settings().resolve({})
    for var in ("EMBERPOOL_FIRECRACKER", "EMBERPOOL_JAILER", "EMBERPOOL_KERNEL", "EMBERPOOL_ROOTFS"):
        assert var in str(e.value)


@pytest.mark.parametrize(
    "key, value, match",
    [
        ("EMBERPOOL_ROOTFS", "relative/rootfs.ext4", "absolute"),
        ("EMBERPOOL_KERNEL", "/nonexistent/ep-int/Image", "does not exist"),
        ("EMBERPOOL_JAIL_BASE", "jails", "absolute"),
        ("EMBERPOOL_JAIL_UID", "0", "never root"),
        ("EMBERPOOL_JAIL_GID", "-5", "number"),
        ("EMBERPOOL_JAIL_UID", "abc", "number"),
        ("EMBERPOOL_PREFIX", "xx", "prefix"),
        ("EMBERPOOL_PREFIX", "ep-toolong", "prefix"),
        ("EMBERPOOL_PREFIX", "ep-A", "prefix"),
    ],
)
def test_invalid_values_fail(env, key, value, match):
    env[key] = value
    with pytest.raises(ValueError, match=match):
        Settings().resolve(env)


def test_directory_and_non_executable_fail(env, files, tmp_path):
    env["EMBERPOOL_ROOTFS"] = str(tmp_path)
    with pytest.raises(ValueError, match="regular file"):
        Settings().resolve(env)
    env["EMBERPOOL_ROOTFS"] = str(files["rootfs.ext4"])
    files["jailer"].chmod(0o644)  # no x bit at all: not executable, even for root
    with pytest.raises(ValueError, match="not executable"):
        Settings().resolve(env)


def test_default_jail_base(env):
    del env["EMBERPOOL_JAIL_BASE"]
    assert Settings().resolve(env).jail_base == Path("/srv/jailer")


def test_jail_base_must_be_a_folder(env, files):
    env["EMBERPOOL_JAIL_BASE"] = str(files["Image"])
    with pytest.raises(ValueError, match="folder"):
        Settings().resolve(env)


def test_settings_are_frozen():
    with pytest.raises(AttributeError):
        Settings().prefix = "ep"  # type: ignore[misc]


def test_engine_config_and_table(env):
    s = Settings(prefix="ep-x").resolve(env)
    cfg = _wiring.engine_config(s)
    assert cfg.jailer.chroot_base == s.jail_base
    assert cfg.jailer.parent_cgroup == "ep-x"
    assert (cfg.jailer.uid, cfg.jailer.gid) == (10123, 10123)
    assert _wiring.table_name("ep") == "emberpool"
    assert _wiring.table_name("ep-x") == "ep-x"
    with pytest.raises(ValueError):
        _wiring.engine_config(Settings())


# -- the pool --------------------------------------------------------------------


def test_pool_without_settings_fails_before_creating_anything(clean_env, tmp_path):
    with pytest.raises(ValueError, match="settings missing"):
        SandboxPool(1)
    assert not (tmp_path / "jails").exists()


def test_pool_bad_settings_type(clean_env):
    with pytest.raises(TypeError):
        SandboxPool(1, settings={"rootfs": "/x"})  # type: ignore[arg-type]


def test_pool_internal_backends_are_all_or_nothing(tmp_path):
    with pytest.raises(TypeError):
        SandboxPool(1, _engine=FakeEngine())  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        SandboxPool(
            1, settings=Settings(), _engine=FakeEngine(), _netpolicy=FakeNetPolicy(), _exec=FakeExecClient()
        )


class Stub:
    """Real-backend stand-in: a Backends-like object over the fakes."""

    def __init__(self, tmp_path: Path, fail: bool = False) -> None:
        self.engine, self.netpolicy, self.exec_client = FakeEngine(), FakeNetPolicy(), FakeExecClient()
        self.tracer = None
        self.workdir = tmp_path / "work"
        self.fail = fail
        self.entered = self.exited = 0

    @asynccontextmanager
    async def cm(self, settings: Settings):
        self.entered += 1
        if self.fail:
            raise IsolationError("stub: firewall blocks forwarding")
        self.workdir.mkdir()
        try:
            yield self
        finally:
            self.exited += 1


async def test_pool_enters_and_leaves_real_backends(monkeypatch, env, tmp_path):
    stub = Stub(tmp_path)
    monkeypatch.setattr(_wiring, "settings_backends", stub.cm)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    pool = SandboxPool(1)
    assert stub.entered == 0  # nothing starts before enter
    async with pool:
        assert stub.entered == 1 and stub.exited == 0
        r = await pool.run("x", 5)
        assert r.exit_code == 0
    assert stub.exited == 1
    assert stub.engine.leaks() == [] and stub.netpolicy.leaks() == []


async def test_pool_backend_start_failure_propagates(monkeypatch, env, tmp_path):
    stub = Stub(tmp_path, fail=True)
    monkeypatch.setattr(_wiring, "settings_backends", stub.cm)
    pool = SandboxPool(1, settings=Settings().resolve(env))
    with pytest.raises(IsolationError, match="firewall"):
        async with pool:
            pass
    assert stub.entered == 1 and stub.exited == 0


async def test_pool_start_failure_leaves_real_backends(monkeypatch, env, tmp_path):
    stub = Stub(tmp_path)
    stub.engine.vmgenid_ok = False
    monkeypatch.setattr(_wiring, "settings_backends", stub.cm)
    pool = SandboxPool(1, settings=Settings().resolve(env))
    with pytest.raises(IsolationError, match="vmgenid"):
        async with pool:
            pass
    assert stub.exited == 1
    assert stub.engine.leaks() == [] and stub.netpolicy.leaks() == []
