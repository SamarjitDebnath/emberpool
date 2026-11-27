"""Wiring of the real backends, without root: start order, fail-closed paths
and teardown after errors, with the network policy and log reader stubbed."""

from __future__ import annotations

from pathlib import Path

import pytest

from emberpool import _wiring
from emberpool import netpolicy as np_mod
from emberpool import trace as tr_mod
from emberpool._firecracker import FirecrackerConfig
from emberpool._jailer import JailerConfig
from emberpool._types import IsolationError


def config(tmp_path: Path) -> FirecrackerConfig:
    return FirecrackerConfig(
        jailer=JailerConfig(
            jailer_bin=tmp_path / "jailer",
            firecracker_bin=tmp_path / "firecracker",
            chroot_base=tmp_path / "j",
            uid=10123,
            gid=10124,
        ),
        kernel_path=tmp_path / "Image",
        rootfs_path=tmp_path / "rootfs.ext4",
    )


class Log:
    def __init__(self) -> None:
        self.calls: list[str] = []


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch):
    log = Log()
    made: dict[str, object] = {}

    class StubNet:
        fail_start = False

        def __init__(self, **kw: object) -> None:
            made["net_kw"] = kw

        async def __aenter__(self):
            log.calls.append("net start")
            if StubNet.fail_start:
                raise IsolationError("stub: forward path blocked")
            return self

        async def __aexit__(self, *exc: object) -> None:
            log.calls.append("net close")

        async def events(self):  # pragma: no cover - never iterated here
            if False:
                yield None

    class StubReader:
        def __init__(self, group: int, *, netns: str | None = None) -> None:
            made["reader"] = (group, netns)

    class StubTracer:
        fail_start = False

        def __init__(self, events: object, source: object) -> None:
            made["tracer_source"] = source

        async def __aenter__(self):
            log.calls.append("tracer start")
            if StubTracer.fail_start:
                raise IsolationError("stub: nflog bind refused")
            return self

        async def __aexit__(self, *exc: object) -> None:
            log.calls.append("tracer close")

    monkeypatch.setattr(_wiring, "HostNetPolicy", StubNet)
    monkeypatch.setattr(_wiring, "NflogReader", StubReader)
    monkeypatch.setattr(_wiring, "TraceWriter", StubTracer)
    return log, made, StubNet, StubTracer


def test_log_format_agrees():
    _wiring.check_log_format()


@pytest.mark.parametrize(
    "mod, name, value",
    [
        (np_mod, "DEFAULT_NFLOG_GROUP", 8),
        (np_mod, "LOG_PREFIX_ALLOWED", "ep-ok"),
        (tr_mod, "LOG_PREFIX_DROPPED", "ep-no"),
        (tr_mod, "NFLOG_SNAPLEN", 64),
    ],
)
async def test_log_format_mismatch_refuses_to_start(monkeypatch, stubs, tmp_path, mod, name, value):
    log, *_ = stubs
    monkeypatch.setattr(mod, name, value)
    with pytest.raises(IsolationError, match="log format"):
        async with _wiring.real_backends(config(tmp_path)):
            pass
    assert log.calls == []


async def test_backends_agree_and_clean_up(stubs, tmp_path):
    log, made, *_ = stubs
    cfg = config(tmp_path)
    async with _wiring.real_backends(cfg, prefix="ep-x", table="ep-x", nflog_netns="ep-x-host") as b:
        assert made["net_kw"]["tap_owner"] == (10123, 10124)
        assert made["net_kw"]["nflog_group"] == tr_mod.NFLOG_GROUP
        assert made["net_kw"]["prefix"] == "ep-x"
        assert made["reader"] == (tr_mod.NFLOG_GROUP, "ep-x-host")
        assert b.engine._exec is b.exec_client  # VMGenID check has a client
        assert b.workdir.parent == cfg.jailer.chroot_base  # same filesystem
        assert b.workdir.is_dir()
        kw = b.pool_kwargs()
        assert set(kw) == {"_engine", "_netpolicy", "_exec", "_tracer", "_workdir"}
        workdir = b.workdir
    assert log.calls == ["net start", "tracer start", "tracer close", "net close"]
    assert not workdir.exists()


async def test_error_in_body_still_cleans_up(stubs, tmp_path):
    log, *_ = stubs
    with pytest.raises(RuntimeError):
        async with _wiring.real_backends(config(tmp_path)) as b:
            workdir = b.workdir
            raise RuntimeError("boom")
    assert log.calls == ["net start", "tracer start", "tracer close", "net close"]
    assert not workdir.exists()


async def test_net_start_failure_starts_nothing_else(stubs, tmp_path):
    log, _made, StubNet, _ = stubs
    StubNet.fail_start = True
    with pytest.raises(IsolationError, match="forward path"):
        async with _wiring.real_backends(config(tmp_path)):
            pytest.fail("must not get here")
    assert log.calls == ["net start"]
    assert not (tmp_path / "j").exists()


async def test_tracer_start_failure_closes_net(stubs, tmp_path):
    log, _made, _, StubTracer = stubs
    StubTracer.fail_start = True
    with pytest.raises(IsolationError, match="nflog"):
        async with _wiring.real_backends(config(tmp_path)):
            pytest.fail("must not get here")
    assert log.calls == ["net start", "tracer start", "net close"]
    assert not (tmp_path / "j").exists()
