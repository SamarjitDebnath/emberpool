"""Unit tests for FirecrackerEngine pieces that need no root, KVM or VM."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from emberpool import _firecracker as fc
from emberpool._firecracker import (
    FirecrackerConfig,
    FirecrackerEngine,
    LsEntry,
    diff_listings,
    parse_http_head,
    parse_ls_sections,
)
from emberpool._jailer import (
    JailerConfig,
    JailLayout,
    create_jail,
    jailer_argv,
    remove_cgroup,
    remove_jail,
)
from emberpool._types import EmberpoolError, ExecResult, VMHandle
from emberpool.engine import Engine


@pytest.fixture
def short_tmp(test_prefix: str) -> Iterator[Path]:
    """A short temp dir (Unix socket paths are limited to 107 bytes)."""
    path = Path(tempfile.mkdtemp(prefix=f"{test_prefix}-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def jcfg(base: Path = Path("/tmp/ep-x/jail"), **kw: object) -> JailerConfig:
    return JailerConfig(
        jailer_bin=Path("/opt/fc/jailer"),
        firecracker_bin=Path("/opt/fc/firecracker"),
        chroot_base=base,
        **kw,  # type: ignore[arg-type]
    )


def fcfg(base: Path = Path("/tmp/ep-x/jail"), **kw: object) -> FirecrackerConfig:
    return FirecrackerConfig(
        jailer=jcfg(base),
        kernel_path=Path("/opt/fc/Image"),
        rootfs_path=Path("/opt/fc/rootfs.ext4"),
        **kw,  # type: ignore[arg-type]
    )


def handle(vm_id: str = "abc123", netns: str = "ep-x-ns") -> VMHandle:
    return VMHandle(vm_id, 1, Path("/nonexistent/v.sock"), Path("/nonexistent/s.ext4"), netns)


# -- configuration -----------------------------------------------------------


def test_engine_satisfies_protocol() -> None:
    assert isinstance(FirecrackerEngine(fcfg()), Engine)


@pytest.mark.parametrize("uid", [0, -1, True, 2**31, "1000"])
def test_jailer_refuses_root_or_bad_uid(uid: object) -> None:
    with pytest.raises(ValueError):
        jcfg(uid=uid)
    with pytest.raises(ValueError):
        jcfg(gid=uid)


@pytest.mark.parametrize(
    "kw",
    [
        {"cgroups": ("pids.max=64; rm -rf /",)},
        {"cgroups": ["pids.max=64"]},
        {"cgroups": ("../x=1",)},
        {"parent_cgroup": "../escape"},
        {"parent_cgroup": ""},
        {"resource_limits": ("core=0",)},
    ],
)
def test_jailer_config_rejects_bad_values(kw: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        jcfg(**kw)


def test_jailer_config_requires_absolute_paths_and_firecracker_name() -> None:
    with pytest.raises(ValueError):
        JailerConfig(Path("jailer"), Path("/opt/firecracker"))
    with pytest.raises(ValueError):
        JailerConfig(Path("/opt/jailer"), Path("/opt/notthevmm"))


@pytest.mark.parametrize(
    "kw",
    [
        {"vcpu_count": 0},
        {"mem_size_mib": True},
        {"boot_args": "console=ttyS0\nx"},
        {"boot_args": ""},
        {"scratch_upper_dir": ".."},
        {"scratch_upper_dir": "a/b"},
        {"boot_timeout": 0},
        {"changes_timeout": float("inf")},
        {"max_changes": 0},
    ],
)
def test_firecracker_config_rejects_bad_values(kw: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        fcfg(**kw)


# -- jail layout and command line ------------------------------------------------


def test_layout_paths_derive_from_base_and_id() -> None:
    layout = jcfg().layout("abc123")
    assert layout.id_dir == Path("/tmp/ep-x/jail/firecracker/abc123")
    assert layout.root == layout.id_dir / "root"
    assert layout.api_sock == layout.root / "api.sock"
    assert layout.vsock == layout.root / "v.sock"
    assert layout.scratch == layout.root / "scratch.ext4"
    with pytest.raises(ValueError):
        layout.host("/../etc/passwd")
    with pytest.raises(ValueError):
        layout.host("relative")


@pytest.mark.parametrize("vm_id", ["../x", "ABC", "a b", "", "x" * 40, "a/b"])
def test_layout_rejects_bad_vm_ids(vm_id: str) -> None:
    with pytest.raises(ValueError):
        jcfg().layout(vm_id)


def test_layout_rejects_base_too_long_for_sockets() -> None:
    with pytest.raises(ValueError, match="too long"):
        jcfg(Path("/" + "b" * 90)).layout("abc123")


def test_jailer_argv_is_a_list_with_netns_and_no_shell() -> None:
    argv = jailer_argv(jcfg(), "abc123", "ep-x-ns")
    assert argv[0] == "/opt/fc/jailer"
    assert argv[argv.index("--id") + 1] == "abc123"
    assert argv[argv.index("--netns") + 1] == "/var/run/netns/ep-x-ns"
    assert argv[argv.index("--uid") + 1] == "10123"
    assert "--cgroup" not in argv
    sep = argv.index("--")
    assert argv[sep + 1 :] == ["--api-sock", "/api.sock", "--level", "Warning"]
    assert all(isinstance(a, str) for a in argv)


def test_jailer_argv_cgroups_and_limits() -> None:
    cfg = jcfg(cgroups=("pids.max=64",), parent_cgroup="ep-x", resource_limits=("no-file=1024",))
    argv = jailer_argv(cfg, "abc123", "ep-x-ns")
    assert argv[argv.index("--cgroup-version") + 1] == "2"
    assert argv[argv.index("--parent-cgroup") + 1] == "ep-x"
    assert argv[argv.index("--cgroup") + 1] == "pids.max=64"
    assert argv[argv.index("--resource-limit") + 1] == "no-file=1024"


@pytest.mark.parametrize("netns", ["../../proc/1/ns/net", "other-ns", "ep x", ""])
def test_jailer_argv_validates_netns(netns: str) -> None:
    with pytest.raises(ValueError):
        jailer_argv(jcfg(), "abc123", netns)


def test_create_jail_refuses_existing_and_remove_is_idempotent(short_tmp: Path) -> None:
    layout = jcfg(short_tmp / "j").layout("abc123")
    create_jail(layout)
    assert layout.root.is_dir()
    with pytest.raises(FileExistsError):
        create_jail(layout)  # never reused or adopted
    remove_jail(layout)
    assert not layout.id_dir.exists()
    remove_jail(layout)  # idempotent


def test_remove_jail_does_not_follow_symlinks(short_tmp: Path) -> None:
    outside = short_tmp / "outside"
    outside.mkdir()
    (outside / "keep").write_text("x")
    layout = jcfg(short_tmp / "j").layout("abc123")
    create_jail(layout)
    os.symlink(outside, layout.root / "link")
    os.symlink(outside / "keep", layout.root / "filelink")
    remove_jail(layout)
    assert (outside / "keep").read_text() == "x"
    assert not layout.id_dir.exists()


def test_remove_jail_refuses_non_directory(short_tmp: Path) -> None:
    layout = jcfg(short_tmp / "j").layout("abc123")
    layout.id_dir.parent.mkdir(parents=True)
    os.symlink(short_tmp, layout.id_dir)
    with pytest.raises(RuntimeError):
        remove_jail(layout)
    assert short_tmp.is_dir()


def test_remove_cgroup_without_cgroups_is_noop() -> None:
    remove_cgroup(jcfg(), "abc123")


def test_jail_layout_direct_validation() -> None:
    with pytest.raises(ValueError):
        JailLayout(Path("/tmp/x"), "notvmm", "abc123")


# -- debugfs listing parser --------------------------------------------------


LS_OUTPUT = (
    "debugfs 1.47.0 (5-Feb-2023)\n"
    "debugfs: ls -l <12>\n"
    "     12   40775 (2)    501   1000    4096 27-Nov-2026 17:59 .\n"
    "      2   40755 (2)      0      0    4096 27-Nov-2026 17:59 ..\n"
    "     13  100664 (1)    501   1000       3 27-Nov-2026 17:59 a.txt\n"
    "     14   60644 (4)      0      0       0 27-Nov-2026 17:59 blk\n"
    "     16   40775 (2)    501   1000    4096 27-Nov-2026 17:59 sub\n"
    "     17  100664 (1)    501   1000       2 27-Nov-2026 17:59  27-Nov-2026 17:59 fake\n"
    "     18  100664 (1)    501   1000       2 27-Nov-2026 17:59 we ird\"name\\x0anl\n"
    "\n"
    "debugfs: ls -l <16>\n"
    "     16   40775 (2)    501   1000    4096 27-Nov-2026 17:59 .\n"
    "     19   20644 (3)      0      0       0 27-Nov-2026 17:59 wh\n"
    "garbage line that does not parse\n"
    "debugfs: ls -l <99>\n"
    "     20  100664 (1)    501   1000       2 27-Nov-2026 17:59 unexpected\n"
)


def test_parse_ls_sections() -> None:
    out = parse_ls_sections(LS_OUTPUT, [12, 16])
    names12 = [e.name for e in out[12]]
    assert names12 == ["a.txt", "blk", "sub", " 27-Nov-2026 17:59 fake", 'we ird"name\\x0anl']
    sub = next(e for e in out[12] if e.name == "sub")
    assert sub.is_dir and sub.ino == 16
    assert [e.name for e in out[16]] == ["wh"]
    assert 99 not in out  # sections not asked for are ignored


def test_parse_ls_sections_empty_and_hostile() -> None:
    assert parse_ls_sections("", [2]) == {}
    long_name = "x" * 5000
    text = f"debugfs: ls -l <2>\n     13  100664 (1)  0  0  3 27-Nov-2026 17:59 {long_name}\n"
    assert parse_ls_sections(text, [2]) == {2: []}


def _e(ino: int, mode: int = 0o100644, size: int = 1, mtime: str = "t", name: str = "n") -> LsEntry:
    return LsEntry(ino, mode, size, mtime, name)


def test_diff_listings() -> None:
    base = {
        "/same": _e(1),
        "/dir": _e(2, 0o40755, 4096, "t1"),
        "/gone": _e(3),
        "/resized": _e(4, size=1),
        "/touched": _e(5, mtime="t1"),
    }
    cur = {
        "/same": _e(1),
        "/dir": _e(2, 0o40755, 4096, "t2"),
        "/resized": _e(4, size=2),
        "/touched": _e(5, mtime="t2"),
        "/new": _e(6),
        "/newdir": _e(7, 0o40755),
    }
    assert diff_listings(base, cur, 100) == ("/gone", "/new", "/newdir", "/resized", "/touched")
    assert diff_listings(base, cur, 2) == ("/gone", "/new")
    assert diff_listings({}, {}, 10) == ()


# -- Firecracker API client ----------------------------------------------------


def test_parse_http_head() -> None:
    status, headers = parse_http_head(b"HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\nContent-Length: 0")
    assert status == 204 and headers["content-length"] == "0"
    for bad in (b"SSH-2.0", b"HTTP/1.1 999 x", b"HTTP/1.1 200 OK\r\nnocolon", "HTTP/1.1 200 \xe9".encode("latin-1")):
        with pytest.raises(EmberpoolError):
            parse_http_head(bad)


async def _serve(path: Path, reply: bytes) -> tuple[asyncio.Server, list[bytes]]:
    seen: list[bytes] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(await reader.read(65536))
        writer.write(reply)
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(handler, str(path))
    return server, seen


async def test_api_call_ok_and_request_shape(short_tmp: Path) -> None:
    sock = short_tmp / "api.sock"
    server, seen = await _serve(sock, b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    async with server:
        body = await fc._api_call(sock, "PUT", "/actions", {"action_type": "InstanceStart"}, 5)
    assert body == b""
    req = seen[0]
    assert req.startswith(b"PUT /actions HTTP/1.1\r\n")
    assert req.endswith(b'{"action_type":"InstanceStart"}')


async def test_api_call_error_reports_fault(short_tmp: Path) -> None:
    sock = short_tmp / "api.sock"
    body = b'{"fault_message":"Load snapshot error"}'
    reply = b"HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    server, _ = await _serve(sock, reply)
    async with server:
        with pytest.raises(EmberpoolError, match="Load snapshot error"):
            await fc._api_call(sock, "PUT", "/snapshot/load", {}, 5)


@pytest.mark.parametrize(
    "reply",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
        b"HTTP/1.1 200 OK\r\nX: " + b"a" * 70000 + b"\r\n\r\n",
        b"",
    ],
)
async def test_api_call_rejects_bad_responses(short_tmp: Path, reply: bytes) -> None:
    sock = short_tmp / "api.sock"
    server, _ = await _serve(sock, reply)
    async with server:
        with pytest.raises(EmberpoolError):
            await fc._api_call(sock, "GET", "/", None, 5)


async def test_api_call_times_out(short_tmp: Path) -> None:
    sock = short_tmp / "api.sock"

    async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read()  # until the client gives up and closes
        finally:
            writer.close()

    server = await asyncio.start_unix_server(silent, str(sock))
    async with server:
        with pytest.raises(TimeoutError):
            await fc._api_call(sock, "GET", "/", None, 0.2)


# -- readiness probe ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("reply", "ok"),
    [(b"OK 1073741824\n", True), (b"", False), (b"NO\n", False), (b"OK x\n", False), (b"OK " + b"9" * 200, False)],
)
async def test_probe_agent(short_tmp: Path, reply: bytes, ok: bool) -> None:
    sock = short_tmp / "v.sock"
    server, seen = await _serve(sock, reply)
    async with server:
        assert await fc._probe_agent(sock) is ok
    assert seen[0] == b"CONNECT 1024\n"


async def test_probe_agent_missing_socket(short_tmp: Path) -> None:
    assert await fc._probe_agent(short_tmp / "none.sock") is False


# -- engine state machine without VMs ----------------------------------------------


class StubExec:
    def __init__(self, result: ExecResult | Exception) -> None:
        self.result = result
        self.calls: list[tuple[Path, str, float]] = []

    async def run(self, vsock_path: Path, code: str, timeout: float) -> ExecResult:
        self.calls.append((vsock_path, code, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _register(engine: FirecrackerEngine, vm_id: str = "abc123", killed: bool = False) -> None:
    layout = engine.config.jailer.layout(vm_id)
    engine._vms[vm_id] = fc._VM(layout, "ep-x-ns", killed=killed)


async def test_check_vmgenid_without_exec_client_fails_closed() -> None:
    engine = FirecrackerEngine(fcfg())
    _register(engine)
    assert await engine.check_vmgenid(handle()) is False


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ExecResult("vmgenid:bound\n", "", 0), True),
        (ExecResult("vmgenid:unbound\n", "", 0), False),
        (ExecResult("vmgenid:bound\n", "", 1), False),
        (ExecResult("vmgenid:bound\nvmgenid:bound\n", "", 0), False),
        (ExecResult("", "Traceback", 1), False),
        (ConnectionRefusedError(), False),
        (TimeoutError(), False),
    ],
)
async def test_check_vmgenid_answers(result: ExecResult | Exception, expected: bool) -> None:
    stub = StubExec(result)
    engine = FirecrackerEngine(fcfg(), exec_client=stub)
    _register(engine)
    assert await engine.check_vmgenid(handle()) is expected
    path, code, _ = stub.calls[0]
    assert path == engine.config.jailer.layout("abc123").vsock
    assert "/sys/bus/platform/drivers/vmgenid" in code


async def test_check_vmgenid_unknown_or_killed_vm_is_false() -> None:
    stub = StubExec(ExecResult("vmgenid:bound\n", "", 0))
    engine = FirecrackerEngine(fcfg(), exec_client=stub)
    assert await engine.check_vmgenid(handle()) is False
    _register(engine, killed=True)
    assert await engine.check_vmgenid(handle()) is False
    assert stub.calls == []


async def test_list_changes_requires_known_killed_vm() -> None:
    engine = FirecrackerEngine(fcfg())
    with pytest.raises(EmberpoolError, match="unknown"):
        await engine.list_changes(handle())
    _register(engine)
    with pytest.raises(EmberpoolError, match="before kill"):
        await engine.list_changes(handle())


async def test_kill_and_cleanup_unknown_vm_are_noops() -> None:
    engine = FirecrackerEngine(fcfg())
    await engine.kill(handle())
    await engine.cleanup(handle())
    await engine.cleanup(handle())
    assert engine.tracked() == []


async def test_cleanup_removes_jail_of_tracked_vm_without_process(short_tmp: Path) -> None:
    engine = FirecrackerEngine(fcfg(short_tmp / "j"))
    layout = engine.config.jailer.layout("abc123")
    create_jail(layout)
    (layout.root / "scratch.ext4").write_bytes(b"x")
    _register(engine)
    await engine.cleanup(handle())
    assert not layout.id_dir.exists()
    assert engine.tracked() == []
    await engine.cleanup(handle())


async def test_restore_rejects_bad_names_before_touching_anything(short_tmp: Path) -> None:
    engine = FirecrackerEngine(fcfg(short_tmp / "j"))
    tmpl = fc.Template(short_tmp / "s", short_tmp / "m", short_tmp / "r")
    with pytest.raises(ValueError):
        await engine.restore(tmpl, "../x", "ep-x-ns")
    with pytest.raises(ValueError):
        await engine.restore(tmpl, "abc123", "not-ours")
    assert not (short_tmp / "j").exists()


def test_tail_is_bounded_and_escaped() -> None:
    tail = fc._Tail(cap=100)
    for _ in range(50):
        tail.add(b"\x1b[31mred\n" * 3)
    assert sum(len(c) for c in tail._buf) <= 100 + 30
    text = tail.text()
    assert "\x1b" not in text and "\n" not in text
