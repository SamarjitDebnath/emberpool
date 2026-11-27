"""End to end: SandboxPool on the real backends (Firecracker under the jailer,
HostNetPolicy, VsockExecClient, TraceWriter on nflog). Root and KVM only.

Needs:
  EMBERPOOL_FC_DIR      directory with `firecracker`, `Image` and the jailer
                        (`jailer`, or `release-*/jailer-*-<arch>`)
  EMBERPOOL_TEST_ROOTFS guest image with the emberpool agent (default:
                        $EMBERPOOL_FC_DIR/ep-exec-rootfs.ext4)

Deny and the stand-in allow test run with the test process switched into a
private "<prefix>-e2e" namespace that plays the host's root namespace, so they
neither depend on nor disturb the host firewall. The real pypi.org test runs
in the root namespace and skips when another firewall would drop forwarded
VM traffic (HostNetPolicy refuses to start there).

Every namespace, interface, table, directory and cgroup is named with the test
prefix and removed afterwards.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import platform
import shutil
import signal
import socket
import tempfile
import zlib
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from emberpool import SandboxPool, Settings
from emberpool._firecracker import FirecrackerConfig
from emberpool._jailer import CGROUP_ROOT, JailerConfig
from emberpool._names import run_command
from emberpool._resolver import LookupResult
from emberpool._types import ConnEvent, DnsEvent, Result
from emberpool._wiring import Backends, real_backends
from emberpool.netpolicy import forward_block_message, forward_blockers

pytestmark = pytest.mark.vm

JAIL_ID = 10123
T = 15.0

DENY_CODE = """
import socket
try:
    socket.getaddrinfo("pypi.org", 443, proto=socket.IPPROTO_TCP)
    print("dns:ok")
except socket.gaierror:
    print("dns:fail")
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("151.101.0.223", 443))
    print("conn:ok")
except OSError:
    print("conn:fail")
"""


def fetch_code(url: str) -> str:
    return (
        "import urllib.request\n"
        f"with urllib.request.urlopen({url!r}, timeout=20) as r:\n"
        "    body = r.read(65536)\n"
        "    print('status', r.status, len(body) > 0)\n"
    )


# -- environment ------------------------------------------------------------------


def _find_jailer(fc_dir: Path) -> Path | None:
    if (fc_dir / "jailer").is_file():
        return fc_dir / "jailer"
    for path in sorted(fc_dir.glob(f"release-*/jailer-*-{platform.machine()}")):
        if path.is_file():
            return path
    return None


async def sh(*argv: str, check: bool = True) -> bytes:
    return (await run_command(list(argv), timeout=T, check=check)).stdout


@pytest.fixture
def engine_config(test_prefix: str):
    fc_text = os.environ.get("EMBERPOOL_FC_DIR")
    if not fc_text:
        pytest.skip("EMBERPOOL_FC_DIR not set")
    fc_dir = Path(fc_text)
    jailer = _find_jailer(fc_dir)
    rootfs = Path(os.environ.get("EMBERPOOL_TEST_ROOTFS", fc_dir / "ep-exec-rootfs.ext4"))
    for path in (fc_dir / "firecracker", fc_dir / "Image", rootfs):
        if not path.is_file():
            pytest.skip(f"missing {path}")
    if jailer is None:
        pytest.skip(f"no jailer in {fc_dir}")
    base = Path(tempfile.mkdtemp(prefix=f"{test_prefix}-", dir="/tmp"))
    os.chmod(base, 0o755)
    socks_before = set(Path("/tmp").glob("fc-*.sock"))
    cfg = FirecrackerConfig(
        jailer=JailerConfig(
            jailer_bin=jailer,
            firecracker_bin=fc_dir / "firecracker",
            chroot_base=base / "j",
            uid=JAIL_ID,
            gid=JAIL_ID,
            parent_cgroup=test_prefix,
        ),
        kernel_path=fc_dir / "Image",
        rootfs_path=rootfs,
        scratch_size_mib=64,
    )
    try:
        yield cfg
    finally:
        # Safety net only: the pool should have stopped everything already.
        jail_dir = cfg.jailer.chroot_base / cfg.jailer.exec_name
        leftover_ids = {p.name for p in jail_dir.iterdir()} if jail_dir.is_dir() else set()
        stray = _vmm_pids(leftover_ids)
        for pid in stray:
            os.kill(pid, signal.SIGKILL)
        shutil.rmtree(base, ignore_errors=True)
        with contextlib.suppress(OSError):
            os.rmdir(CGROUP_ROOT / test_prefix)
        new_socks = set(Path("/tmp").glob("fc-*.sock")) - socks_before
        for sock in new_socks:
            sock.unlink(missing_ok=True)
        assert not stray, f"VMM processes left running: {stray}"
        assert not leftover_ids, f"jails left behind: {leftover_ids}"
        assert not new_socks, f"sockets left behind: {new_socks}"


def _vmm_pids(vm_ids: set[str]) -> list[int]:
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            argv = Path(f"/proc/{entry}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        for i, arg in enumerate(argv[:-1]):
            if arg == b"--id" and argv[i + 1].decode("ascii", "replace") in vm_ids:
                pids.append(int(entry))
    return pids


async def our_netns(prefix: str) -> set[str]:
    out = await sh("ip", "-j", "netns", "list")
    return {e["name"] for e in json.loads(out or b"[]") if e["name"].startswith(f"{prefix}-")}


@contextlib.asynccontextmanager
async def private_host(prefix: str) -> AsyncIterator[str]:
    """Switch this thread into a fresh namespace that plays the host."""
    ns = f"{prefix}-e2e"
    await sh("ip", "netns", "add", ns)
    orig = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
    try:
        fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
        try:
            os.setns(fd, os.CLONE_NEWNET)
        finally:
            os.close(fd)
        try:
            await sh("ip", "link", "set", "lo", "up")
            # A default route, as a real host has, so traffic to the internet
            # reaches the forward hook (and emberpool's drop) instead of failing
            # the route lookup. The dummy device goes with the namespace.
            await sh("ip", "link", "add", f"{prefix}-d", "type", "dummy")
            await sh("ip", "link", "set", f"{prefix}-d", "up")
            await sh("ip", "route", "add", "default", "dev", f"{prefix}-d")
            yield ns
        finally:
            os.setns(orig, os.CLONE_NEWNET)
    finally:
        os.close(orig)
        await sh("ip", "netns", "del", ns, check=False)


@contextlib.asynccontextmanager
async def index_server(prefix: str, root: Path) -> AsyncIterator[str]:
    """A prefixed namespace on the (private) host serving `root` over HTTP on
    8080. Yields its address."""
    o = zlib.crc32(f"{prefix}-e2e".encode()) % 250
    ns, host_if = f"{prefix}-pypi", f"{prefix}-p"
    addr = f"198.18.{o}.2"
    proc: asyncio.subprocess.Process | None = None
    try:
        await sh("ip", "netns", "add", ns)
        await sh("ip", "link", "add", host_if, "type", "veth", "peer", "name", "ep-pypi", "netns", ns)
        await sh("ip", "addr", "add", f"198.18.{o}.1/29", "dev", host_if)
        await sh("ip", "link", "set", host_if, "up")
        await sh("ip", "-n", ns, "addr", "add", f"{addr}/29", "dev", "ep-pypi")
        await sh("ip", "-n", ns, "link", "set", "ep-pypi", "up")
        await sh("ip", "-n", ns, "link", "set", "lo", "up")
        await sh("ip", "-n", ns, "route", "add", "default", "via", f"198.18.{o}.1")
        proc = await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", ns, "python3", "-m", "http.server", "8080",
            "--bind", addr, "--directory", str(root),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        for _ in range(100):
            with contextlib.suppress(OSError), socket.create_connection((addr, 8080), timeout=0.2):
                break
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("stand-in index server did not start")
        yield addr
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), T)
        await sh("ip", "link", "del", host_if, check=False)
        await sh("ip", "netns", "del", ns, check=False)


async def run_pool(backends: Backends, network: str, codes: list[str]) -> list[Result]:
    async with SandboxPool(2, network, **backends.pool_kwargs()) as pool:
        results = [await pool.run(code, timeout=60) for code in codes]
    assert backends.engine.tracked() == []
    return results


def dns_events(r: Result, name: str) -> list[DnsEvent]:
    return [e for e in r.trace if isinstance(e, DnsEvent) and e.name == name]


def conn_events(r: Result) -> list[ConnEvent]:
    return [e for e in r.trace if isinstance(e, ConnEvent)]


def assert_allowed_fetch(r: Result, port: int) -> None:
    assert r.exit_code == 0, r.stderr
    assert not r.timed_out
    assert r.stdout.startswith("status 200 True"), r.stdout
    dns = dns_events(r, "pypi.org")
    answered = [e for e in dns if e.answers]
    assert answered, f"no answered pypi.org query in {r.trace.to_dict()}"
    ips = {ip for e in answered for ip in e.answers or ()}
    allowed = [e for e in conn_events(r) if e.verdict == "allowed"]
    assert allowed, f"no allowed connection in {r.trace.to_dict()}"
    assert any(
        e.dst_ip in ips and e.dst_port == port and e.protocol == "tcp" and e.name == "pypi.org"
        for e in allowed
    )
    assert not [e for e in conn_events(r) if e.verdict == "dropped" and e.dst_ip in ips]
    times = [e.time for e in r.trace]
    assert times == sorted(times)


# -- tests ----------------------------------------------------------------------------


async def test_deny_pool_records_nxdomain_and_drop(engine_config, test_prefix):
    async with private_host(test_prefix) as host:
        async with real_backends(
            engine_config, prefix=test_prefix, table=test_prefix, nflog_netns=host
        ) as b:
            first, second = await run_pool(b, "deny", [DENY_CODE, DENY_CODE])
        assert await our_netns(test_prefix) == {host}

    assert await our_netns(test_prefix) == set()
    for r in (first, second):
        assert r.exit_code == 0, r.stderr
        assert not r.timed_out
        assert r.stdout == "dns:fail\nconn:fail\n"
        dns = dns_events(r, "pypi.org")
        assert dns, f"no pypi.org query in {r.trace.to_dict()}"
        assert all(e.answers is None for e in dns)  # NXDOMAIN
        assert r.trace.to_dict()["events"][0]["rcode"] == "NXDOMAIN"
        assert not [e for e in conn_events(r) if e.verdict == "allowed"]
        assert any(
            e.dst_ip == "151.101.0.223" and e.dst_port == 443 and e.protocol == "tcp"
            and e.verdict == "dropped"
            for e in conn_events(r)
        )
    # Each run had its own VM: nothing in the trace belongs to the other.
    assert {e.vm_id for e in first.trace}.isdisjoint({e.vm_id for e in second.trace})


async def test_allow_pypi_fetches_index(engine_config, test_prefix):
    ruleset = json.loads(await sh("nft", "-j", "list", "ruleset"))
    blockers = forward_blockers(ruleset, test_prefix, test_prefix)
    if blockers:
        pytest.skip("real egress unavailable: " + forward_block_message(blockers, test_prefix))
    async with real_backends(engine_config, prefix=test_prefix, table=test_prefix) as b:
        (r,) = await run_pool(b, "allow:pypi.org", [fetch_code("https://pypi.org/simple/pip/")])
    assert await our_netns(test_prefix) == set()
    assert_allowed_fetch(r, 443)


async def test_allow_stand_in_index(engine_config, test_prefix, tmp_path):
    """The allow path on a host without real egress: pypi.org resolves (through
    the real resolver, with a stubbed upstream) to a prefixed server namespace."""
    root = tmp_path / "www"
    (root / "simple" / "pip").mkdir(parents=True)
    (root / "simple" / "pip" / "index.html").write_text("<a>pip-1.0.tar.gz</a>\n")
    os.chmod(tmp_path, 0o755)
    async with private_host(test_prefix) as host:
        async with index_server(test_prefix, root) as addr:

            async def lookup(name: str) -> LookupResult:
                return LookupResult((addr,) if name == "pypi.org" else None, 30)

            async with real_backends(
                engine_config, prefix=test_prefix, table=test_prefix, lookup=lookup, nflog_netns=host
            ) as b:
                (r,) = await run_pool(
                    b, "allow:pypi.org", [fetch_code("http://pypi.org:8080/simple/pip/")]
                )
    assert await our_netns(test_prefix) == set()
    assert_allowed_fetch(r, 8080)


# -- the public path: SandboxPool(size, network, settings) in the root namespace --------


async def skip_unless_forward_open(prefix: str, table: str) -> None:
    ruleset = json.loads(await sh("nft", "-j", "list", "ruleset"))
    blockers = forward_blockers(ruleset, prefix, table)
    if blockers:
        pytest.skip("host forward path blocked: " + forward_block_message(blockers, prefix))


async def our_tables(prefix: str) -> list[str]:
    out = (await sh("nft", "-j", "list", "tables")).decode()
    return [
        t["table"]["name"] for t in json.loads(out)["nftables"]
        if "table" in t and t["table"]["name"].startswith(prefix)
    ]


@pytest.fixture
async def settings(engine_config: FirecrackerConfig, test_prefix: str) -> AsyncIterator[Settings]:
    await skip_unless_forward_open(test_prefix, test_prefix)
    jail = engine_config.jailer
    yield Settings(
        firecracker=jail.firecracker_bin,
        jailer=jail.jailer_bin,
        kernel=engine_config.kernel_path,
        rootfs=engine_config.rootfs_path,
        jail_base=jail.chroot_base,
        jail_uid=jail.uid,
        jail_gid=jail.gid,
        prefix=test_prefix,
    )
    assert await our_netns(test_prefix) == set()
    assert await our_tables(test_prefix) == []


async def test_timeout_kills_vm(settings):
    async with SandboxPool(1, "deny", settings) as pool:
        async with pool.checkout(60) as sandbox:
            vm_id = sandbox.vm_id
            r = await sandbox.run("while True:\n    pass\n", 3)
        assert r.timed_out and r.exit_code == -1 and r.stdout == ""
        assert vm_id not in pool._engine.tracked()  # type: ignore[attr-defined]
        assert _vmm_pids({vm_id}) == []
        # The pool keeps working after a kill.
        again = await pool.run("print('ok')", 60)
        assert again.stdout == "ok\n" and not again.timed_out


async def test_empty_pool_waits_then_runs(settings):
    async with SandboxPool(2, "deny", settings) as pool:
        async with pool.checkout(60) as a, pool.checkout(60) as b:
            # Both warm VMs are taken; their replacements are still restoring.
            assert len(pool._idle) == 0
            r = await pool.run("print('waited')", 120)
            assert r.exit_code == 0 and r.stdout == "waited\n"
            ra, rb = await a.run("print('a')", 60), await b.run("print('b')", 60)
        assert (ra.stdout, rb.stdout) == ("a\n", "b\n")


async def test_concurrent_runs_on_pool_of_two(settings):
    code = "import os\nprint(os.urandom(16).hex())\n"
    async with SandboxPool(2, "deny", settings) as pool:
        results = await asyncio.gather(*(pool.run(code, 180) for _ in range(6)))
        engine = pool._engine
    assert all(r.exit_code == 0 and not r.timed_out for r in results), [r.stderr for r in results]
    outputs = [r.stdout for r in results]
    assert len(set(outputs)) == len(outputs)  # fresh VM and fresh random state per run
    assert engine.tracked() == []  # type: ignore[attr-defined]
