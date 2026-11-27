"""Hostile-guest tests on real VMs (docs/40-rules.md). Root and KVM only.

Each test runs code that behaves like an attacker inside the sandbox and
checks what the HOST observes: the guest's own report is never trusted
(rule 2). All runs use a deny pool inside a private namespace that plays the
host, so nothing here depends on or touches the real host firewall.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from emberpool import SandboxPool
from emberpool._protocol import MAX_OUTPUT_BYTES
from emberpool._types import ConnEvent, DnsEvent, Result
from emberpool._wiring import Backends, real_backends
from tests.test_e2e_vm import _vmm_pids, engine_config, our_netns, private_host  # noqa: F401

pytestmark = pytest.mark.vm

JAIL_ID = 10123
CANARY_KEY = "EMBERPOOL_TEST_CANARY"
CANARY = "canary-6f1d0c2e9b"


@contextlib.asynccontextmanager
async def deny_pool(engine_config, prefix: str, size: int = 1) -> AsyncIterator[tuple[SandboxPool, Backends]]:  # noqa: F811
    async with private_host(prefix) as host:
        async with real_backends(engine_config, prefix=prefix, table=prefix, nflog_netns=host) as b:
            async with SandboxPool(size, "deny", **b.pool_kwargs()) as pool:
                yield pool, b
            assert b.engine.tracked() == []
    assert await our_netns(prefix) == set()


def conns(r: Result) -> list[ConnEvent]:
    return [e for e in r.trace if isinstance(e, ConnEvent)]


def lines(r: Result) -> dict[str, str]:
    out = {}
    for line in r.stdout.splitlines():
        key, _, value = line.partition("=")
        out[key] = value
    return out


ESCAPE_CODE = r'''
import socket

def tcp(host, port, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        return "open"
    except OSError as e:
        return "closed"
    finally:
        s.close()

def dns_direct(server, name):
    # A raw A query sent straight to `server`, bypassing resolv.conf.
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(q, (server, 53))
        data = s.recv(512)
        ancount = int.from_bytes(data[6:8], "big")
        return f"rcode{data[3] & 15}-an{ancount}"
    except OSError:
        return "noreply"
    finally:
        s.close()

print("tap_ssh=" + tcp("172.16.0.1", 22))
print("tap_http=" + tcp("172.16.0.1", 80))
print("uplink_ssh=" + tcp("10.200.0.1", 22))
print("metadata=" + tcp("169.254.169.254", 80))
print("dns_tcp=" + tcp("8.8.8.8", 53))
print("web=" + tcp("151.101.0.223", 443))
print("dns_direct=" + dns_direct("8.8.8.8", "pypi.org"))
print("dns_tap=" + dns_direct("172.16.0.1", "evil.example"))
try:
    print("v6=" + tcp("2606:4700:4700::1111", 443, socket.AF_INET6))
except OSError:
    print("v6=closed")
'''


async def test_guest_cannot_reach_host_metadata_or_internet(engine_config, test_prefix):  # noqa: F811
    async with deny_pool(engine_config, test_prefix) as (pool, _):
        r = await pool.run(ESCAPE_CODE, 90)
    assert r.exit_code == 0 and not r.timed_out, r.stderr
    got = lines(r)
    for key in ("tap_ssh", "tap_http", "uplink_ssh", "metadata", "dns_tcp", "web", "v6"):
        assert got[key] == "closed", (key, got)
    # Direct DNS to any server is answered by emberpool's resolver: no addresses.
    for key in ("dns_direct", "dns_tap"):
        assert got[key] in ("rcode3-an0", "noreply"), (key, got)
    # Host-observed: nothing allowed, the escape attempts are logged as dropped.
    assert not [e for e in conns(r) if e.verdict == "allowed"]
    dropped = {(e.dst_ip, e.dst_port) for e in conns(r) if e.verdict == "dropped"}
    for target in (("151.101.0.223", 443), ("169.254.169.254", 80), ("8.8.8.8", 53)):
        assert target in dropped, (target, r.trace.to_dict())
    names = [e.name for e in r.trace if isinstance(e, DnsEvent)]
    assert "pypi.org" in names and all(
        e.answers is None for e in r.trace if isinstance(e, DnsEvent)
    )


async def test_nothing_persists_between_runs(engine_config, test_prefix):  # noqa: F811
    write = (
        "import pathlib\n"
        "for p in ('/root/marker', '/tmp/marker', '/var/marker'):\n"
        "    pathlib.Path(p).write_text('x')\n"
        "with open('/etc/hosts', 'a') as f:\n"
        "    f.write('6.6.6.6 pypi.org\\n')\n"
        "print('written')\n"
    )
    check = (
        "import os\n"
        "print([p for p in ('/root/marker', '/tmp/marker', '/var/marker') if os.path.exists(p)])\n"
        "print('6.6.6.6' in open('/etc/hosts').read())\n"
    )
    async with deny_pool(engine_config, test_prefix) as (pool, _):
        first = await pool.run(write, 60)
        second = await pool.run(check, 60)
    assert first.stdout == "written\n", first.stderr
    assert second.stdout == "[]\nFalse\n", second.stdout
    assert any(c.endswith("marker") for c in first.file_changes)
    assert {e.vm_id for e in first.trace}.isdisjoint({e.vm_id for e in second.trace})


async def test_host_environment_never_reaches_guest_or_vmm(engine_config, test_prefix, monkeypatch):  # noqa: F811
    monkeypatch.setenv(CANARY_KEY, CANARY)
    code = (
        "import os, glob\n"
        "hits = [k for k, v in os.environ.items() if 'canary' in (k + v).lower()]\n"
        "for path in glob.glob('/proc/*/environ'):\n"
        "    try:\n"
        "        if b'canary' in open(path, 'rb').read().lower():\n"
        "            hits.append(path)\n"
        "    except OSError:\n"
        "        pass\n"
        "print(hits)\n"
    )
    async with deny_pool(engine_config, test_prefix) as (pool, _):
        async with pool.checkout(60) as sandbox:
            pid = sandbox._vm.handle.pid  # type: ignore[attr-defined]
            vmm_env = Path(f"/proc/{pid}/environ").read_bytes()
            r = await sandbox.run(code, 60)
    assert r.stdout == "[]\n", r.stdout
    assert CANARY.encode() not in vmm_env
    assert CANARY_KEY.encode() not in vmm_env


def _status(pid: int) -> dict[str, str]:
    out = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        out[key] = value.strip()
    return out


async def test_vmm_is_confined(engine_config, test_prefix):  # noqa: F811
    async with deny_pool(engine_config, test_prefix) as (pool, _):
        async with pool.checkout(60) as sandbox:
            pid = sandbox._vm.handle.pid  # type: ignore[attr-defined]
            st = _status(pid)
            # The jailer pivots into the chroot in a new mount namespace, so
            # look at what the process can see rather than the link text.
            visible = set(os.listdir(f"/proc/{pid}/root"))
            vmm_mnt = os.readlink(f"/proc/{pid}/ns/mnt")
            host_mnt = os.readlink("/proc/self/ns/mnt")
            vmm_net = os.readlink(f"/proc/{pid}/ns/net")
            host_net = os.readlink("/proc/self/ns/net")
            await sandbox.run("print(1)", 60)
    # Dropped to the jail user, no capabilities, seccomp filter on, chrooted,
    # and in its own network namespace (docs/00-scope.md trust model).
    assert st["Uid"].split() == [str(JAIL_ID)] * 4, st["Uid"]
    assert st["Gid"].split() == [str(JAIL_ID)] * 4, st["Gid"]
    assert int(st["CapEff"], 16) == 0 and int(st["CapPrm"], 16) == 0
    assert st["Seccomp"] == "2"
    assert vmm_mnt != host_mnt
    assert not visible & {"etc", "home", "root", "usr", "proc", "tmp"}, visible
    assert "firecracker" in visible, visible
    assert vmm_net != host_net


async def test_output_flood_is_capped(engine_config, test_prefix):  # noqa: F811
    code = (
        "import sys\n"
        "chunk = 'A' * 65536\n"
        "for _ in range(160):\n"
        "    sys.stdout.write(chunk)\n"
        "    sys.stderr.write(chunk)\n"
    )
    async with deny_pool(engine_config, test_prefix) as (pool, _):
        r = await pool.run(code, 90)
        after = await pool.run("print('ok')", 60)
    assert len(r.stdout.encode()) <= MAX_OUTPUT_BYTES
    assert len(r.stderr.encode()) <= MAX_OUTPUT_BYTES + 4096  # plus the agent's note
    assert after.stdout == "ok\n"


async def test_killing_the_agent_only_costs_the_caller(engine_config, test_prefix):  # noqa: F811
    code = "import os, signal, time\nos.kill(os.getppid(), signal.SIGKILL)\ntime.sleep(30)\n"
    async with deny_pool(engine_config, test_prefix) as (pool, b):
        async with pool.checkout(60) as sandbox:
            vm_id = sandbox.vm_id
            r = await sandbox.run(code, 20)
        after = await pool.run("print('ok')", 60)
        assert vm_id not in b.engine.tracked()
    assert r.exit_code == -1
    assert _vmm_pids({vm_id}) == []
    assert after.stdout == "ok\n"


@pytest.mark.parametrize(
    "name,code",
    [
        ("fork_bomb", "import os\nwhile True:\n    try:\n        os.fork()\n    except OSError:\n        pass\n"),
        ("memory_bomb", "blocks = []\nwhile True:\n    blocks.append(bytearray(64 << 20))\n"),
        ("cpu_spin", "while True:\n    pass\n"),
        ("ignore_sigterm",
         "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nwhile True:\n    time.sleep(1)\n"),
    ],
)
async def test_resource_abuse_is_contained(engine_config, test_prefix, name, code):  # noqa: F811
    async with deny_pool(engine_config, test_prefix) as (pool, b):
        async with pool.checkout(60) as sandbox:
            vm_id = sandbox.vm_id
            r = await sandbox.run(code, 8)
        after = await pool.run("print('ok')", 60)
        assert vm_id not in b.engine.tracked()
    # Either the guest's own limits stopped it or the host killed the VM; the
    # VMM is gone either way and the pool keeps serving.
    assert r.timed_out or r.exit_code != 0, (name, r)
    assert _vmm_pids({vm_id}) == []
    assert after.stdout == "ok\n", (name, after.stderr)


async def test_disk_fill_and_hostile_names(engine_config, test_prefix):  # noqa: F811
    code = (
        "import os\n"
        "os.makedirs('/tmp/n', exist_ok=True)\n"
        "for name in ('new\\nline', '\\x1b[31mred', 'a' * 255, 'sp ace', '..dots', 'uni-\u00fc'):\n"
        "    open(os.path.join('/tmp/n', name), 'w').write('x')\n"
        "for i in range(3000):\n"
        "    open(f'/tmp/n/f{i}', 'w').close()\n"
        "try:\n"
        "    with open('/tmp/fill', 'wb') as f:\n"
        "        while True:\n"
        "            f.write(b'\\0' * (1 << 20))\n"
        "except OSError as e:\n"
        "    print('full', e.errno)\n"
    )
    async with deny_pool(engine_config, test_prefix) as (pool, _):
        r = await pool.run(code, 120)
        after = await pool.run("import os\nprint(os.path.exists('/tmp/fill'))\n", 60)
    assert r.stdout.startswith("full"), (r.stdout, r.stderr)
    # The change list is bounded and every entry is a single escaped line.
    assert 0 < len(r.file_changes) <= 100_000
    for path in r.file_changes:
        assert "\n" not in path and "\x1b" not in path and "\x00" not in path, repr(path)
    assert any("fill" in p for p in r.file_changes)
    assert after.stdout == "False\n"
