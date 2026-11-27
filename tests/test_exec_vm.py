"""Boot a real microVM from the built rootfs and talk to the agent over vsock.

Needs root, KVM, a Firecracker binary, the guest kernel and a rootfs built by
scripts/build-rootfs.sh. Paths come from the environment:

    EMBERPOOL_FC_DIR       directory with `firecracker` and `Image` (default ~/fc)
    EMBERPOOL_TEST_ROOTFS  rootfs image (default $EMBERPOOL_FC_DIR/rootfs-agent.ext4)

Firecracker runs without the jailer here, which only tests marked `vm` may do
(docs/40-rules.md rule 4).
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import signal
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from emberpool._names import run_command
from emberpool.exec_client import VsockExecClient, wait_ready

pytestmark = pytest.mark.vm

FC_DIR = Path(os.environ.get("EMBERPOOL_FC_DIR", "~/fc")).expanduser()
FIRECRACKER = FC_DIR / "firecracker"
KERNEL = FC_DIR / "Image"
ROOTFS = Path(os.environ.get("EMBERPOOL_TEST_ROOTFS", str(FC_DIR / "rootfs-agent.ext4"))).expanduser()
BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off"
BOOT_TIMEOUT = 60.0  # generous: nested virtualization is slow


@pytest.fixture
def images():
    missing = [p for p in (FIRECRACKER, KERNEL, ROOTFS) if not p.exists()]
    if missing:
        pytest.skip(f"missing {', '.join(map(str, missing))}; build the rootfs with scripts/build-rootfs.sh")


class FcProcess:
    """One unjailed Firecracker process with an API socket."""

    def __init__(self, workdir: Path, prefix: str):
        self.workdir = workdir
        self.api_sock = Path(f"/tmp/fc-{prefix}-{secrets.token_hex(4)}.sock")
        self.log = workdir / f"fc-{self.api_sock.stem}.log"
        self.proc: asyncio.subprocess.Process | None = None

    async def start(self, config: Path | None = None) -> None:
        argv = [str(FIRECRACKER), "--api-sock", str(self.api_sock)]
        if config is not None:
            argv += ["--config-file", str(config)]
        with open(self.log, "wb") as log:
            self.proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True
            )
        async with asyncio.timeout(10):
            while not self.api_sock.exists():
                if self.proc.returncode is not None:
                    raise RuntimeError(f"firecracker exited: {self.log_tail()}")
                await asyncio.sleep(0.02)

    async def api(self, method: str, path: str, body: dict) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(self.api_sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=60) as c:
            r = await c.request(method, path, json=body)
        assert r.status_code < 300, f"{method} {path}: {r.status_code} {r.text}"

    async def kill(self) -> None:
        if self.proc is not None and self.proc.returncode is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await asyncio.wait_for(self.proc.wait(), 10)
        self.api_sock.unlink(missing_ok=True)

    def log_tail(self) -> str:
        try:
            return self.log.read_text(errors="replace")[-3000:]
        except OSError:
            return ""


@pytest.fixture
async def workdir(test_prefix, images) -> AsyncIterator[Path]:
    d = Path(tempfile.mkdtemp(prefix=f"{test_prefix}-vm-", dir="/tmp"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


async def _make_scratch(path: Path) -> None:
    with open(path, "wb") as f:
        f.truncate(64 * 1024 * 1024)
    await run_command(["mkfs.ext4", "-q", "-F", str(path)], timeout=30)


async def _write_config(workdir: Path) -> Path:
    scratch = workdir / "scratch.ext4"
    await _make_scratch(scratch)
    config = {
        "boot-source": {"kernel_image_path": str(KERNEL), "boot_args": BOOT_ARGS},
        "drives": [
            {"drive_id": "rootfs", "path_on_host": str(ROOTFS), "is_root_device": True, "is_read_only": True},
            {"drive_id": "scratch", "path_on_host": str(scratch), "is_root_device": False, "is_read_only": False},
        ],
        "machine-config": {"vcpu_count": 1, "mem_size_mib": 512},
        "vsock": {"guest_cid": 3, "uds_path": str(workdir / "v.sock")},
    }
    path = workdir / "vm.json"
    path.write_text(json.dumps(config))
    return path


async def _boot(workdir: Path, prefix: str) -> FcProcess:
    fc = FcProcess(workdir, prefix)
    try:
        await fc.start(await _write_config(workdir))
        await wait_ready(workdir / "v.sock", BOOT_TIMEOUT)
    except BaseException:
        log = fc.log_tail()
        await fc.kill()
        print(log)
        raise
    return fc


async def test_boot_and_run(workdir, test_prefix):
    fc = await _boot(workdir, test_prefix)
    try:
        client = VsockExecClient()
        res = await client.run(workdir / "v.sock", "print(1+1)", 30)
        assert (res.stdout, res.stderr, res.exit_code) == ("2\n", "", 0)

        # Root is the overlay; writes land on the scratch drive, not the shared image.
        code = (
            "open('/etc/ep-written', 'w').write('x')\n"
            "print([l.split()[2] for l in open('/proc/mounts') if l.split()[1] == '/'][-1])"
        )
        res = await client.run(workdir / "v.sock", code, 30)
        assert (res.stdout, res.exit_code) == ("overlay\n", 0), res.stderr

        # The agent survives a run that fails, and serves the next one.
        res = await client.run(workdir / "v.sock", "import sys; sys.exit(7)", 30)
        assert res.exit_code == 7
        res = await client.run(workdir / "v.sock", "import time; time.sleep(30)", 1)
        assert res.exit_code == -9 and "timed out" in res.stderr
        res = await client.run(workdir / "v.sock", "print('again')", 30)
        assert res.stdout == "again\n"
    finally:
        await fc.kill()


async def test_agent_survives_snapshot_restore(workdir, test_prefix):
    fc = await _boot(workdir, test_prefix)
    state, mem = workdir / "state", workdir / "mem"
    try:
        await fc.api("PATCH", "/vm", {"state": "Paused"})
        await fc.api(
            "PUT",
            "/snapshot/create",
            {"snapshot_type": "Full", "snapshot_path": str(state), "mem_file_path": str(mem)},
        )
    finally:
        await fc.kill()
    (workdir / "v.sock").unlink(missing_ok=True)

    restored = FcProcess(workdir, test_prefix)
    try:
        await restored.start()
        await restored.api(
            "PUT",
            "/snapshot/load",
            {
                "snapshot_path": str(state),
                "mem_backend": {"backend_type": "File", "backend_path": str(mem)},
                "resume_vm": True,
            },
        )
        # No new boot: the listening socket from before the snapshot serves.
        res = await VsockExecClient().run(workdir / "v.sock", "print(1+1)", 30)
        assert (res.stdout, res.exit_code) == ("2\n", 0), res.stderr
    except BaseException:
        print(restored.log_tail())
        raise
    finally:
        await restored.kill()


async def test_no_scratch_drive_fails_closed(workdir, test_prefix):
    # Without /dev/vdb the guest must not run on the shared root: init powers
    # off, the VM process exits and the agent never becomes ready.
    config_path = await _write_config(workdir)
    config = json.loads(config_path.read_text())
    config["drives"] = config["drives"][:1]
    config_path.write_text(json.dumps(config))
    fc = FcProcess(workdir, test_prefix)
    try:
        await fc.start(config_path)
        with pytest.raises(TimeoutError):
            await wait_ready(workdir / "v.sock", 10)
        assert fc.proc is not None
        await asyncio.wait_for(fc.proc.wait(), BOOT_TIMEOUT)
        assert "ep-init: no scratch drive" in fc.log_tail()
    finally:
        await fc.kill()
