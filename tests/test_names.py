import asyncio
import sys

import pytest

from emberpool import _names as n

HOSTILE = [
    "",
    " ",
    "a b",
    "a;rm -rf /",
    "$(id)",
    "`id`",
    "a\nb",
    "a\x00b",
    "../etc",
    "a/b",
    "-rf",
    "A",
    "ü",
    "a" * 300,
    None,
    1,
    b"ep-x",
]


@pytest.mark.parametrize("bad", HOSTILE + ["-ab", "ab-", "a_b", "a.b"])
def test_vm_id_rejects(bad):
    with pytest.raises(ValueError):
        n.validate_vm_id(bad)


@pytest.mark.parametrize("good", ["a", "a3f1", "a3f1b2c4", "ep-net-1", "0" * 32])
def test_vm_id_accepts(good):
    assert n.validate_vm_id(good) == good


def test_vm_id_length_cap():
    with pytest.raises(ValueError):
        n.validate_vm_id("a" * 33)


def test_new_vm_id_is_valid_and_unique():
    ids = {n.new_vm_id() for _ in range(100)}
    assert len(ids) == 100
    for i in ids:
        n.validate_vm_id(i)


@pytest.mark.parametrize("good", ["ep-a3f1", "ep-net-a3f1", "ep0-tmpl", "ep" + "a" * 38])
def test_netns_accepts(good):
    assert n.validate_netns(good) == good


@pytest.mark.parametrize("bad", HOSTILE + ["netns", "ep", "ep-", "EP-a", "ep_a", "ep" + "a" * 39, "x-ep-a"])
def test_netns_rejects(bad):
    with pytest.raises(ValueError):
        n.validate_netns(bad)


@pytest.mark.parametrize("good", ["tap0", "ep-h0", "ep-h255", "ep-net-h12", "ep" + "a" * 13])
def test_interface_accepts(good):
    assert n.validate_interface(good) == good


@pytest.mark.parametrize(
    "bad", HOSTILE + ["eth0", "tap1", "lo", "ep" + "a" * 14, "ep-h0-", "ep-h0:1", "ep-h0.1", "ep"]
)
def test_interface_rejects(bad):
    with pytest.raises(ValueError):
        n.validate_interface(bad)


def test_interface_max_15():
    assert len(n.validate_interface("ep-abcdefghijkl")) == 15
    with pytest.raises(ValueError):
        n.validate_interface("ep-abcdefghijklm")


@pytest.mark.parametrize("good", ["emberpool", "ep-net-test", "ep_trace_1"])
def test_nft_table_accepts(good):
    assert n.validate_nft_table(good) == good


@pytest.mark.parametrize("bad", HOSTILE + ["filter", "inet", "ep-", "ep}", "ep;flush ruleset", "ep" + "a" * 31])
def test_nft_table_rejects(bad):
    with pytest.raises(ValueError):
        n.validate_nft_table(bad)


@pytest.mark.parametrize("good", ["allow_a3f1", "allow-ep-net-a3f1", "a"])
def test_nft_set_accepts(good):
    assert n.validate_nft_set(good) == good


@pytest.mark.parametrize("bad", HOSTILE + ["1abc", "_x", "a{b}", "a" * 64])
def test_nft_set_rejects(bad):
    with pytest.raises(ValueError):
        n.validate_nft_set(bad)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("pypi.org", "pypi.org"),
        ("PyPI.ORG", "pypi.org"),
        ("files.pythonhosted.org.", "files.pythonhosted.org"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("a-b.c0.io", "a-b.c0.io"),
    ],
)
def test_domain_accepts_and_normalises(raw, expected):
    assert n.validate_domain(raw) == expected


@pytest.mark.parametrize(
    "bad",
    HOSTILE
    + [
        "localhost",
        "*.pypi.org",
        "pypi..org",
        ".pypi.org",
        "-pypi.org",
        "pypi-.org",
        "pypi.org..",
        "pypi_org.com",
        "1.2.3.4",
        "pypi.org/simple",
        "pypi.org:443",
        "bücher.de",
        ("a" * 64) + ".com",
        ".".join(["a" * 63] * 4) + ".com",
    ],
)
def test_domain_rejects(bad):
    with pytest.raises(ValueError):
        n.validate_domain(bad)


# ---------------------------------------------------------------- run_command

PY = sys.executable


async def test_run_command_ok():
    r = await n.run_command([PY, "-c", "import sys; print('hi'); print('e', file=sys.stderr)"], timeout=30)
    assert r.returncode == 0
    assert r.stdout == b"hi\n"
    assert r.stderr == b"e\n"


async def test_run_command_no_shell_interpretation():
    r = await n.run_command([PY, "-c", "import sys; print(sys.argv[1])", "$(id); `id` | x"], timeout=30)
    assert r.stdout == b"$(id); `id` | x\n"


async def test_run_command_minimal_env(monkeypatch):
    monkeypatch.setenv("EMBERPOOL_SECRET", "leak")
    r = await n.run_command([PY, "-c", "import os; print(sorted(os.environ))"], timeout=30)
    assert b"EMBERPOOL_SECRET" not in r.stdout


async def test_run_command_stdin():
    r = await n.run_command([PY, "-c", "import sys; print(sys.stdin.read()[::-1])"], timeout=30, stdin=b"abc")
    assert r.stdout == b"cba\n"


async def test_run_command_nonzero_raises():
    with pytest.raises(n.CommandError) as e:
        await n.run_command([PY, "-c", "import sys; sys.exit(3)"], timeout=30)
    assert e.value.result.returncode == 3


async def test_run_command_nonzero_unchecked():
    r = await n.run_command([PY, "-c", "import sys; sys.exit(3)"], timeout=30, check=False)
    assert r.returncode == 3


async def test_run_command_timeout_kills():
    code = "import os, time; print(os.getpid(), flush=True); time.sleep(60)"
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    with pytest.raises(n.CommandTimeout):
        await n.run_command([PY, "-c", code], timeout=0.5)
    assert loop.time() - t0 < 10


async def test_run_command_cancel_kills(tmp_path):
    pidfile = tmp_path / "pid"
    code = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(60)"
    task = asyncio.create_task(n.run_command([PY, "-c", code], timeout=60))
    for _ in range(200):
        if pidfile.exists() and pidfile.read_text():
            break
        await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    import os

    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_run_command_caps_output():
    r = await n.run_command([PY, "-c", "import sys; sys.stdout.write('x' * 200000)"], timeout=30, max_output=1000)
    assert len(r.stdout) == 1000
    assert r.stdout_truncated


@pytest.mark.parametrize("argv", ["echo hi", b"echo", [], [""], ["echo", 1], ["echo", "a\x00b"]])
async def test_run_command_rejects_bad_argv(argv):
    with pytest.raises((TypeError, ValueError)):
        await n.run_command(argv, timeout=1)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
async def test_run_command_rejects_bad_timeout(timeout):
    with pytest.raises((TypeError, ValueError)):
        await n.run_command([PY, "-c", "pass"], timeout=timeout)
