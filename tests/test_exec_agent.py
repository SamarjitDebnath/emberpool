"""Guest agent unit tests. They run the agent's functions on the host, with
python3 replaced by this interpreter and socketpairs in place of vsock."""

from __future__ import annotations

import importlib.util
import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from types import ModuleType

import pytest

AGENT_PATH = Path(__file__).resolve().parent.parent / "src" / "emberpool" / "guest" / "agent.py"


def _load_agent() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ep_guest_agent", AGENT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


agent = _load_agent()
proto = agent.proto


def run(code: str, timeout: float = 10.0) -> tuple[str, str, int]:
    return agent.run_code(code, timeout, python=sys.executable)


def _payload(frame: bytes) -> bytes:
    (n,) = struct.unpack(">I", frame[:4])
    return frame[4 : 4 + n]


# --------------------------------------------------------------------------
# run_code
# --------------------------------------------------------------------------


def test_agent_uses_stdlib_only():
    allowed_local = {"_protocol"}
    text = AGENT_PATH.read_text()
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(("import ", "from ")) and not s.startswith("from __future__"):
            mod = s.split()[1].split(".")[0]
            assert mod in sys.stdlib_module_names or mod in allowed_local, s


def test_run_print():
    assert run("print(1 + 1)") == ("2\n", "", 0)


def test_run_exit_code_and_stderr():
    out, err, rc = run("import sys\nprint('x')\nsys.stderr.write('bad\\n')\nsys.exit(3)")
    assert (out, err, rc) == ("x\n", "bad\n", 3)


def test_run_exception_traceback():
    out, err, rc = run("raise ValueError('boom')")
    assert rc == 1 and "ValueError: boom" in err


def test_run_unicode_and_newlines():
    out, _, rc = run("print('héllo\\nwörld')")
    assert rc == 0 and out == "héllo\nwörld\n"


def test_run_fixed_env_and_empty_cwd(monkeypatch):
    monkeypatch.setenv("EP_SECRET_FROM_HOST", "leak")
    out, _, rc = run("import os, json\nprint(json.dumps([sorted(os.environ), os.listdir('.')]))")
    env_keys, files = json.loads(out)
    assert rc == 0
    assert "EP_SECRET_FROM_HOST" not in env_keys
    assert files == ["main.py"]


def test_run_cleans_workdir():
    out, _, _ = run("import os\nprint(os.getcwd())")
    assert not Path(out.strip()).exists()


def test_run_timeout_kills_process_group():
    code = "import subprocess, time\nsubprocess.Popen(['sleep', '30'])\nprint('started', flush=True)\ntime.sleep(30)"
    t0 = time.monotonic()
    out, err, rc = run(code, timeout=1.0)
    assert time.monotonic() - t0 < 6
    assert out == "started\n"
    assert rc == -9
    assert "timed out after 1s" in err


def test_run_background_child_holding_pipe_is_bounded():
    # The main process exits but leaves a child holding stdout open.
    code = "import subprocess\nsubprocess.Popen(['sleep', '30'])\nprint('done')"
    t0 = time.monotonic()
    out, _, rc = run(code, timeout=20)
    assert time.monotonic() - t0 < agent.DRAIN_GRACE + 4
    assert (out, rc) == ("done\n", 0)


def test_run_output_capped():
    out, _, rc = run(f"import sys\nsys.stdout.write('a' * {proto.MAX_OUTPUT_BYTES * 2})")
    assert rc == 0
    assert len(out.encode()) <= proto.MAX_OUTPUT_BYTES
    assert out.endswith(agent.TRUNCATED_MARK)


def test_run_invalid_utf8_stays_within_cap():
    out, _, rc = run(f"import sys\nsys.stdout.buffer.write(b'\\xff' * {proto.MAX_OUTPUT_BYTES})")
    assert rc == 0
    assert len(out.encode()) <= proto.MAX_OUTPUT_BYTES
    assert out.startswith("�")
    proto.encode_response(out, "", rc)  # always fits a frame


def test_run_missing_interpreter():
    out, err, rc = agent.run_code("print(1)", 5, python="/nonexistent/python3")
    assert (out, rc) == ("", 127) and "cannot start" in err


def test_clip_output_short_and_long():
    assert agent.clip_output(b"hi") == "hi"
    clipped = agent.clip_output("é".encode() * 100, limit=50)
    assert len(clipped.encode()) <= 50 and clipped.endswith(agent.TRUNCATED_MARK)


# --------------------------------------------------------------------------
# handle_connection over a socketpair
# --------------------------------------------------------------------------


def _fake_run(code: str, timeout: float) -> tuple[str, str, int]:
    return f"ran {code}\n", "", 0


def _serve_one(raw: bytes, run_fn=_fake_run) -> tuple[bool, bytes]:
    host, guest = socket.socketpair()
    with host, guest:
        host.sendall(raw)
        host.shutdown(socket.SHUT_WR)
        sent = agent.handle_connection(guest, run_fn)
        guest.close()
        host.settimeout(5)
        reply = b""
        while chunk := host.recv(65536):
            reply += chunk
    return sent, reply


def test_handle_good_request():
    sent, reply = _serve_one(proto.encode_request("x", 5))
    assert sent
    assert proto.decode_response(_payload(reply)) == proto.Response("ran x\n", "", 0)


def test_handle_passes_timeout():
    seen = []
    _serve_one(proto.encode_request("x", 2.5), lambda c, t: (seen.append(t), ("", "", 0))[1])
    assert seen == [2.5]


@pytest.mark.parametrize(
    "raw",
    [
        b"",  # readiness probe: connect, then close
        b"\x00\x00",  # short header
        struct.pack(">I", proto.MAX_FRAME + 1),  # oversized
        struct.pack(">I", 0),  # empty frame
        struct.pack(">I", 10) + b"abc",  # short payload
        proto.frame(b"not json"),
        proto.frame(b'{"v":2,"code":"x","timeout":1}'),
        proto.frame(b'{"v":1,"code":"x","timeout":1,"files":[]}'),
        proto.frame(b'{"v":1,"code":"x","timeout":-1}'),
    ],
)
def test_handle_bad_request_closes_without_reply(raw):
    def must_not_run(code, timeout):
        raise AssertionError("ran code from a bad request")

    sent, reply = _serve_one(raw, must_not_run)
    assert (sent, reply) == (False, b"")


def test_handle_peer_gone_before_reply():
    host, guest = socket.socketpair()
    with guest:
        host.sendall(proto.encode_request("x", 5))
        host.close()
        # The reply write may fail; it must not raise.
        agent.handle_connection(guest, _fake_run)


def test_handle_run_breaking_limits_still_replies():
    big = "a" * (proto.MAX_OUTPUT_BYTES + 1)
    sent, reply = _serve_one(proto.encode_request("x", 5), lambda c, t: (big, "", 0))
    assert sent
    resp = proto.decode_response(_payload(reply))
    assert resp.exit_code == 1 and resp.stdout == ""


# --------------------------------------------------------------------------
# serve loop
# --------------------------------------------------------------------------


class _FlakyListener:
    """accept() fails `fail` times, then hands out the given connections."""

    def __init__(self, fail: int, conns: list[socket.socket]):
        self.fail = fail
        self.conns = conns
        self.accepts = 0

    def accept(self):
        self.accepts += 1
        if self.fail:
            self.fail -= 1
            raise ConnectionResetError("vsock transport reset")
        return self.conns.pop(0), None


def test_serve_survives_accept_errors(monkeypatch):
    monkeypatch.setattr(agent, "ACCEPT_BACKOFF", 0)
    host, guest = socket.socketpair()
    listener = _FlakyListener(fail=3, conns=[guest])
    with host:
        host.sendall(proto.encode_request("x", 5))
        agent.serve(listener, _fake_run, stop=lambda: not listener.conns)
        host.settimeout(5)
        reply = host.recv(65536)
    assert listener.accepts == 4
    assert proto.decode_response(_payload(reply)).stdout == "ran x\n"
    assert guest.fileno() == -1  # connection closed after serving


def test_serve_survives_crashing_handler(monkeypatch):
    def boom(code, timeout):
        raise RuntimeError("handler bug")

    a1, g1 = socket.socketpair()
    a2, g2 = socket.socketpair()
    listener = _FlakyListener(fail=0, conns=[g1, g2])
    with a1, a2:
        a1.sendall(proto.encode_request("x", 5))
        a2.sendall(proto.encode_request("x", 5))
        calls = []

        def run_fn(code, timeout):
            calls.append(code)
            if len(calls) == 1:
                boom(code, timeout)
            return _fake_run(code, timeout)

        agent.serve(listener, run_fn, stop=lambda: not listener.conns)
        a2.settimeout(5)
        assert proto.decode_response(_payload(a2.recv(65536))).exit_code == 0
    assert len(calls) == 2


def test_serve_gives_up_after_repeated_errors(monkeypatch):
    monkeypatch.setattr(agent, "ACCEPT_BACKOFF", 0)
    listener = _FlakyListener(fail=10**6, conns=[])
    with pytest.raises(OSError):
        agent.serve(listener, _fake_run)
    assert listener.accepts == agent.MAX_ACCEPT_ERRORS


def test_serve_one_at_a_time_with_real_listener(test_prefix):
    # A Unix listener stands in for vsock: two sequential clients both served.
    import tempfile

    d = Path(tempfile.mkdtemp(prefix=f"{test_prefix}-", dir="/tmp"))
    path = str(d / "agent.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(path)
        listener.listen(8)
        served = []

        def run_fn(code, timeout):
            served.append(code)
            return _fake_run(code, timeout)

        t = threading.Thread(target=agent.serve, args=(listener, run_fn, lambda: len(served) >= 2), daemon=True)
        t.start()
        for code in ("a", "b"):
            with socket.socket(socket.AF_UNIX) as c:
                c.settimeout(5)
                c.connect(path)
                c.sendall(proto.encode_request(code, 5))
                assert proto.decode_response(_payload(c.recv(65536))).stdout == f"ran {code}\n"
        t.join(5)
        assert not t.is_alive()
    finally:
        listener.close()
        import shutil

        shutil.rmtree(d, ignore_errors=True)
