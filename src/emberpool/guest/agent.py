#!/usr/bin/env python3
"""emberpool guest agent. Runs inside the microVM; standard library only.

Listens on AF_VSOCK port 1024 and serves one connection at a time:

    read one request frame -> run the code in a python3 subprocess
    -> write one response frame -> close

The wire format lives in _protocol.py next to this file, an exact copy of
emberpool/_protocol.py (a host test checks the copy is identical).

This agent is a convenience, not a control. Code it runs can kill it or make
it lie; the host enforces the wall-clock limit by killing the VM. The agent
still keeps its own limits so an honest run returns a well-formed reply:

- the subprocess is killed (whole process group) at the requested timeout;
- stdout and stderr are each capped at MAX_OUTPUT_BYTES of UTF-8;
- the subprocess gets a fixed environment and an empty working directory.

The listening socket survives snapshot restore. Restore resets the vsock
device, which can surface as errors from accept(); those are logged and the
loop carries on. If accepting keeps failing, the socket is re-created.

Readiness: the agent is ready once a vsock connection to port 1024 is
accepted. The host probes this with emberpool.exec_client.wait_ready, which
connects and closes without sending a frame. The agent also prints
"emberpool-agent: ready" on its stdout (the serial console) for debugging.
"""

from __future__ import annotations

import os
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _protocol as proto  # noqa: E402  (vendored copy, see module docstring)

PORT = 1024
PYTHON = "/usr/bin/python3"
# Bounds the wait for a request after accept, and for the reply to be sent.
IO_TIMEOUT = 30.0
# After the child exits (or is killed), how long to keep draining pipes that a
# leftover grandchild may hold open.
DRAIN_GRACE = 1.0
KILL_WAIT = 5.0
ACCEPT_BACKOFF = 0.05
MAX_ACCEPT_ERRORS = 50
TRUNCATED_MARK = "\n[emberpool: output truncated]\n"
CHILD_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
}

RunFn = Callable[[str, float], "tuple[str, str, int]"]


def log(msg: str) -> None:
    try:
        print(f"emberpool-agent: {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Running code
# --------------------------------------------------------------------------


def clip_output(data: bytes, truncated: bool = False, limit: int = proto.MAX_OUTPUT_BYTES) -> str:
    """Decode captured bytes and keep the result within `limit` bytes of UTF-8.

    Invalid UTF-8 becomes U+FFFD, which can grow the text, so the limit is
    checked after decoding."""
    text = data.decode("utf-8", "replace")
    encoded = text.encode("utf-8")
    if not truncated and len(encoded) <= limit:
        return text
    mark = TRUNCATED_MARK.encode("utf-8")
    keep = max(limit - len(mark), 0)
    return encoded[:keep].decode("utf-8", "ignore") + TRUNCATED_MARK


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if proc.poll() is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def _collect(
    proc: subprocess.Popen[bytes], timeout: float, cap: int
) -> tuple[bytes, bool, bytes, bool, bool]:
    """Read stdout and stderr until EOF, the timeout or the drain grace ends.
    Returns (out, out_truncated, err, err_truncated, timed_out)."""
    assert proc.stdout is not None and proc.stderr is not None
    streams = {proc.stdout.fileno(): 0, proc.stderr.fileno(): 1}
    bufs = [bytearray(), bytearray()]
    over = [False, False]
    timed_out = False
    deadline = time.monotonic() + timeout
    stop_at: float | None = None
    with selectors.DefaultSelector() as sel:
        for fd in streams:
            os.set_blocking(fd, False)
            sel.register(fd, selectors.EVENT_READ)
        while sel.get_map():
            now = time.monotonic()
            if stop_at is None:
                if proc.poll() is not None:
                    stop_at = now + DRAIN_GRACE
                elif now >= deadline:
                    timed_out = True
                    _kill_group(proc)
                    stop_at = now + DRAIN_GRACE
            if stop_at is not None and now >= stop_at:
                break
            limit_at = stop_at if stop_at is not None else deadline
            for key, _ in sel.select(min(max(limit_at - now, 0.0), 0.1)):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fd)
                    continue
                i = streams[key.fd]
                room = cap - len(bufs[i])
                if room > 0:
                    bufs[i] += chunk[:room]
                if len(chunk) > room:
                    over[i] = True  # keep draining so the child never blocks
    return bytes(bufs[0]), over[0], bytes(bufs[1]), over[1], timed_out


def run_code(code: str, timeout: float, python: str = PYTHON) -> tuple[str, str, int]:
    """Run `code` as a script in a fresh python3 process, in its own session and
    an empty temporary directory. Returns (stdout, stderr, exit_code); a
    negative exit code is the signal that ended the process."""
    workdir = tempfile.mkdtemp(prefix="ep-run-")
    try:
        script = os.path.join(workdir, "main.py")
        with open(script, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            proc = subprocess.Popen(
                [python, script],
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(CHILD_ENV),
                start_new_session=True,
            )
        except OSError as e:
            return "", f"emberpool agent: cannot start {python}: {e.strerror}\n", 127
        try:
            cap = proto.MAX_OUTPUT_BYTES
            out, out_over, err, err_over, timed_out = _collect(proc, timeout, cap)
        finally:
            _kill_group(proc)  # also reaps leftover background processes
            try:
                proc.wait(KILL_WAIT)
            except subprocess.TimeoutExpired:
                pass
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()
        note = f"\nemberpool agent: timed out after {timeout:g}s, killed\n" if timed_out else ""
        stderr = clip_output(err, err_over, cap - len(note.encode("utf-8"))) + note
        code_ = proc.returncode if proc.returncode is not None else -signal.SIGKILL
        return clip_output(out, out_over), stderr, code_
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Serving
# --------------------------------------------------------------------------


def handle_connection(conn: socket.socket, run: RunFn = run_code) -> bool:
    """Serve one request on an accepted connection. Returns True if a reply was
    sent. Bad or missing requests close the connection without a reply."""
    conn.settimeout(IO_TIMEOUT)
    try:
        payload = proto.recv_frame(conn)
    except proto.ProtocolError as e:
        if "got 0 of 4" not in str(e):  # a readiness probe closes without a frame
            log(f"bad request frame: {e}")
        return False
    except OSError as e:
        log(f"read failed: {e}")
        return False
    try:
        req = proto.decode_request(payload)
    except proto.ProtocolError as e:
        log(f"bad request: {e}")
        return False
    stdout, stderr, exit_code = run(req.code, req.timeout)
    try:
        reply = proto.encode_response(stdout, stderr, exit_code)
    except proto.ProtocolError as e:  # only if `run` broke its own limits
        log(f"cannot encode reply: {e}")
        reply = proto.encode_response("", f"emberpool agent: {e}\n", 1)
    try:
        conn.sendall(reply)
    except OSError as e:
        log(f"write failed: {e}")
        return False
    return True


def serve(
    listener: socket.socket,
    run: RunFn = run_code,
    stop: Callable[[], bool] = lambda: False,
) -> None:
    """Accept connections one at a time until `stop()` is true. Accept errors
    (for example after a snapshot restore resets the vsock device) are logged
    and retried. Raises OSError after MAX_ACCEPT_ERRORS errors in a row so the
    caller can re-create the listener."""
    errors = 0
    while not stop():
        try:
            conn, _ = listener.accept()
        except OSError as e:
            errors += 1
            log(f"accept failed ({errors}): {e}")
            if errors >= MAX_ACCEPT_ERRORS:
                raise
            time.sleep(ACCEPT_BACKOFF)
            continue
        errors = 0
        try:
            with conn:
                handle_connection(conn, run)
        except Exception as e:  # never let one connection kill the agent
            log(f"connection failed: {type(e).__name__}: {e}")


def make_listener(port: int = PORT) -> socket.socket:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        sock.bind((socket.VMADDR_CID_ANY, port))
        sock.listen(8)
    except BaseException:
        sock.close()
        raise
    return sock


def main() -> None:
    while True:
        try:
            listener = make_listener()
        except OSError as e:
            log(f"cannot listen on vsock port {PORT}: {e}")
            time.sleep(0.5)
            continue
        log("ready")
        try:
            serve(listener)
        except OSError as e:
            log(f"re-creating listener after: {e}")
        finally:
            listener.close()


if __name__ == "__main__":
    main()
