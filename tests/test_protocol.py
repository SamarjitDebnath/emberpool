import asyncio
import json
import socket
import struct

import pytest

from emberpool import _protocol as p


def _payload(frame_bytes: bytes) -> bytes:
    (n,) = struct.unpack(">I", frame_bytes[:4])
    assert len(frame_bytes) == 4 + n
    return frame_bytes[4:]


def test_request_round_trip():
    f = p.encode_request("print('héllo\\n')\n", 10)
    assert json.loads(_payload(f)) == {"v": 1, "code": "print('héllo\\n')\n", "timeout": 10.0, "files": None}
    assert p.decode_request(_payload(f)) == p.Request("print('héllo\\n')\n", 10.0)


def test_response_round_trip():
    f = p.encode_response("a\nb\n", "\x00err", -9)
    assert p.decode_response(_payload(f)) == p.Response("a\nb\n", "\x00err", -9)


def test_request_files_absent_ok():
    assert p.decode_request(b'{"v":1,"code":"x","timeout":1}') == p.Request("x", 1.0)


def test_worst_case_response_fits_frame():
    worst = "\x01" * p.MAX_OUTPUT_BYTES
    f = p.encode_response(worst, worst, 0)
    assert len(f) - 4 <= p.MAX_FRAME


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\xff\xfe",
        b"not json",
        b"[]",
        b'"x"',
        b'{"v":1,"code":"x"}',
        b'{"v":2,"code":"x","timeout":1,"files":null}',
        b'{"v":true,"code":"x","timeout":1,"files":null}',
        b'{"v":"1","code":"x","timeout":1,"files":null}',
        b'{"v":1,"code":1,"timeout":1,"files":null}',
        b'{"v":1,"code":"x","timeout":"1","files":null}',
        b'{"v":1,"code":"x","timeout":true,"files":null}',
        b'{"v":1,"code":"x","timeout":0,"files":null}',
        b'{"v":1,"code":"x","timeout":-1,"files":null}',
        b'{"v":1,"code":"x","timeout":NaN,"files":null}',
        b'{"v":1,"code":"x","timeout":Infinity,"files":null}',
        b'{"v":1,"code":"x","timeout":1e9,"files":null}',
        b'{"v":1,"code":"x","timeout":1,"files":[]}',
        b'{"v":1,"code":"x","timeout":1,"files":null,"extra":1}',
        b'{"v":1,"code":"x","code":"y","timeout":1}',
        b'{"v":1,"code":"\\ud800","timeout":1}',
        b"[" * 100000 + b"]" * 100000,
    ],
)
def test_decode_request_rejects(payload):
    with pytest.raises(p.ProtocolError):
        p.decode_request(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"v":1,"stdout":"","stderr":""}',
        b'{"v":1,"stdout":"","stderr":"","exit_code":0,"x":1}',
        b'{"v":0,"stdout":"","stderr":"","exit_code":0}',
        b'{"v":1,"stdout":1,"stderr":"","exit_code":0}',
        b'{"v":1,"stdout":"","stderr":null,"exit_code":0}',
        b'{"v":1,"stdout":"","stderr":"","exit_code":1.0}',
        b'{"v":1,"stdout":"","stderr":"","exit_code":true}',
        b'{"v":1,"stdout":"","stderr":"","exit_code":99999999999}',
    ],
)
def test_decode_response_rejects(payload):
    with pytest.raises(p.ProtocolError):
        p.decode_response(payload)


def test_decode_response_rejects_oversized_output():
    big = json.dumps({"v": 1, "stdout": "x" * (p.MAX_OUTPUT_BYTES + 1), "stderr": "", "exit_code": 0})
    with pytest.raises(p.ProtocolError):
        p.decode_response(big.encode())


def test_encode_rejects_bad_values():
    with pytest.raises(p.ProtocolError):
        p.encode_request("x" * (p.MAX_CODE_BYTES + 1), 1)
    with pytest.raises(p.ProtocolError):
        p.encode_request("x", float("nan"))
    with pytest.raises(p.ProtocolError):
        p.encode_response("", "", True)


def test_parse_header():
    assert p.parse_header(struct.pack(">I", 5)) == 5
    with pytest.raises(p.ProtocolError):
        p.parse_header(b"\x00\x00\x00")
    with pytest.raises(p.ProtocolError):
        p.parse_header(struct.pack(">I", 0))
    with pytest.raises(p.ProtocolError):
        p.parse_header(struct.pack(">I", p.MAX_FRAME + 1))
    with pytest.raises(p.ProtocolError):
        p.parse_header(b"\xff\xff\xff\xff")
    with pytest.raises(p.ProtocolError):
        p.parse_header(struct.pack(">I", 100), max_size=99)


def test_frame_rejects_empty_and_oversized():
    with pytest.raises(p.ProtocolError):
        p.frame(b"")
    with pytest.raises(p.ProtocolError):
        p.frame(b"x" * 10, max_size=9)


def _reader(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


async def test_read_frame_async():
    f = p.encode_request("x", 1)
    assert p.decode_request(await p.read_frame(_reader(f + b"trailing"))) == p.Request("x", 1.0)


async def test_read_frame_short():
    f = p.encode_request("x", 1)
    with pytest.raises(p.ProtocolError, match="short read"):
        await p.read_frame(_reader(f[:-1]))
    with pytest.raises(p.ProtocolError, match="short read"):
        await p.read_frame(_reader(f[:2]))


async def test_read_frame_oversized_before_reading_body():
    r = _reader(struct.pack(">I", p.MAX_FRAME + 1))  # no body at all
    with pytest.raises(p.ProtocolError, match="too large"):
        await p.read_frame(r)


def test_recv_frame_sync():
    a, b = socket.socketpair()
    with a, b:
        b.settimeout(5)
        f = p.encode_response("out", "", 0)
        a.sendall(f[:3])
        a.sendall(f[3:])
        assert p.decode_response(p.recv_frame(b)) == p.Response("out", "", 0)
        a.sendall(struct.pack(">I", p.MAX_FRAME + 1))
        with pytest.raises(p.ProtocolError):
            p.recv_frame(b)


def test_recv_frame_short():
    a, b = socket.socketpair()
    with b:
        b.settimeout(5)
        a.sendall(p.encode_response("out", "", 0)[:-2])
        a.close()
        with pytest.raises(p.ProtocolError, match="short read"):
            p.recv_frame(b)


def test_protocol_module_is_standalone():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(p))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module and not node.module.startswith("emberpool"), node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("emberpool")
