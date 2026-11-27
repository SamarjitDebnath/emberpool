"""The guest agent vendors an exact copy of the frozen wire protocol."""

from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "emberpool"


def test_vendored_protocol_is_identical():
    original = (SRC / "_protocol.py").read_bytes()
    copy = (SRC / "guest" / "_protocol.py").read_bytes()
    assert copy == original, "src/emberpool/guest/_protocol.py differs; re-copy _protocol.py"
