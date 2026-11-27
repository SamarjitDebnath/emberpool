"""Shared pytest setup.

Tests marked `vm` need Linux, root and /dev/kvm; they are skipped elsewhere.
Every resource a test creates is named with `test_prefix`, taken from
$EMBERPOOL_TEST_PREFIX (default "ep-test"), so parallel sessions on one host
never touch each other's resources.
"""

from __future__ import annotations

import os
import sys

import pytest

from emberpool._names import validate_netns


def _vm_unavailable() -> str | None:
    if not sys.platform.startswith("linux"):
        return "needs Linux"
    if not os.path.exists("/dev/kvm"):
        return "needs /dev/kvm"
    if os.geteuid() != 0:
        return "needs root"
    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    reason = _vm_unavailable()
    if reason is None:
        return
    skip = pytest.mark.skip(reason=f"vm test: {reason}")
    for item in items:
        if "vm" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def test_prefix() -> str:
    """Prefix for every namespace, interface, table, socket and temp dir a test creates."""
    prefix = os.environ.get("EMBERPOOL_TEST_PREFIX", "ep-test")
    validate_netns(prefix)  # starts with "ep", lowercase, short
    if len(prefix) > 8:
        raise pytest.UsageError("EMBERPOOL_TEST_PREFIX must be at most 8 chars (interface names cap at 15)")
    return prefix
