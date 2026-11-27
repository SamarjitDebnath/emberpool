"""The fakes satisfy the protocols and behave like the real lifecycle."""

from pathlib import Path

import pytest

from emberpool._types import ExecError, IsolationError, NetworkPolicy
from emberpool.engine import Engine, ExecClient, NetPolicy
from tests.fakes import FakeEngine, FakeExecClient, FakeNetPolicy


def test_fakes_implement_protocols():
    assert isinstance(FakeEngine(), Engine)
    assert isinstance(FakeNetPolicy(), NetPolicy)
    assert isinstance(FakeExecClient(), ExecClient)


async def test_lifecycle(tmp_path: Path):
    eng, net, ex = FakeEngine(changes=("/tmp/x",)), FakeNetPolicy(), FakeExecClient()
    async with net.template_netns() as ns:
        tmpl = await eng.build_template(tmp_path, ns)
    h = await net.setup("a3f1", 0, NetworkPolicy.parse("allow:pypi.org"))
    vm = await eng.restore(tmpl, "a3f1", h.netns)
    assert await eng.check_vmgenid(vm)
    r = await ex.run(vm.vsock_path, "print(1)", 5)
    assert r.exit_code == 0
    await eng.kill(vm)
    assert await eng.list_changes(vm) == ("/tmp/x",)
    await eng.cleanup(vm)
    await eng.cleanup(vm)  # idempotent
    await net.teardown(h)
    await net.teardown(h)
    assert eng.leaks() == [] and net.leaks() == []


async def test_failure_knobs(tmp_path: Path):
    eng = FakeEngine(fail_restore=1)
    tmpl = await eng.build_template(tmp_path, "ep-fake-tmpl")
    with pytest.raises(IsolationError):
        await eng.restore(tmpl, "a1", "ep-fake-a1")
    await eng.restore(tmpl, "a2", "ep-fake-a2")
    with pytest.raises(ExecError):
        await FakeExecClient(fail=True).run(Path("/x"), "", 1)
    with pytest.raises(TimeoutError):
        await FakeExecClient(delay=1).run(Path("/x"), "", 0.05)
    with pytest.raises(IsolationError):
        await FakeNetPolicy(fail_setup=True).setup("a1", 0, NetworkPolicy())
