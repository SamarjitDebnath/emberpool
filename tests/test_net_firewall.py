"""Detection of other firewalls that would drop forwarded sandbox traffic.

Pure unit tests on canned `nft -j list ruleset` output. The Docker cases are
shaped like real iptables-nft output.
"""

from __future__ import annotations

from typing import Any

import pytest

from emberpool.netpolicy import forward_block_message, forward_blockers

C = {"counter": {"packets": 0, "bytes": 0}}


def chain(name: str, *, family: str = "ip", table: str = "filter", hook: str | None = None,
          policy: str | None = None) -> dict[str, Any]:
    c: dict[str, Any] = {"family": family, "table": table, "name": name, "handle": 1}
    if hook:
        c.update(type="filter", hook=hook, prio=0, policy=policy or "accept")
    return {"chain": c}


def rule(chain_name: str, *expr: dict[str, Any], family: str = "ip", table: str = "filter") -> dict[str, Any]:
    return {"rule": {"family": family, "table": table, "chain": chain_name, "handle": 9, "expr": list(expr)}}


def ifmatch(key: str, value: str) -> dict[str, Any]:
    return {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": value}}


ACCEPT = {"accept": None}
DROP = {"drop": None}
CT_EST = {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}
XT_CONNTRACK = {"xt": {"type": "match", "name": "conntrack"}}


def docker(user_rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Docker's FORWARD layout with the given DOCKER-USER rules."""
    return {"nftables": [
        {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
        {"table": {"family": "ip", "name": "filter", "handle": 1}},
        chain("FORWARD", hook="forward", policy="drop"),
        chain("DOCKER-USER"),
        chain("DOCKER-FORWARD"),
        chain("DOCKER-CT"),
        rule("FORWARD", C, {"jump": {"target": "DOCKER-USER"}}),
        rule("FORWARD", C, {"jump": {"target": "DOCKER-FORWARD"}}),
        *[rule("DOCKER-USER", *r["expr"]) for r in user_rules],
        rule("DOCKER-FORWARD", C, {"jump": {"target": "DOCKER-CT"}}),
        rule("DOCKER-FORWARD", ifmatch("iifname", "docker0"), C, ACCEPT),
        rule("DOCKER-CT", ifmatch("oifname", "docker0"), CT_EST, C, ACCEPT),
    ]}


def u(*expr: dict[str, Any]) -> dict[str, Any]:
    return {"expr": list(expr)}


IN_OK = u(ifmatch("iifname", "ep-h*"), C, ACCEPT)
OUT_OK = u(ifmatch("oifname", "ep-h*"), C, ACCEPT)
RETURN = u(C, {"return": None})


def blockers(ruleset: dict[str, Any], prefix: str = "ep") -> list[str]:
    return forward_blockers(ruleset, prefix, "emberpool")


def test_empty_ruleset_is_fine() -> None:
    assert blockers({"nftables": [{"metainfo": {"json_schema_version": 1}}]}) == []


def test_accepting_forward_chain_is_fine() -> None:
    assert blockers({"nftables": [chain("FORWARD", hook="forward", policy="accept")]}) == []


def test_docker_default_is_a_blocker() -> None:
    assert blockers(docker([])) == ["ip filter FORWARD (policy drop)"]
    assert blockers(docker([RETURN])) == ["ip filter FORWARD (policy drop)"]


def test_docker_user_exemption_is_recognised() -> None:
    assert blockers(docker([IN_OK, OUT_OK, RETURN])) == []
    assert blockers(docker([OUT_OK, IN_OK])) == []


def test_native_ct_state_return_rule_is_recognised() -> None:
    out_est = u(ifmatch("oifname", "ep-h*"), CT_EST, C, ACCEPT)
    assert blockers(docker([IN_OK, out_est])) == []


def test_xt_conntrack_return_rule_is_not_trusted() -> None:
    # iptables -m conntrack shows up as an opaque xt match: stay strict.
    out_xt = u(ifmatch("oifname", "ep-h*"), XT_CONNTRACK, C, ACCEPT)
    assert blockers(docker([IN_OK, out_xt, RETURN])) != []


def test_partial_exemption_is_a_blocker() -> None:
    assert blockers(docker([IN_OK, RETURN])) != []
    assert blockers(docker([OUT_OK])) != []


def test_exemption_after_other_rules_is_a_blocker() -> None:
    other = u(ifmatch("iifname", "eth9"), C, DROP)
    assert blockers(docker([other, IN_OK, OUT_OK])) != []


def test_exemption_must_cover_the_prefix() -> None:
    narrow_in = u(ifmatch("iifname", "ep-h1*"), C, ACCEPT)
    narrow_out = u(ifmatch("oifname", "ep-h1*"), C, ACCEPT)
    assert blockers(docker([narrow_in, narrow_out])) != []
    exact = u(ifmatch("iifname", "ep-h1"), C, ACCEPT)
    assert blockers(docker([exact, OUT_OK])) != []
    # A broader pattern covers it; a test prefix needs its own coverage.
    assert blockers(docker([u(ifmatch("iifname", "ep*"), ACCEPT), u(ifmatch("oifname", "ep*"), ACCEPT)])) == []
    assert blockers(docker([IN_OK, OUT_OK]), prefix="ep-net") != []


def test_conditional_accept_with_extra_match_is_not_trusted() -> None:
    extra = u(ifmatch("iifname", "ep-h*"), {"match": {"op": "==", "left": {"payload": {
        "protocol": "tcp", "field": "dport"}}, "right": 443}}, ACCEPT)
    assert blockers(docker([extra, OUT_OK])) != []


def test_final_unconditional_drop_rule_is_a_blocker() -> None:
    rs = {"nftables": [
        chain("fwd", family="inet", table="fw", hook="forward", policy="accept"),
        rule("fwd", ifmatch("iifname", "eth0"), ACCEPT, family="inet", table="fw"),
        rule("fwd", C, DROP, family="inet", table="fw"),
    ]}
    assert blockers(rs) == ["inet fw fwd (final drop rule)"]
    rs["nftables"][-1] = rule("fwd", C, {"reject": None}, family="inet", table="fw")
    assert blockers(rs) == ["inet fw fwd (final drop rule)"]


def test_conditional_final_drop_is_not_a_blocker() -> None:
    rs = {"nftables": [
        chain("fwd", family="inet", table="fw", hook="forward", policy="accept"),
        rule("fwd", ifmatch("iifname", "eth0"), DROP, family="inet", table="fw"),
    ]}
    assert blockers(rs) == []


def test_ip6_and_other_hooks_are_ignored() -> None:
    rs = {"nftables": [
        chain("FORWARD", family="ip6", hook="forward", policy="drop"),
        chain("INPUT", hook="input", policy="drop"),
    ]}
    assert blockers(rs) == []


def test_own_table_is_ignored() -> None:
    rs = {"nftables": [chain("forward", family="inet", table="emberpool", hook="forward", policy="drop")]}
    assert blockers(rs) == []
    rs = {"nftables": [chain("forward", family="ip", table="emberpool", hook="forward", policy="drop")]}
    assert blockers(rs) != []  # same name, different family: not ours


def test_several_blockers_all_listed() -> None:
    rs = docker([])
    rs["nftables"].append(chain("f2", family="inet", table="other", hook="forward", policy="drop"))
    assert blockers(rs) == ["ip filter FORWARD (policy drop)", "inet other f2 (policy drop)"]


@pytest.mark.parametrize("bad", [[], {"x": 1}, {"nftables": "x"}, {"nftables": [1]},
                                 {"nftables": [{"rule": {"chain": "x", "expr": "nope"}}]}])
def test_malformed_input_raises(bad: object) -> None:
    with pytest.raises(ValueError):
        forward_blockers(bad, "ep", "emberpool")


def test_message_names_chain_and_fix() -> None:
    msg = forward_block_message(["ip filter FORWARD (policy drop)"], "ep")
    assert "ip filter FORWARD" in msg
    assert "iptables -I DOCKER-USER -i ep-h+ -j ACCEPT" in msg
    assert "iptables -I DOCKER-USER -o ep-h+ -j ACCEPT" in msg
