import json

import pytest

from emberpool._types import (
    GUEST_IP,
    TAP_HOST_CIDR,
    TAP_MAC,
    TAP_NAME,
    VSOCK_PORT,
    ConnEvent,
    DnsEvent,
    NetHandle,
    NetworkPolicy,
    Trace,
    VMHandle,
    uplink_host_ip,
    uplink_ns_ip,
    uplink_subnet,
)


def test_constants():
    assert TAP_NAME == "tap0"
    assert TAP_MAC == "02:ee:00:00:00:01"
    assert TAP_HOST_CIDR == "172.16.0.1/30"
    assert GUEST_IP == "172.16.0.2"
    assert VSOCK_PORT == 1024


def test_uplink():
    assert str(uplink_subnet(7)) == "10.200.7.0/30"
    assert uplink_host_ip(7) == "10.200.7.1"
    assert uplink_ns_ip(255) == "10.200.255.2"
    for bad in (-1, 256, True, "1", 1.0):
        with pytest.raises(ValueError):
            uplink_subnet(bad)


# ---------------------------------------------------------------- NetworkPolicy


def test_policy_default_deny():
    assert NetworkPolicy().is_deny
    assert NetworkPolicy.parse().is_deny
    assert NetworkPolicy.parse("deny") == NetworkPolicy()
    assert str(NetworkPolicy()) == "deny"


def test_policy_allow():
    p = NetworkPolicy.parse("allow:PyPI.org, files.pythonhosted.org,pypi.org")
    assert p.allow == ("pypi.org", "files.pythonhosted.org")
    assert not p.is_deny
    assert str(p) == "allow:pypi.org,files.pythonhosted.org"
    assert NetworkPolicy.parse(str(p)) == p


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "Deny",
        "allow",
        "allow:",
        "allow:,",
        "allow:pypi.org,",
        "allow:pypi.org,,x.com",
        "allow:*",
        "allow:*.pypi.org",
        "allow:1.2.3.4",
        "allow:localhost",
        "allow:pypi.org;rm",
        "allow:pypi.org evil.com",
        "deny:pypi.org",
        "allow pypi.org",
        None,
        ["pypi.org"],
    ],
)
def test_policy_rejects(bad):
    with pytest.raises(ValueError):
        NetworkPolicy.parse(bad)


def test_policy_direct_construction_validates():
    assert NetworkPolicy(("PYPI.org",)).allow == ("pypi.org",)
    with pytest.raises(ValueError):
        NetworkPolicy(("bad name",))
    with pytest.raises(ValueError):
        NetworkPolicy(("a.com", "A.com"))
    with pytest.raises(TypeError):
        NetworkPolicy(["a.com"])


# ---------------------------------------------------------------- events + trace


def _events():
    return (
        DnsEvent(1.0, "a3f1", "pypi.org", ("151.101.0.223", "2a04:4e42::223")),
        DnsEvent(1.5, "a3f1", "evil.example", None),
        ConnEvent(2.0, "a3f1", "151.101.0.223", 443, "tcp", "pypi.org", "allowed"),
        ConnEvent(3.0, "a3f1", "8.8.8.8", 53, "udp", None, "dropped"),
    )


def test_trace_round_trip():
    t = Trace(events=_events())
    text = t.to_json()
    assert Trace.from_json(text) == t
    assert Trace.from_json(text.encode()) == t
    data = json.loads(text)
    assert data["schema_version"] == 1
    assert data["events"][1] == {
        "type": "dns",
        "time": 1.5,
        "vm_id": "a3f1",
        "name": "evil.example",
        "rcode": "NXDOMAIN",
        "answers": [],
    }
    assert data["events"][2]["verdict"] == "allowed"
    assert list(t) == list(_events())
    assert len(t) == 4


def test_trace_empty_round_trip():
    assert Trace.from_json(Trace().to_json()) == Trace()


def test_trace_noerror_empty_answers_is_not_nxdomain():
    t = Trace(events=(DnsEvent(1, "a3f1", "pypi.org", ()),))
    back = Trace.from_json(t.to_json())
    assert back.events[0].answers == ()


def test_trace_ignores_unknown_event_fields():
    data = json.loads(Trace(events=_events()).to_json())
    data["events"][0]["future_field"] = 1
    assert Trace.from_json(json.dumps(data)) == Trace(events=_events())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema_version=2),
        lambda d: d.update(schema_version=True),
        lambda d: d.pop("schema_version"),
        lambda d: d.update(events={}),
        lambda d: d["events"][0].update(type="http"),
        lambda d: d["events"][0].update(rcode="SERVFAIL"),
        lambda d: d["events"][1].update(answers=["1.2.3.4"]),
        lambda d: d["events"][0].update(answers=["not-an-ip"]),
        lambda d: d["events"][0].update(vm_id="../x"),
        lambda d: d["events"][0].update(name="has space"),
        lambda d: d["events"][0].pop("time"),
        lambda d: d["events"][2].update(dst_port=70000),
        lambda d: d["events"][2].update(dst_port=True),
        lambda d: d["events"][2].update(verdict="maybe"),
        lambda d: d["events"][2].update(protocol="TCP; drop"),
        lambda d: d["events"][2].update(time=-1),
    ],
)
def test_trace_from_json_rejects(mutate):
    data = json.loads(Trace(events=_events()).to_json())
    mutate(data)
    with pytest.raises((ValueError, TypeError)):
        Trace.from_json(json.dumps(data))


def test_trace_rejects_nan():
    with pytest.raises(ValueError):
        Trace.from_json('{"schema_version":1,"events":[{"type":"dns","time":NaN,"vm_id":"a","name":"a.b","rcode":"NOERROR","answers":[]}]}')


def test_events_normalise_ips():
    e = ConnEvent(1, "a3f1", "2A04:4E42:0::223", 443, "tcp", "PyPI.org", "allowed")
    assert e.dst_ip == "2a04:4e42::223"
    assert e.name == "pypi.org"


def test_dns_event_rejects_raw_guest_names():
    for bad in ("", "a b", "a\x00b", "ü.com", "x" * 1025):
        with pytest.raises(ValueError):
            DnsEvent(1, "a3f1", bad, None)
    DnsEvent(1, "a3f1", "weird_\\x00name", None)  # escaped form is fine


def test_handles_validate_names(tmp_path):
    VMHandle("a3f1", 1, tmp_path / "v.sock", tmp_path / "s.ext4", "ep-a3f1")
    with pytest.raises(ValueError):
        VMHandle("a3f1", 1, tmp_path / "v.sock", tmp_path / "s.ext4", "a3f1; reboot")
    NetHandle("a3f1", 3, "ep-a3f1", "ep-h3")
    with pytest.raises(ValueError):
        NetHandle("a3f1", 3, "ep-a3f1", "eth0")
    with pytest.raises(ValueError):
        NetHandle("a3f1", 999, "ep-a3f1", "ep-h3")
