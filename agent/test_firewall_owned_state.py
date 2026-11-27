"""UFW preflight on a host that also runs Tailscale and LARP's blocklist (ruleset captured from the lab VPS)."""
import copy
import json
from pathlib import Path

import pytest

import firewall_control as control
from network_sources import CollectionError

RULESET = json.loads((Path(__file__).parent / "testdata" / "vps_nft_ruleset_tailscale.json").read_text())


def scope(monkeypatch, ruleset, **kwargs):
    def run(name, *args, **kw):
        return "iptables v1.8.11 (nf_tables)" if args == ("-V",) else ""
    monkeypatch.setattr(control, "run", run)
    monkeypatch.setattr(control, "run_json", lambda *a: ruleset)
    monkeypatch.setattr(control.Path, "exists", lambda self: False if str(self) == "/tmp/isolated" else Path.exists(self))
    return control._kernel_scope(**kwargs)


def with_entries(*extra):
    data = copy.deepcopy(RULESET)
    data["nftables"].extend(extra)
    return data


def test_lab_vps_ruleset_with_tailscale_and_larp_blocklist_passes(monkeypatch):
    assert scope(monkeypatch, RULESET, active=False)


@pytest.mark.parametrize("entry,error", [
    ({"chain": {"family": "ip", "table": "filter", "name": "evil", "handle": 99}}, "Independent filter chains"),
    ({"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 98,
               "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                        {"drop": None}]}}, "Independent filtering rules"),
    ({"rule": {"family": "ip", "table": "mangle", "chain": "PREROUTING", "handle": 97, "expr": [{"drop": None}]}},
     "mangle rules can filter"),
    ({"chain": {"family": "ip", "table": "filter", "name": "ts-evil", "handle": 96, "type": "filter",
                "hook": "input", "prio": 0, "policy": "drop"}}, "Tailscale chain is unexpectedly hooked"),
    ({"chain": {"family": "inet", "table": "larp_blocklist", "name": "input", "handle": 95, "type": "filter",
                "hook": "input", "prio": -160, "policy": "drop"}}, "accept policy"),
    ({"table": {"family": "inet", "name": "someone_else", "handle": 94}}, "Independent firewall policy"),
])
def test_unknown_or_unsafe_state_is_still_refused(monkeypatch, entry, error):
    with pytest.raises(CollectionError, match=error):
        scope(monkeypatch, with_entries(entry), active=False)


def test_tailscale_jump_before_ufw_does_not_break_the_ordering_check(monkeypatch):
    extra = []
    for family, prefix in (("ip", "ufw"), ("ip6", "ufw6")):
        for direction in ("input", "output"):
            for index, name in enumerate((f"{prefix}-before-logging-{direction}", f"{prefix}-before-{direction}")):
                extra.append({"chain": {"family": family, "table": "filter", "name": name, "handle": 200 + index}})
                extra.append({"rule": {"family": family, "table": "filter", "chain": direction.upper(), "handle": 300 + index,
                                       "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": name}}]}})
    assert scope(monkeypatch, with_entries(*extra), active=True)


def test_tailscale_changes_are_not_counted_as_drift():
    changed = copy.deepcopy(RULESET)
    for entry in changed["nftables"]:
        rule = entry.get("rule")
        if rule and rule.get("chain") == "ts-input":
            rule["expr"] = [{"accept": None}]
    assert control._kernel_fingerprint(RULESET["nftables"]) == control._kernel_fingerprint(changed["nftables"])
