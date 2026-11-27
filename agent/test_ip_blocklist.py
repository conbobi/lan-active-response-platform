"""Host IP blocking (nftables, table inet larp_blocklist).

Unit tests use an in-memory nft double. The live test (LARP_NFT_LIVE=1, root, own network
namespace — e.g. a throwaway container) applies real rules to a TEST-NET address only.
"""
import json
import os
import re
import subprocess
import uuid

import pytest

import ip_blocklist as ib
from network_sources import CollectionError

TARGET = "198.51.100.7"  # TEST-NET-2, never routed


class FakeNft:
    def __init__(self):
        self.table = False
        self.rules = []
        self.handle = 0
        self.calls = []

    def __call__(self, name, *args, input_data=None, **kwargs):
        self.calls.append((name, args))
        if name == "ip":
            return "[]"
        assert name == "nft"
        if args == ("-f", "-"):
            for line in input_data.decode().splitlines():
                if line.startswith("add table"):
                    self.table = True
                elif line.startswith("add rule"):
                    m = re.match(r'add rule inet larp_blocklist (\w+) (ip6?) (saddr|daddr) (\S+) counter( drop)? comment "([^"]+)"', line)
                    assert m, line
                    self.handle += 1
                    self.rules.append({"chain": m[1], "family": m[2], "field": m[3], "ip": m[4],
                                       "drop": bool(m[5]), "comment": m[6], "handle": self.handle, "packets": 0})
            return ""
        if args[:2] == ("-j", "list"):
            if not self.table:
                raise CollectionError("nft: Error: No such file or directory")
            return json.dumps({"nftables": [{"rule": {
                "family": "inet", "table": "larp_blocklist", "chain": r["chain"], "handle": r["handle"],
                "comment": r["comment"], "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": r["family"], "field": r["field"]}}, "right": r["ip"]}},
                    {"counter": {"packets": r["packets"], "bytes": r["packets"] * 84}},
                    *([{"drop": None}] if r["drop"] else [])]}} for r in self.rules]})
        if args[:2] == ("delete", "rule"):
            handle = int(args[-1])
            self.rules = [r for r in self.rules if r["handle"] != handle]
            return ""
        if args == ("list", "tables"):
            return "table inet larp_blocklist" if self.table else ""
        raise AssertionError(args)


def blocklist(nft, reachable=(True, True)):
    answers = iter(reachable)
    return ib.Blocklist(runner=nft, manager_url="wss://manager.invalid/ws/agent",
                        probe=lambda: {"reachable": next(answers, reachable[-1]), "endpoint": "manager.invalid:443"})


def new_id():
    return uuid.uuid4().hex


def test_block_adds_owned_rules_on_both_directions_and_verifies_them():
    nft, block_id = FakeNft(), new_id()
    receipt = blocklist(nft).block(block_id, TARGET)
    assert receipt["status"] == "success" and receipt["outcome"] == "applied" and receipt["rule_verified"]
    assert receipt["chains"] == ["input", "output"] and receipt["backend"] == "nftables"
    assert {r["comment"] for r in nft.rules} == {f"larp-block:{block_id}"}
    # Never touches anything but its own table.
    assert all(a[0] in ("-f", "-j", "delete") or a == ("list", "tables") for n, a in nft.calls if n == "nft")


def test_replayed_block_does_not_duplicate_rules():
    nft, block_id = FakeNft(), new_id()
    bl = blocklist(nft)
    bl.block(block_id, TARGET)
    again = bl.block(block_id, TARGET)
    assert again["outcome"] == "already_applied" and len(nft.rules) == 2


def test_unblock_removes_only_its_own_rules_and_reports_other_blocks():
    nft, first, second, unblock_id = FakeNft(), new_id(), new_id(), new_id()
    bl = blocklist(nft)
    bl.block(first, TARGET)
    bl.block(second, TARGET)
    result = bl.unblock(first, unblock_id, TARGET)
    assert result["status"] == "success" and result["removed_rules"] == 2
    assert result["other_larp_blocks"] == [second]
    assert result["verification_counter"] is None  # still blocked by another policy: no restore claim
    assert {r["comment"] for r in nft.rules} == {f"larp-block:{second}"}


def test_unblock_adds_a_bounded_verification_counter_and_status_expires_it(monkeypatch):
    nft, block_id, unblock_id = FakeNft(), new_id(), new_id()
    bl = blocklist(nft)
    bl.block(block_id, TARGET)
    result = bl.unblock(block_id, unblock_id, TARGET, verify_seconds=60)
    assert result["rule_absent_verified"] and result["verification_counter"]["deadline"]
    verify, = nft.rules
    assert verify["comment"].startswith(f"larp-verify:{unblock_id}:") and not verify["drop"]
    verify["packets"] = 3
    state = bl.status()
    assert state["verifications"][unblock_id]["packets"] == 3 and not state["verifications"][unblock_id]["expired"]
    monkeypatch.setattr(ib.time, "time", lambda: result["verification_counter"]["deadline"] + 1)
    assert bl.status()["verifications"][unblock_id]["expired"] and nft.rules == []
    assert bl.unblock(block_id, new_id(), TARGET)["outcome"] == "already_removed"


def test_management_loss_after_block_rolls_back():
    nft = FakeNft()
    receipt = blocklist(nft, reachable=(True, False)).block(new_id(), TARGET)
    assert receipt["code"] == "CONNECTIVITY_GUARD_ROLLBACK" and receipt["rolled_back"] and nft.rules == []


def test_unverifiable_management_path_refuses_to_block():
    nft = FakeNft()
    receipt = blocklist(nft, reachable=(False,)).block(new_id(), TARGET)
    assert receipt["code"] == "MANAGEMENT_UNVERIFIED" and nft.rules == []


@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.1.1", "100.100.100.100"])
def test_protected_targets_are_refused(target, monkeypatch):
    nft = FakeNft()
    receipt = blocklist(nft).block(new_id(), target)
    assert receipt["code"] == "PROTECTED_TARGET" and nft.rules == []


def test_protected_cidr_and_session_peers(monkeypatch):
    monkeypatch.setenv("LARP_PROTECTED_CIDRS", "100.113.42.95/32")
    nft = FakeNft()
    assert blocklist(nft).block(new_id(), "100.113.42.95")["code"] == "PROTECTED_TARGET"
    monkeypatch.setattr(ib.Blocklist, "protected", lambda self: {"203.0.113.9": "phiên SSH quản trị đang mở"})
    assert "SSH" in blocklist(nft).block(new_id(), "203.0.113.9")["message"]
    # A specific Tailscale peer is not protected just for being in 100.64.0.0/10.
    assert blocklist(nft).block(new_id(), "100.67.222.3")["status"] == "success"


def test_invalid_targets():
    with pytest.raises(CollectionError):
        blocklist(FakeNft()).block(new_id(), "10.0.0.0/8")
    with pytest.raises(CollectionError):
        blocklist(FakeNft()).block("not-an-id", TARGET)


@pytest.mark.skipif(os.getenv("LARP_NFT_LIVE") != "1" or os.geteuid() != 0, reason="needs root in a disposable netns")
def test_live_nftables_block_counts_dropped_packets_and_unblock_restores():
    bl = ib.Blocklist(manager_url="wss://manager.invalid/ws/agent", probe=lambda: {"reachable": True})
    block_id, unblock_id = new_id(), new_id()
    receipt = bl.block(block_id, TARGET)
    assert receipt["status"] == "success" and receipt["rule_verified"], receipt
    subprocess.run(["ping", "-c", "2", "-W", "1", TARGET], capture_output=True)
    state = bl.status()
    assert state["blocks"][block_id]["complete"] and state["blocks"][block_id]["packets"] >= 2  # drops observed
    result = bl.unblock(block_id, unblock_id, TARGET)
    assert result["rule_absent_verified"] and block_id not in bl.status()["blocks"]
    listing = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True).stdout
    assert f"larp-block:{block_id}" not in listing and f"larp-verify:{unblock_id}" in listing
