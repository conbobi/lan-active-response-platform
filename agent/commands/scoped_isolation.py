"""Preserve the host firewall when isolating an enrolled endpoint."""
import ipaddress
from pathlib import Path
import socket
from urllib.parse import urlsplit

from firewall_control import firewall_lock, take_containment_priority
from network_sources import CollectionError, run, run_json

TABLE = "larp_containment"


def _isolation_addresses(manager_url, peer):
    manager = urlsplit(manager_url)
    port = manager.port or 443
    addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(manager.hostname, port, type=socket.SOCK_STREAM)}
    if isinstance(peer, tuple):
        addresses.add(ipaddress.ip_address(peer[0]))
    if not addresses:
        raise CollectionError("Could not resolve Manager addresses for isolation")
    return port, addresses


def scoped_isolation(action, manager_url, peer):
    with firewall_lock():
        if Path("/tmp/isolated").exists():
            raise CollectionError("Legacy containment is active and requires local recovery")
        state = run_json("nft", "-j", "list", "tables")
        exists = any(entry.get("table", {}).get("family") == "inet" and
                     entry["table"]["name"] == TABLE for entry in state["nftables"])
        if action == "unisolate":
            if exists:
                run("nft", "delete", "table", "inet", TABLE)
            return {"status": "success", "message": "EDR containment removed"}
        if exists:
            return {"status": "success", "message": "EDR containment is already active"}
        take_containment_priority()
        port, addresses = _isolation_addresses(manager_url, peer)
        rules = [
            f"add table inet {TABLE}",
            f"add chain inet {TABLE} input {{ type filter hook input priority -150; policy drop; }}",
            f"add chain inet {TABLE} output {{ type filter hook output priority -150; policy drop; }}",
            f"add chain inet {TABLE} forward {{ type filter hook forward priority -150; policy drop; }}",
            f'add rule inet {TABLE} input iifname "lo" accept',
            f'add rule inet {TABLE} output oifname "lo" accept',
            f"add rule inet {TABLE} input icmpv6 type {{ nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept",
            f"add rule inet {TABLE} output icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept",
        ]
        for transport in ("udp", "tcp"):
            rules.extend((f"add rule inet {TABLE} output {transport} dport 53 accept",
                          f"add rule inet {TABLE} input {transport} sport 53 ct state established accept"))
        for address in sorted(addresses, key=str):
            family = "ip" if address.version == 4 else "ip6"
            rules.extend((f"add rule inet {TABLE} output {family} daddr {address} tcp dport {port} accept",
                          f"add rule inet {TABLE} input {family} saddr {address} tcp sport {port} ct state established accept"))
        run("nft", "-f", "-", input_data=("\n".join(rules) + "\n").encode())
        return {"status": "success", "message": "EDR containment applied"}
