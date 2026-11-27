"""Network tab: connection direction from listening sockets, and evidence-based access anomalies."""
from datetime import datetime, timedelta, timezone

import pytest

from app.models.auth_event import AuthEvent
from app.models.flow import Flow
from app.services.agent.network_service import annotate_directions
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

PORTS = [{"protocol": "TCP", "status": "LISTEN", "family": "IPv4", "src_ip": "0.0.0.0", "src_port": 22, "process_name": "sshd"},
         {"protocol": "TCP", "status": "LISTEN", "family": "IPv4", "src_ip": "0.0.0.0", "src_port": 5000, "process_name": "python"}]


def row(src_port, dst_ip, dst_port, process, status="ESTAB"):
    return {"protocol": "TCP", "family": "IPv4", "src_ip": "172.31.32.238", "src_port": src_port, "dst_ip": dst_ip,
            "dst_port": dst_port, "status": status, "direction": "unknown", "process_name": process}


def test_directions_come_from_listening_sockets_and_management_is_marked():
    rows = annotate_directions([
        row(22, "171.239.227.85", 45046, "unknown"),          # SSH session into the host
        row(40986, "100.67.222.3", 4444, "python3"),           # reverse shell dialling out
        row(39982, "192.200.0.106", 80, "tailscaled"),          # Tailscale control plane
        row(37120, "172.67.204.217", 443, "python"),            # Agent → Manager (Cloudflare)
        {**row(1, "10.0.0.1", 9, "x", status="UNCONN"), "protocol": "UDP"},
    ], PORTS)
    assert [(r["direction"], r.get("service")) for r in rows[:4]] == [
        ("inbound", "sshd"), ("outbound", None), ("outbound", None), ("outbound", None)]
    assert rows[2]["management_channel"] is True and rows[1]["management_channel"] is False
    assert rows[4]["direction"] == "unknown"  # never guessed without evidence
    assert annotate_directions([row(40986, "100.67.222.3", 4444, "python3")], [])[0]["direction"] == "unknown"


@pytest.mark.asyncio
async def test_access_anomalies_use_successful_logins_and_verified_control_channels(lab):
    client, factory = lab
    now = datetime.now(timezone.utc)
    async with factory.begin() as db:
        for n, (ip, user, status) in enumerate([("100.113.42.95", "admin", "success"), ("100.67.222.3", "admin", "success"),
                                                ("100.67.222.3", "admin", "failed"), ("100.67.222.3", "unknown", "success"),
                                                ("171.239.227.85", "deploy", "success")]):
            db.add(AuthEvent(id=f"auth_{n}", agent_id=AGENT, service="flask_web" if user != "deploy" else "ssh",
                             source_ip=ip, username=user, status=status, count=1, timestamp=now - timedelta(minutes=n)))
        holder = {"pid": 198919, "process_name": "python3", "cmdline": "python3 /tmp/uploads/backdoor.py", "euid": 0,
                  "socket_stdio": True}
        for fid, ip, port, evidence in [
            ("f1", "100.67.222.3", 4444, {"direction": "outbound", "attribution": "inode_verified", "holders": [holder]}),
            ("f2", "192.200.0.106", 80, {"direction": "outbound", "attribution": "inode_verified",
                                         "holders": [{**holder, "pid": 648, "process_name": "tailscaled", "socket_stdio": False}]}),
            ("f3", "198.51.100.9", 4444, {"direction": "outbound", "attribution": "unverified_socket", "holders": [holder]}),
        ]:
            db.add(Flow(id=fid, agent_id=AGENT, src_ip="100.112.146.63", src_port=40000, dst_ip=ip, dst_port=port,
                        protocol="TCP", start_time=now, end_time=now, created_at=now, socket_evidence=evidence))
    assert client.get(f"/api/v1/network/agents/{AGENT}/access-anomalies").status_code == 401
    data = client.get(f"/api/v1/network/agents/{AGENT}/access-anomalies", headers=ANALYST).json()
    account, = data["shared_account_logins"]  # failed and anonymous logins are not counted
    assert account["account"] == "admin" and {i["ip"] for i in account["ips"]} == {"100.113.42.95", "100.67.222.3"}
    channel, = data["control_channels"]  # only verified, stdio-bound, outbound sockets
    assert channel["remote_ip"] == "100.67.222.3" and channel["remote_port"] == 4444 and channel["euid"] == 0
