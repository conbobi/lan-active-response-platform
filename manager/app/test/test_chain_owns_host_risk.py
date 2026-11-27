"""The host risk score must not open a second incident for processes a web compromise chain already explains.

Real case (27/11/2026 21:00): `GET /ping?ip=127.0.0.1;python3 /tmp/uploads/backdoor.py` gave a reverse shell.
The chain incident (risk 100, five stages) was created, and 3 s later the host risk score opened
"High Risk Threat Spike" from the same python → sh / python3 → bash processes, analysed as
"insufficient telemetry". The analyst opened the second one and concluded nothing was detected.
"""
import pytest
from sqlalchemy import select

from app.models.incident import Incident
from app.services.detection import web_compromise
from app.websocket import agent_ws
from test_containment import chain_incident, env, lab, proc, send  # noqa: F401  (fixture re-export)

SPIKE = "High Risk Threat Spike"


async def titles(factory):
    async with factory() as db:
        return [(i.title, (i.detection_evidence or {}).get("rule_id")) for i in (await db.scalars(select(Incident))).all()]


async def host_risk(factory, processes):
    await send(factory, agent_ws._handle_telemetry_risk, {"process_list": processes, "network_connections": []})


def attack_processes(payload):
    web = proc(5000, 1, "python", "/usr/bin/python3.13", "python -u /srv/vulnerable_web/app.py", -600)
    sh = proc(5001, 5000, "sh", "/usr/bin/dash", f"/bin/sh -c ping -c 1 127.0.0.1;python3 {payload}", 0)
    py = proc(5002, 5001, "python3", "/usr/bin/python3.13", f"python3 {payload}", 0.05)
    bash = proc(5003, 5002, "bash", "/usr/bin/bash", "/bin/bash", 0.1)
    return web, sh, py, bash


@pytest.mark.asyncio
async def test_chain_processes_do_not_open_a_host_risk_spike(env):
    _, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload)
    web, sh, py, bash = attack_processes(payload)
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": bash["process_start_time"], **bash, "parent": py}]})
    await host_risk(factory, [web, sh, py, bash])

    found = await titles(factory)
    assert not [t for t, _ in found if t.startswith(SPIKE)], found
    assert [r for _, r in found].count(web_compromise.RULE_ID) == 1


@pytest.mark.asyncio
async def test_spawns_no_chain_explains_still_open_an_incident(env):
    _, factory, _, _ = env
    # A non-web script spawning shells: the chain detector has no web anchor, the host score still decides.
    tool = proc(6000, 1, "python3", "/usr/bin/python3.13", "python3 /home/admin/build.py", -60)
    sh = proc(6001, 6000, "sh", "/usr/bin/dash", "/bin/sh -c make all", 0)
    await host_risk(factory, [tool, sh])
    found = await titles(factory)
    assert web_compromise.RULE_ID not in [r for _, r in found]
    assert [t for t, _ in found if t.startswith(SPIKE)], found
