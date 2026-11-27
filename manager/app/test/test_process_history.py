"""Task B: process history survives snapshots and reconstructs web app → shell → payload chains.

Replays the shape of the lab incident of 2026-11-27 (PIDs and timings from the VPS), built as
fixture data; nothing here is read from the live system.
"""
import pytest
from sqlalchemy import select

from app.models.process_info import ProcessInfo
from app.models.process_instance import ProcessInstance
from app.services.agent import process_history
from app.websocket import agent_ws
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

WEB = {"pid": 153380, "parent_pid": 1, "process_start_time": 1795737312.0, "name": "python",
       "exe": "/usr/bin/python3.13", "cmdline": "/opt/larp-agent/venv/bin/python -u /opt/larp-agent/vulnerable_web/app.py",
       "uid": 0, "euid": 0, "username": "root"}
SH = {"pid": 154105, "parent_pid": 153380, "process_start_time": 1795737688.8, "name": "sh", "exe": "/usr/bin/dash",
      "cmdline": "/bin/sh -c ping -c 1 127.0.0.1;python3 /tmp/uploads/backdoor.py", "uid": 0, "euid": 0}
PAYLOAD = {"pid": 154107, "parent_pid": 154105, "process_start_time": 1795737688.86, "name": "python3",
           "exe": "/usr/bin/python3.13", "cmdline": "python3 /tmp/uploads/backdoor.py", "uid": 0, "euid": 0}


async def handle(factory, handler, payload):
    async with factory() as db:
        result = await handler(AGENT, {"payload": {"agent_id": AGENT, **payload}, "wait_ack": True}, db)
        await db.commit()
    return result


@pytest.mark.asyncio
async def test_short_lived_shell_and_orphaned_payload_keep_their_lineage(lab):
    client, factory = lab
    # 1. Kernel exec events (Agent proc connector): shell and payload, then the shell exits (timeout kill).
    await handle(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": 1795737688.8, **SH, "parent": WEB},
        {"event": "exec", "observed_at": 1795737688.86, **PAYLOAD, "parent": SH},
        {"event": "exit", "observed_at": 1795737698.9, "pid": 154105, "exit_code": 0, "exit_signal": 9},
    ]})
    # 2. Later polling sees only the orphan (PPID 1) holding the socket; the snapshot replaces process_info.
    orphan = {**PAYLOAD, "parent_pid": 1}
    await handle(factory, agent_ws._handle_process_list, {"processes": [WEB, orphan],
                                                         "activity_sample": {"complete": True}})
    await handle(factory, agent_ws._handle_process_list, {"processes": [WEB], "activity_sample": {"complete": True}})

    async with factory() as db:
        snapshot = (await db.scalars(select(ProcessInfo.pid))).all()
        rows = {r.pid: r for r in (await db.scalars(select(ProcessInstance))).all()}
    assert 154105 not in snapshot  # the latest snapshot no longer has it ...
    assert rows[154105].exited_at is not None and rows[154105].exit_signal == 9  # ... history does
    assert rows[154107].parent_pid == 154105 and rows[154107].euid == 0  # re-parenting did not erase the link
    assert set(rows[154107].sources) == {"exec_event", "snapshot"}
    assert rows[153380].sources == ["exec_parent", "snapshot"]

    path = f"/api/v1/process/{AGENT}/history/{rows[154107].id}/lineage"
    assert client.get(path).status_code == 401  # command lines require an authenticated operator
    lineage = client.get(path, headers=ANALYST).json()
    assert [a["pid"] for a in lineage["ancestors"]] == [154105, 153380, ]
    assert lineage["ancestors"][0]["state"] == "exited" and "vulnerable_web/app.py" in lineage["ancestors"][1]["cmdline"]
    assert lineage["instance"]["id"] == process_history.instance_id(154107, 1795737688.86, "/usr/bin/python3.13")

    found = client.get(f"/api/v1/process/{AGENT}/history", params={"q": "backdoor", "minutes": 60}, headers=ADMIN).json()
    assert {i["pid"] for i in found["items"]} == {154105, 154107}
    assert found["collector"]["collector"] == "proc_connector"


@pytest.mark.asyncio
async def test_socket_holder_ancestry_is_recorded(lab):
    _, factory = lab
    conn = {"src_ip": "100.112.146.63", "src_port": 40986, "dst_ip": "100.67.222.3", "dst_port": 4444,
            "protocol": "TCP", "status": "ESTABLISHED", "direction": "outbound", "direction_basis": "no_local_listener",
            "attribution": "inode_verified", "pid": 154107,
            "holders": [{**{k: PAYLOAD[k] for k in ("pid", "parent_pid", "process_start_time", "cmdline", "uid", "euid")},
                         "process_name": "python3", "exe_path": "/usr/bin/python3.13", "socket_stdio": True,
                         "ancestry": [{**SH, "process_name": "sh", "exe_path": "/usr/bin/dash"},
                                      {**WEB, "process_name": "python", "exe_path": "/usr/bin/python3.13"}]}]}
    async with factory() as db:
        await process_history.record(db, AGENT, process_history.socket_processes([conn]))
        await db.commit()
        rows = {r.pid: r for r in (await db.scalars(select(ProcessInstance))).all()}
        chain = await process_history.lineage(db, AGENT, rows[154107])
    assert rows[154107].sources == ["socket_holder"] and rows[154105].sources == ["socket_ancestor"]
    assert [a["pid"] for a in chain] == [154105, 153380]


@pytest.mark.asyncio
async def test_lineage_never_links_a_parent_that_started_after_the_child(lab):
    _, factory = lab
    reused = {**SH, "pid": 153380, "process_start_time": 1795737999.0, "cmdline": "unrelated", "parent_pid": 1}
    async with factory() as db:
        await process_history.record(db, AGENT, [("snapshot", PAYLOAD | {"parent_pid": 153380}), ("snapshot", reused)])
        await db.commit()
        child = (await db.scalars(select(ProcessInstance).where(ProcessInstance.pid == 154107))).one()
        assert await process_history.lineage(db, AGENT, child) == []  # PID 153380 was reused later


@pytest.mark.asyncio
async def test_partial_exec_without_procfs_read_is_kept(lab):
    _, factory = lab
    await handle(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "pid": 160000, "partial": True, "parent_pid": 153380, "observed_at": 1795738000.123,
         "fork_observed_at": 1795738000.1, "start_time_source": "event_clock"}]})
    async with factory() as db:
        row = (await db.scalars(select(ProcessInstance).where(ProcessInstance.pid == 160000))).one()
    assert row.partial and row.start_time_source == "event_clock" and row.parent_pid == 153380
