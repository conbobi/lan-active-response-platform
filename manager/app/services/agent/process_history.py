"""Process instance history: every observed (PID, start time, executable) kept with first/last seen.

Sources, recorded per instance in ``sources``:
- ``snapshot``: PROCESS_LIST / TELEMETRY_RISK polling.
- ``socket_holder`` / ``socket_ancestor``: the verified owner of a socket and its parent chain,
  captured by the Agent at observation time.
- ``exec_event`` / ``exec_parent``: kernel exec events (proc connector) and the parent read then.

Lineage is only asserted between instances that the data links: same Agent, parent PID equal and
the parent started no later than the child. Anything else is left unlinked.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import delete, select

from app.models.process_instance import ProcessInstance
from app.services.detection.behavior_evidence import stable_id

logger = logging.getLogger("larp.process_history")

RETENTION_DAYS = float(os.getenv("PROCESS_HISTORY_DAYS", "7"))
_last_purge = 0.0
# Latest collector status per Agent (process connector availability, drops); in memory only.
COLLECTOR_STATUS: Dict[str, Dict[str, Any]] = {}


def _int(value, low=0, high=2**31):
    return value if type(value) is int and low <= value < high else None


def _float(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value < 4e9 else None


def _text(value, limit):
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    return str(value).replace("\x00", "")[:limit] if value is not None else ""


def instance_id(pid: int, start: Optional[float], exe: str) -> str:
    return stable_id("proc_", pid, start, exe)


def normalize(proc: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
    if not isinstance(proc, dict):
        return None
    pid = _int(proc.get("pid"), 1)
    if pid is None:
        return None
    start = _float(proc.get("process_start_time") or proc.get("create_time"))
    exe = _text(proc.get("exe") or proc.get("exe_path") or proc.get("path"), 1024)
    partial = bool(proc.get("partial")) or start is None
    if start is None:
        # Exited before it could be read: identify by PID and the kernel event time instead.
        start = _float(proc.get("fork_observed_at") or proc.get("observed_at"))
        if start is None:
            return None
        start = round(start, 1)
    parent = proc.get("parent")
    return {
        "id": instance_id(pid, start, exe), "pid": pid,
        "parent_pid": _int(proc.get("parent_pid") if proc.get("parent_pid") is not None else proc.get("ppid")),
        "process_start_time": start,
        "start_time_source": "event_clock" if partial else "procfs",
        "name": _text(proc.get("name") or proc.get("process_name"), 128),
        "exe": exe, "cmdline": _text(proc.get("cmdline"), 2048),
        "uid": _int(proc.get("uid")), "euid": _int(proc.get("euid")),
        "username": _text(proc.get("username"), 64) or None, "partial": partial, "source": source,
        "parent_snapshot": {k: parent.get(k) for k in ("pid", "parent_pid", "process_start_time", "name", "exe",
                                                       "cmdline", "uid", "euid")} if isinstance(parent, dict) else None,
    }


def socket_processes(connections: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Verified socket holders and their recorded ancestry, flattened for recording."""
    out = []
    for conn in connections or []:
        if not isinstance(conn, dict):
            continue
        for holder in conn.get("holders") or []:
            if not isinstance(holder, dict):
                continue
            out.append(("socket_holder", holder))
            for ancestor in holder.get("ancestry") or []:
                if isinstance(ancestor, dict):
                    out.append(("socket_ancestor", ancestor))
    return out


async def record(session, agent_id: str, observations: Iterable, observed_at: Optional[datetime] = None) -> int:
    """Upsert ``(source, process)`` observations. Returns the number of new instances."""
    now = observed_at or datetime.now(timezone.utc)
    rows: Dict[str, Dict[str, Any]] = {}
    for source, proc in observations:
        row = normalize(proc, source)
        if row is None:
            continue
        merged = rows.get(row["id"])
        if merged is not None and merged.get("parent_pid") == 1 and row.get("parent_pid") not in (None, 1):
            merged["parent_pid"] = row["parent_pid"]
        if merged is None:
            row["sources"] = {source}
            rows[row["id"]] = row
        else:
            merged["sources"].add(source)
            for key in ("parent_pid", "name", "cmdline", "uid", "euid", "username", "parent_snapshot"):
                if not merged.get(key) and row.get(key):
                    merged[key] = row[key]
    if not rows:
        return 0
    existing = {}
    ids = list(rows)
    for start in range(0, len(ids), 500):
        for inst in (await session.scalars(select(ProcessInstance).where(
                ProcessInstance.id.in_(ids[start:start + 500])))).all():
            existing[inst.id] = inst
    added = 0
    for key, row in rows.items():
        inst = existing.get(key)
        if inst is None:
            session.add(ProcessInstance(
                id=key, agent_id=agent_id, pid=row["pid"], parent_pid=row["parent_pid"],
                process_start_time=row["process_start_time"], start_time_source=row["start_time_source"],
                name=row["name"], exe=row["exe"], cmdline=row["cmdline"], uid=row["uid"], euid=row["euid"],
                username=row["username"], partial=row["partial"], sources=sorted(row["sources"]),
                parent_snapshot=row["parent_snapshot"], first_seen=now, last_seen=now,
            ))
            added += 1
            continue
        if inst.agent_id != agent_id:
            continue  # IDs are per instance; never let one Agent touch another's records
        if inst.last_seen is None or _utc(inst.last_seen) < now:
            inst.last_seen = now
        sources = set(inst.sources or []) | row["sources"]
        if sources != set(inst.sources or []):
            inst.sources = sorted(sources)
        for attr in ("parent_pid", "name", "cmdline", "uid", "euid", "username", "parent_snapshot"):
            if getattr(inst, attr) in (None, "") and row.get(attr) not in (None, ""):
                setattr(inst, attr, row[attr])
        # An orphan is re-parented to PID 1 (or a subreaper); the original parent, once known, wins.
        if inst.parent_pid == 1 and row.get("parent_pid") not in (None, 1):
            inst.parent_pid = row["parent_pid"]
    await _purge(session, now)
    return added


async def record_exits(session, agent_id: str, exits: Iterable[Dict[str, Any]]) -> int:
    """Mark the most recent matching instance of each exited PID (started before the exit)."""
    marked = 0
    for event in exits:
        pid = _int(event.get("pid"), 1)
        at = _float(event.get("observed_at"))
        if pid is None or at is None:
            continue
        inst = (await session.scalars(
            select(ProcessInstance).where(
                ProcessInstance.agent_id == agent_id, ProcessInstance.pid == pid,
                ProcessInstance.exited_at.is_(None), ProcessInstance.process_start_time <= at + 1)
            .order_by(ProcessInstance.process_start_time.desc()).limit(1))).first()
        if inst is None:
            continue
        inst.exited_at = datetime.fromtimestamp(at, timezone.utc)
        inst.exit_code = _int(event.get("exit_code"), -256, 256)
        inst.exit_signal = _int(event.get("exit_signal"), 0, 256)
        marked += 1
    return marked


async def lineage(session, agent_id: str, inst: ProcessInstance, depth: int = 8) -> List[Dict[str, Any]]:
    """Recorded ancestors, nearest first. A link needs the parent to have started before the child."""
    chain = []
    seen = {inst.id}
    child = inst
    for _ in range(depth):
        if not child.parent_pid or child.parent_pid in (0,):
            break
        query = select(ProcessInstance).where(
            ProcessInstance.agent_id == agent_id, ProcessInstance.pid == child.parent_pid)
        if child.process_start_time is not None:
            query = query.where(ProcessInstance.process_start_time <= child.process_start_time + 0.01)
        parent = (await session.scalars(query.order_by(ProcessInstance.process_start_time.desc()).limit(1))).first()
        if parent is None or parent.id in seen:
            if child.parent_snapshot and child.parent_snapshot.get("pid") == child.parent_pid:
                chain.append({**child.parent_snapshot, "id": None, "link": "exec_time_snapshot"})
            break
        chain.append({**serialize(parent), "link": "recorded_instance"})
        seen.add(parent.id)
        child = parent
    return chain


def serialize(inst: ProcessInstance) -> Dict[str, Any]:
    return {
        "id": inst.id, "pid": inst.pid, "parent_pid": inst.parent_pid,
        "process_start_time": inst.process_start_time, "start_time_source": inst.start_time_source,
        "name": inst.name, "exe": inst.exe, "cmdline": inst.cmdline, "uid": inst.uid, "euid": inst.euid,
        "username": inst.username, "partial": inst.partial, "sources": inst.sources or [],
        "first_seen": _iso(inst.first_seen), "last_seen": _iso(inst.last_seen), "exited_at": _iso(inst.exited_at),
        "exit_code": inst.exit_code, "exit_signal": inst.exit_signal,
        "state": "exited" if inst.exited_at else "last_seen_running",
    }


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return _utc(value).isoformat() if value else None


async def _purge(session, now: datetime):
    global _last_purge
    if time.monotonic() - _last_purge < 3600:
        return
    _last_purge = time.monotonic()
    await session.execute(delete(ProcessInstance).where(
        ProcessInstance.last_seen < now - timedelta(days=RETENTION_DAYS)))
