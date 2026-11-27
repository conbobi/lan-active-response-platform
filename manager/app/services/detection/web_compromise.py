"""Correlation rule: multi-stage web application compromise (web_compromise_chain).

Joins evidence that each collector records on its own into one explained attack chain:

    authentication bypass → suspicious upload → command injection → web process spawns a shell or
    interpreter → the uploaded file is executed → outbound connection from that process tree,
    amplified by execution with UID 0.

Every condition lists the evidence IDs it rests on, how it was established (OBSERVED: one telemetry
record shows it; CORRELATED: records from different sources joined by a key such as child PID +
spawn time, session hash or PID + start time), its weight and contribution. Conditions without
evidence are reported as NOT_OBSERVED with the reason. Score and severity are computed here,
deterministically; no model output is read. One incident is kept per web service process instance
(fingerprint), updated as stages arrive instead of opening new incidents.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import posixpath
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import or_, select

from app.core.agent_health import as_utc
from app.models.auth_event import AuthEvent
from app.models.event import Event
from app.models.flow import Flow
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.process_instance import ProcessInstance
from app.models.web_access_log import WebAccessLog
from app.schemas.enums import IncidentSeverity, IncidentStatus
from app.services.detection.behavior_evidence import stable_id

logger = logging.getLogger("larp.detection.web_compromise")

RULE_ID = "web_compromise_chain"
RULE_VERSION = "chain:1"
WINDOW = timedelta(minutes=int(os.getenv("WEB_CHAIN_WINDOW_MINUTES", "60")))
INCIDENT_REUSE = timedelta(hours=24)

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "busybox"}
INTERPRETERS = {"python", "python2", "python3", "perl", "php", "ruby", "node", "nodejs", "lua", "java", "pwsh"}
WEB_SERVICE = re.compile(
    r"(?:^|/)(?:nginx|apache2|httpd|lighttpd|caddy|gunicorn|uwsgi|php-fpm[\d.]*)\b|flask|vulnerable_web/app\.py|"
    r"\bmanage\.py\s+runserver\b|\buvicorn\b", re.I)
SHELL_CHAIN = re.compile(r"[;|&`]|\$\(")
TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")

# Weights: how much each verified condition contributes to the chain score (capped at 100).
WEIGHTS = {
    "auth_bypass": 20,
    "suspicious_upload": 10,
    "command_injection": 20,
    "web_spawned_shell": 25,
    "uploaded_file_execution": 25,
    "outbound_connection": 30,
    "privileged_execution": 15,
}
LABELS = {
    "auth_bypass": "Vượt xác thực (Authentication Bypass)",
    "suspicious_upload": "Upload file đáng ngờ",
    "command_injection": "Command Injection",
    "web_spawned_shell": "Web process sinh shell/interpreter bất thường",
    "uploaded_file_execution": "Thực thi file vừa upload",
    "outbound_connection": "Kết nối ra ngoài từ cây tiến trình (reverse shell/C2)",
    "privileged_execution": "Thực thi với quyền root (UID 0)",
}
STAGES = ("auth_bypass", "suspicious_upload", "command_injection", "web_spawned_shell",
          "uploaded_file_execution", "outbound_connection")
EXECUTION = ("web_spawned_shell", "uploaded_file_execution")


def _base(path: str) -> str:
    return posixpath.basename((path or "").split()[0]) if path else ""


def _proc_kind(inst: ProcessInstance) -> Optional[str]:
    names = {(inst.name or "").lower(), _base(inst.exe).lower()}
    stripped = {n.rstrip("0123456789.") for n in names}
    if names & SHELLS or stripped & SHELLS:
        return "shell"
    if names & INTERPRETERS or stripped & INTERPRETERS:
        return "interpreter"
    return None


def _ts(value) -> Optional[float]:
    if isinstance(value, datetime):
        return as_utc(value).timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return as_utc(datetime.fromisoformat(value.replace("Z", "+00:00"))).timestamp()
        except ValueError:
            return None
    return None


def _iso(value: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value else None


def _proc(inst: ProcessInstance) -> Dict[str, Any]:
    return {"id": inst.id, "pid": inst.pid, "parent_pid": inst.parent_pid, "name": inst.name, "exe": inst.exe,
            "cmdline": (inst.cmdline or "")[:512], "euid": inst.euid, "uid": inst.uid,
            "process_start_time": inst.process_start_time, "started_at": _iso(inst.process_start_time),
            "exited_at": as_utc(inst.exited_at).isoformat() if inst.exited_at else None,
            "sources": inst.sources or [], "partial": inst.partial}


@dataclass
class Condition:
    id: str
    status: str = "NOT_OBSERVED"
    evidence_ids: List[str] = field(default_factory=list)
    observed_at: Optional[float] = None
    detail: str = ""
    link: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def matched(self) -> bool:
        return self.status in ("OBSERVED", "CORRELATED")

    def hit(self, status: str, evidence_id: Optional[str], at: Optional[float], detail: str, link=None, **data):
        # OBSERVED beats CORRELATED; earliest timestamp kept.
        if not self.matched or (self.status == "CORRELATED" and status == "OBSERVED"):
            self.status, self.detail, self.link = status, detail, link
            self.data.update(data)
        if evidence_id and evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)
        if at and (self.observed_at is None or at < self.observed_at):
            self.observed_at = at


@dataclass
class Chain:
    anchor: Optional[ProcessInstance]
    anchor_pid: Optional[int]
    conditions: Dict[str, Condition] = field(default_factory=lambda: {k: Condition(k) for k in WEIGHTS})
    processes: Dict[str, ProcessInstance] = field(default_factory=dict)
    network: List[Dict[str, Any]] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    request_ids: List[str] = field(default_factory=list)


class Evidence:
    """Everything recorded for one Agent inside the correlation window."""

    def __init__(self, now: datetime):
        self.now = now
        self.uploads: List[Dict[str, Any]] = []
        self.commands: List[Dict[str, Any]] = []
        self.bypasses: List[Dict[str, Any]] = []
        self.web_pids: Dict[int, float] = {}
        self.instances: List[ProcessInstance] = []
        self.flows: List[Flow] = []
        self.has_process_history = False


async def load(session, agent_id: str, now: datetime) -> Evidence:
    ev = Evidence(now)
    since = now - WINDOW
    logs = (await session.scalars(select(WebAccessLog).where(
        WebAccessLog.agent_id == agent_id, WebAccessLog.timestamp >= since,
        WebAccessLog.raw_message.contains('"app_event"') | WebAccessLog.raw_message.contains('"process_pid"'),
    ).order_by(WebAccessLog.timestamp))).all()
    for log in logs:
        try:
            raw = json.loads(log.raw_message or "{}")
        except ValueError:
            continue
        at = _ts(log.timestamp)
        if type(raw.get("process_pid")) is int:
            ev.web_pids.setdefault(raw["process_pid"], at)
        event = raw.get("app_event") or {}
        base = {"evidence_id": log.id, "request_id": raw.get("request_id"), "source_ip": log.src_ip,
                "session_ref": raw.get("session_ref"), "at": at, "web_pid": raw.get("process_pid"),
                "http_status": log.status_code, "path": log.path}
        if event.get("type") == "file_upload" and event.get("stored"):
            ev.uploads.append({**base, **event})
        elif event.get("type") == "shell_command":
            ev.commands.append({**base, **event})
    auth_rows = (await session.scalars(select(Event).where(
        Event.agent_id == agent_id, Event.event_type == "AUTH_OBSERVATION", Event.created_at >= since,
    ))).all()
    for row in auth_rows:
        details = row.details or {}
        if details.get("suspected_auth_bypass") is True:
            auth = await session.get(AuthEvent, row.id)
            ev.bypasses.append({"evidence_id": row.id, "request_id": details.get("request_id"),
                                "session_ref": details.get("session_ref"),
                                "source_ip": auth.source_ip if auth else None,
                                "at": _ts(auth.timestamp) if auth else _ts(row.created_at),
                                "payload_indicators": details.get("payload_indicators") or []})
    ev.instances = list((await session.scalars(select(ProcessInstance).where(
        ProcessInstance.agent_id == agent_id, ProcessInstance.last_seen >= since))).all())
    ev.has_process_history = bool(ev.instances)
    ev.flows = list((await session.scalars(select(Flow).where(
        Flow.agent_id == agent_id, Flow.created_at >= since, Flow.socket_evidence.is_not(None),
    ).order_by(Flow.created_at))).all())
    return ev


def _is_web(inst: ProcessInstance, ev: Evidence) -> bool:
    return inst.pid in ev.web_pids or bool(WEB_SERVICE.search(f"{inst.exe} {inst.cmdline}"))


def _children(inst: ProcessInstance, ev: Evidence) -> List[ProcessInstance]:
    start = inst.process_start_time or 0
    return [c for c in ev.instances if c.parent_pid == inst.pid and c.id != inst.id
            and (c.process_start_time or 0) >= start - 0.01]


def build_chains(ev: Evidence) -> List[Chain]:
    chains: Dict[Any, Chain] = {}
    webs = [i for i in ev.instances if _is_web(i, ev)]

    def chain_for(inst: Optional[ProcessInstance], pid: Optional[int]) -> Chain:
        key = inst.pid if inst else pid
        if key not in chains:
            chains[key] = Chain(anchor=inst, anchor_pid=key)
        elif inst is not None and chains[key].anchor is None:
            chains[key].anchor = inst
        return chains[key]

    # Process stages: unexpected shell/interpreter children of a web service process and their descendants.
    for web in webs:
        for child in _children(web, ev):
            kind = _proc_kind(child)
            if kind is None:
                continue
            command = next((c for c in ev.commands if c.get("child_pid") == child.pid and c.get("child_spawned_at")
                            and child.process_start_time
                            and abs(c["child_spawned_at"] - child.process_start_time) <= 3), None)
            descendants = _descendants(child, ev)
            chained = kind == "shell" and bool(SHELL_CHAIN.search(_shell_command(child.cmdline)))
            injected = bool(command and command.get("shell_indicators"))
            # A web app that legitimately runs `sh -c ping ...` is not a stage; injection, chaining or
            # further program execution from the spawned process is.
            if not (chained or injected or kind == "interpreter" or any(_proc_kind(d) for d in descendants)):
                continue
            chain = chain_for(web, web.pid)
            chain.processes[web.id] = web
            chain.processes[child.id] = child
            for d in descendants:
                chain.processes[d.id] = d
            reason = ("dòng lệnh shell chứa ký tự nối lệnh" if chained else
                      "liên kết với request có chỉ báo injection" if injected else
                      "web process sinh interpreter" if kind == "interpreter" else
                      "shell tiếp tục thực thi chương trình khác")
            chain.conditions["web_spawned_shell"].hit(
                "OBSERVED", child.id, child.process_start_time,
                f"{web.name or _base(web.exe)} (PID {web.pid}) → {child.name} (PID {child.pid}): {reason}",
                link="process_history: parent PID + start time")
            if command:
                chain.conditions["command_injection"].hit(
                    "CORRELATED", command["evidence_id"], command["at"],
                    f"Request {command['path']} sinh shell PID {child.pid}",
                    link="child_pid + spawn time (±3 s)")

    # HTTP stages: attach to the chain of the web process that served them.
    for item in ev.commands + ev.uploads + ev.bypasses:
        pid = item.get("web_pid")
        anchor = _instance_for_pid(pid, item.get("at"), ev) if pid else None
        if anchor is None and pid is None:
            anchor = next(iter(c.anchor for c in chains.values() if c.anchor), None)
        chain = chain_for(anchor, pid if pid else (anchor.pid if anchor else None))
        if item.get("source_ip") and item["source_ip"] not in chain.source_ips and item["source_ip"] != "unknown":
            chain.source_ips.append(item["source_ip"])
        if item.get("request_id") and item["request_id"] not in chain.request_ids:
            chain.request_ids.append(item["request_id"])

    for chain in chains.values():
        _http_conditions(chain, ev)
        _execution_conditions(chain, ev)
        _network_condition(chain, ev)
    return [c for c in chains.values() if any(c.conditions[s].matched for s in STAGES)]


def _instance_for_pid(pid: int, at: Optional[float], ev: Evidence) -> Optional[ProcessInstance]:
    candidates = [i for i in ev.instances if i.pid == pid and (at is None or (i.process_start_time or 0) <= at)]
    return max(candidates, key=lambda i: i.process_start_time or 0, default=None)


def _descendants(root: ProcessInstance, ev: Evidence, depth: int = 4) -> List[ProcessInstance]:
    out, frontier = [], [root]
    for _ in range(depth):
        nxt = []
        for parent in frontier:
            for child in _children(parent, ev):
                if child not in out:
                    out.append(child)
                    nxt.append(child)
        frontier = nxt
    return out


def _shell_command(cmdline: str) -> str:
    match = re.search(r"\s-c\s+(.*)$", cmdline or "")
    return match.group(1) if match else ""


def _http_conditions(chain: Chain, ev: Evidence):
    sessions = set()
    ips = set(chain.source_ips)
    commands = [c for c in ev.commands if c.get("web_pid") in (chain.anchor_pid, None)]
    for command in commands:
        if command.get("shell_indicators"):
            chain.conditions["command_injection"].hit(
                "OBSERVED", command["evidence_id"], command["at"],
                f"{command['path']}: tham số đi vào shell chứa {', '.join(command['shell_indicators'])}; "
                f"kết quả thực thi: {command.get('execution_result')}",
                request_id=command.get("request_id"), execution_result=command.get("execution_result"))
            if command.get("session_ref"):
                sessions.add(command["session_ref"])
    for upload in [u for u in ev.uploads if u.get("web_pid") in (chain.anchor_pid, None)]:
        if upload.get("script_or_binary") or upload.get("outside_upload_dir"):
            chain.conditions["suspicious_upload"].hit(
                "OBSERVED", upload["evidence_id"], upload["at"],
                f"Lưu {upload.get('upload_path')} ({upload.get('upload_size')} byte, sha256 "
                f"{(upload.get('upload_sha256') or '')[:12]}…); chỉ xác nhận đã lưu, chưa xác nhận đã thực thi",
                upload_path=upload.get("upload_path"), upload_sha256=upload.get("upload_sha256"))
            if upload.get("session_ref"):
                sessions.add(upload["session_ref"])
    for bypass in ev.bypasses:
        same_session = bypass.get("session_ref") and bypass["session_ref"] in sessions
        same_source = bypass.get("source_ip") and bypass["source_ip"] in ips
        if not (same_session or same_source):
            continue  # no key links this login to the chain
        chain.conditions["auth_bypass"].hit(
            "OBSERVED", bypass["evidence_id"], bypass["at"],
            "Đăng nhập được cấp phiên nhưng thông tin gửi lên không khớp tài khoản trả về"
            + (f"; chỉ báo: {', '.join(bypass['payload_indicators'])}" if bypass["payload_indicators"] else ""),
            link=("session_ref (cùng phiên với request sau)" if same_session else
                  "cùng source IP trong cửa sổ thời gian" if same_source else None))
        if bypass.get("source_ip") and bypass["source_ip"] not in chain.source_ips:
            chain.source_ips.append(bypass["source_ip"])


def _execution_conditions(chain: Chain, ev: Evidence):
    paths = {u["upload_path"]: u for u in ev.uploads if u.get("upload_path")}
    names = {n for c in ev.commands for n in (c.get("referenced_upload_files") or [])}
    for inst in list(chain.processes.values()):
        if chain.anchor and inst.id == chain.anchor.id:
            continue
        cmd = inst.cmdline or ""
        upload = next((u for p, u in paths.items() if p in cmd), None)
        referenced = next((n for n in names if re.search(rf"/{re.escape(n)}(?:\s|$)", cmd)), None)
        temp_script = _proc_kind(inst) == "interpreter" and any(t in cmd for t in TEMP_DIRS)
        if upload or referenced:
            chain.conditions["uploaded_file_execution"].hit(
                "CORRELATED", inst.id, inst.process_start_time,
                f"PID {inst.pid} `{cmd[:160]}` chạy file "
                + (f"đã upload {upload['upload_path']}" if upload else f"{referenced} được request nhắc tới")
                + " (khớp theo đường dẫn; chưa so sánh hash nội dung)",
                link="đường dẫn file trong command line", upload_evidence_id=upload["evidence_id"] if upload else None)
            if upload:
                chain.conditions["uploaded_file_execution"].evidence_ids.append(upload["evidence_id"])
        elif temp_script:
            chain.conditions["uploaded_file_execution"].hit(
                "CORRELATED", inst.id, inst.process_start_time,
                f"PID {inst.pid} chạy script trong thư mục tạm: `{cmd[:160]}` (không có bản ghi upload tương ứng)",
                link="thư mục tạm trong command line")
        if inst.euid == 0 and _proc_kind(inst):
            chain.conditions["privileged_execution"].hit(
                "OBSERVED", inst.id, inst.process_start_time,
                f"PID {inst.pid} ({inst.name}) chạy với euid 0 (root)")


def _network_condition(chain: Chain, ev: Evidence):
    keys = {(i.pid, i.process_start_time): i for i in chain.processes.values()
            if not (chain.anchor and i.id == chain.anchor.id)}
    if not keys:
        return
    seen = set()
    for flow in ev.flows:
        socket = flow.socket_evidence or {}
        if not str(socket.get("attribution") or "").startswith("inode_verified"):
            continue
        for holder in socket.get("holders") or []:
            inst = keys.get((holder.get("pid"), holder.get("process_start_time")))
            if inst is None or socket.get("direction") == "inbound":
                continue
            ident = (flow.dst_ip, flow.dst_port, flow.src_port, inst.id)
            if ident in seen:
                continue
            seen.add(ident)
            stdio = bool(holder.get("socket_stdio"))
            chain.network.append({"flow_id": flow.id, "src": f"{flow.src_ip}:{flow.src_port}",
                                  "dst": f"{flow.dst_ip}:{flow.dst_port}", "direction": socket.get("direction"),
                                  "process_id": inst.id, "pid": inst.pid, "socket_stdio": stdio,
                                  "first_seen": socket.get("first_seen"), "last_seen": socket.get("observed_at")})
            chain.conditions["outbound_connection"].hit(
                "OBSERVED", flow.id, _ts(socket.get("first_seen")) or _ts(flow.created_at),
                f"PID {inst.pid} giữ socket tới {flow.dst_ip}:{flow.dst_port} (xác minh qua inode)"
                + ("; stdin/stdout gắn vào socket (shell tương tác qua mạng)" if stdio else ""),
                link="socket inode + PID + start time", destination=f"{flow.dst_ip}:{flow.dst_port}")


def assess(chain: Chain, ev: Evidence) -> Dict[str, Any]:
    c = chain.conditions
    matched = [k for k in WEIGHTS if c[k].matched]
    stages = [k for k in STAGES if c[k].matched]
    execution = any(c[k].matched for k in EXECUTION)
    total = sum(WEIGHTS[k] for k in matched)
    score = min(100, total)
    if execution and c["outbound_connection"].matched:
        severity, reason = IncidentSeverity.CRITICAL, ("Thực thi mã từ web process đã được quan sát và tiến trình "
                                                        "đó giữ kết nối ra ngoài")
        score = max(score, 90)
    elif execution:
        severity, reason = IncidentSeverity.HIGH, "Web process thực thi shell/interpreter bất thường"
        score = max(score, 70)
    elif len(stages) >= 2:
        severity, reason = IncidentSeverity.MEDIUM, "Nhiều giai đoạn tấn công web nhưng chưa thấy thực thi mã"
        score = min(score, 69)
    else:
        return {"create": False}  # one HTTP-side signal alone stays with the per-request detectors
    missing = {
        "web_spawned_shell": "Không có bản ghi tiến trình con bất thường của web process"
        + ("" if ev.has_process_history else " (chưa có lịch sử tiến trình từ Agent)"),
        "uploaded_file_execution": "Không thấy tiến trình chạy file đã upload hoặc script trong thư mục tạm",
        "outbound_connection": "Không có socket đi ra được xác minh thuộc cây tiến trình này",
        "privileged_execution": "Không có tiến trình trong chuỗi chạy với euid 0",
        "auth_bypass": "Không có bản ghi đăng nhập bị vượt xác thực liên kết với chuỗi",
        "suspicious_upload": "Không có upload script/binary trong cửa sổ",
        "command_injection": "Không có request mang chỉ báo injection liên kết với chuỗi",
    }
    conditions = []
    for key in WEIGHTS:
        cond = c[key]
        conditions.append({
            "id": key, "label": LABELS[key], "status": cond.status, "weight": WEIGHTS[key],
            "contribution": WEIGHTS[key] if cond.matched else 0, "evidence_ids": cond.evidence_ids[:20],
            "observed_at": _iso(cond.observed_at), "detail": cond.detail if cond.matched else missing[key],
            "link": cond.link, **({k: v for k, v in cond.data.items() if v is not None} if cond.matched else {}),
        })
    return {
        "create": True, "severity": severity, "score": float(score), "severity_reason": reason,
        "conditions": conditions, "matched": matched, "execution_observed": execution,
        "score_breakdown": {"sum_of_weights": total, "cap": 100, "final": score,
                            "rule": "CRITICAL: thực thi + kết nối ra; HIGH: thực thi; MEDIUM: ≥2 giai đoạn, chưa thực thi"},
    }


def _fingerprint(agent_id: str, chain: Chain) -> str:
    # The web service PID is known from HTTP telemetry before (or without) process history, so it keeps
    # the chain identity stable while stages arrive; a restarted service gets a new PID and a new chain.
    return hashlib.sha256(json.dumps([RULE_ID, agent_id, chain.anchor_pid]).encode()).hexdigest()


async def _related_incidents(session, agent_id: str, chain: Chain, since: datetime, exclude: Optional[str]):
    rows = (await session.scalars(select(Incident).where(
        Incident.agent_id == agent_id, Incident.created_at >= since,
        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]),
    ))).all()
    related = []
    for inc in rows:
        if inc.id == exclude:
            continue
        behavior = (inc.detection_evidence or {}).get("behavior") or {}
        if behavior.get("request_id") in chain.request_ids or (
                behavior.get("source_ip") in chain.source_ips and behavior.get("evidence_type") == "http"):
            related.append({"id": inc.id, "title": inc.title, "link": "cùng request_id/source IP"})
    return related[:20]


async def correlate(session, agent_id: str, now: Optional[datetime] = None) -> List[Incident]:
    now = now or datetime.now(timezone.utc)
    ev = await load(session, agent_id, now)
    if not (ev.commands or ev.uploads or ev.bypasses or ev.instances):
        return []
    touched = []
    for chain in build_chains(ev):
        result = assess(chain, ev)
        if not result["create"]:
            continue
        incident = await _upsert(session, agent_id, chain, result, ev, now)
        if incident is not None:
            touched.append(incident)
    return touched


async def _upsert(session, agent_id, chain: Chain, result, ev: Evidence, now: datetime) -> Optional[Incident]:
    fingerprint = _fingerprint(agent_id, chain)
    existing = (await session.scalars(select(Incident).where(
        Incident.agent_id == agent_id, Incident.fingerprint == fingerprint,
        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]),
        or_(Incident.label.is_(None), Incident.label != "false_positive"),
        Incident.updated_at >= now - INCIDENT_REUSE,
    ).order_by(Incident.updated_at.desc()))).first()
    processes = sorted(chain.processes.values(), key=lambda i: i.process_start_time or 0)
    times = [t for t in (_ts(c["observed_at"]) for c in result["conditions"] if c["observed_at"]) if t]
    chain_doc = {
        "anchor": _proc(chain.anchor) if chain.anchor else {"pid": chain.anchor_pid},
        "source_ips": chain.source_ips, "request_ids": chain.request_ids[:50],
        "conditions": result["conditions"], "score_breakdown": result["score_breakdown"],
        "severity": result["severity"].value, "severity_reason": result["severity_reason"],
        "execution_observed": result["execution_observed"],
        "process_tree": [_proc(p) for p in processes], "network": chain.network[:20],
        "first_activity_at": _iso(min(times)) if times else None, "last_activity_at": _iso(max(times)) if times else None,
        "status_basis": "OBSERVED = một bản ghi telemetry thể hiện trực tiếp; CORRELATED = ghép các nguồn qua khóa liên kết",
    }
    digest = hashlib.sha256(json.dumps(chain_doc, sort_keys=True, default=str).encode()).hexdigest()
    factors = [{"rule": c["id"], "score": c["contribution"], "reason": c["detail"], "status": c["status"],
                "evidence_ids": c["evidence_ids"]} for c in result["conditions"] if c["contribution"]]
    title_kind = "Web Application Compromise" if result["execution_observed"] else "Web Application Intrusion"
    title = f"{title_kind} on Agent '{agent_id}' (Score: {result['score']:.0f})"
    if existing is not None:
        previous = existing.detection_evidence or {}
        if previous.get("chain_digest") == digest:
            return None
        chain_doc["related_incidents"] = await _related_incidents(session, agent_id, chain, now - WINDOW, existing.id)
        existing.detection_evidence = {
            **previous, "rule_id": RULE_ID, "rule_version": RULE_VERSION, "factors": factors, "chain": chain_doc,
            "chain_digest": digest, "last_received_at": now.isoformat(),
            "observations": int(previous.get("observations", 1)) + 1, "risk_calculated_at": now.isoformat(),
        }
        if result["score"] >= existing.risk_score:
            existing.risk_score = result["score"]
            existing.severity = result["severity"]
            existing.title = title
        existing.updated_at = now
        session.add(IncidentNote(id=f"note_{uuid.uuid4().hex[:12]}", incident_id=existing.id, user="detection_engine",
                                 content=f"Chuỗi tấn công cập nhật: {', '.join(result['matched'])} "
                                      f"(điểm {result['score']:.0f}, {result['severity'].value}).",
                                 created_at=now))
        await session.flush()
        return existing
    inc = Incident(
        id=f"inc_{uuid.uuid4().hex[:12]}", title=title, severity=result["severity"], status=IncidentStatus.OPEN,
        agent_id=agent_id, risk_score=result["score"], fingerprint=fingerprint, notes=f"risk_source:{RULE_ID}",
        description=(f"{result['severity_reason']}. Điều kiện khớp: "
                     + ", ".join(LABELS[k] for k in result["matched"]) + "."),
        detection_evidence={
            "rule_id": RULE_ID, "rule_version": RULE_VERSION, "risk_calculated_at": now.isoformat(),
            "first_seen": now.isoformat(), "last_received_at": now.isoformat(), "observations": 1,
            "factors": factors, "chain": {**chain_doc, "related_incidents": await _related_incidents(
                session, agent_id, chain, now - WINDOW, None)}, "chain_digest": digest,
        },
    )
    session.add(inc)
    await session.flush()
    session.add(IncidentNote(id=f"note_{uuid.uuid4().hex[:12]}", incident_id=inc.id, user="detection_engine",
                             content=f"Tạo bởi {RULE_ID}: {result['severity_reason']}.", created_at=now))
    context = getattr(session, "info", {})
    if context.get("defer_incident_events") is True:  # WebSocket path: triage/broadcast after commit
        context.setdefault("new_incident_ids", []).append(inc.id)
        context.setdefault("dashboard_events", []).append({"type": "INCIDENT_NEW", "data": [{
            "id": inc.id, "title": inc.title, "severity": inc.severity.value, "risk_score": inc.risk_score,
            "agent_id": agent_id}]})
    logger.warning("web_compromise_chain: incident %s for Agent %s (%s, %s)", inc.id, agent_id,
                   result["severity"].value, ",".join(result["matched"]))
    return inc
