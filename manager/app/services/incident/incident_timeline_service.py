import re
import ast
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.flow import Flow
from app.models.event import Event
from app.models.risk_score import RiskScoreRecord
from app.models.response_action import ResponseAction
from app.core.exceptions import NotFoundError

from app.services.incident.incident_service import is_eligible_culprit


def _parse_factors(description: str, factors_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Parse factors from raw description text or existing dict."""
    if factors_dict and isinstance(factors_dict, dict):
        return factors_dict

    if not description:
        return {}

    # Try extracting "Factors: {...}" block
    match = re.search(r"Factors:\s*(\{.*?\})", description, re.DOTALL)
    if match:
        raw_factors = match.group(1)
        try:
            return json.loads(raw_factors)
        except Exception:
            try:
                parsed = ast.literal_eval(raw_factors)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
    return {}


class IncidentTimelineService:
    """
    Service aggregates and synthesizes a chronological incident investigation timeline
    from 4 telemetry sources:
    1. process_info: Culprit process spawn and parent lineage
    2. flows / events: Outbound network communication and C2 connections
    3. risk_score_records: Risk assessment rule triggers and scoring
    4. response_actions: Applied mitigation actions (isolate, kill, rollback)
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def build_timeline(self, incident_id: str) -> Dict[str, Any]:
        inc_stmt = select(Incident).where(Incident.id == incident_id)
        inc_res = await self.session.execute(inc_stmt)
        incident = inc_res.scalar_one_or_none()
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        agent_id = incident.agent_id
        inc_time = incident.created_at or datetime.now(timezone.utc)
        timeline: List[Dict[str, Any]] = []
        if incident.detection_evidence:
            return await self._evidence_timeline(incident, inc_time)
        if ((incident.notes or "").startswith("rule_id:builtin_linux_network_shell")
                or "Direct connection to C2 port" in (incident.description or "")):
            return await self._evidence_timeline(incident, inc_time)

        # ------------------------------------------------------------------
        # 1. PROCESS SPAWN: Look up processes for the agent
        # ------------------------------------------------------------------
        culprit_proc: Optional[ProcessInfo] = None
        parent_proc: Optional[ProcessInfo] = None

        if agent_id:
            proc_stmt = (
                select(ProcessInfo)
                .where(ProcessInfo.agent_id == agent_id)
                .order_by(ProcessInfo.is_suspicious.desc(), ProcessInfo.created_at.desc())
                .limit(50)
            )
            proc_res = await self.session.execute(proc_stmt)
            procs = list(proc_res.scalars().all())

            # If incident already has culprit_process or parent_process (e.g. from enriched incident):
            culprit_dict = getattr(incident, "culprit_process", None)
            parent_dict = getattr(incident, "parent_process", None)

            if culprit_dict and culprit_dict.get("pid") is not None:
                c_pid = culprit_dict.get("pid")
                culprit_proc = next((p for p in procs if p.pid == c_pid), None)
                if not culprit_proc:
                    culprit_proc = ProcessInfo(
                        id=f"p_{c_pid}",
                        agent_id=agent_id,
                        pid=c_pid,
                        name=culprit_dict.get("name"),
                        cmdline=culprit_dict.get("cmdline"),
                        exe_path=culprit_dict.get("exe_path"),
                        is_suspicious=culprit_dict.get("is_suspicious", False)
                    )

            if parent_dict and parent_dict.get("pid") is not None:
                p_pid = parent_dict.get("pid")
                if p_pid == 1:
                    parent_proc = ProcessInfo(
                        id="p_systemd",
                        agent_id=agent_id,
                        pid=1,
                        name="systemd",
                        exe="/usr/lib/systemd/systemd",
                        exe_path="/usr/lib/systemd/systemd"
                    )
                else:
                    parent_proc = next((p for p in procs if p.pid == p_pid), None)

            # Fallback heuristic if not enriched
            if not culprit_proc:
                desc_lower = (incident.description or "").lower()

                # 1. Suspicious userland process
                for p in procs:
                    if p.is_suspicious and is_eligible_culprit(p):
                        culprit_proc = p
                        break

                # 2. Check reverse DNS of IP in description for known admin/remote desktop (e.g. AnyDesk)
                if not culprit_proc:
                    import socket
                    target_ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", incident.description or "")
                    target_proc_name = None
                    for ip in target_ips:
                        try:
                            hostname, _, _ = socket.gethostbyaddr(ip)
                            if any(d in hostname for d in ["anydesk.com", "teamviewer.com", "rustdesk.com"]):
                                target_proc_name = "anydesk"
                                break
                        except Exception:
                            pass
                    if target_proc_name:
                        for p in procs:
                            if (p.name or "").lower() == target_proc_name and is_eligible_culprit(p):
                                culprit_proc = p
                                break

                # 3. Process mentioned in description
                if not culprit_proc:
                    for p in procs:
                        p_name = (p.name or "").lower()
                        if p_name and p_name in desc_lower and is_eligible_culprit(p):
                            culprit_proc = p
                            break

                # 4. Known shell / attack binaries only if suspicious or reverse shell cmdline
                if not culprit_proc:
                    common_attack_names = {
                        "nc", "ncat", "netcat", "socat"
                    }
                    for p in procs:
                        p_name = (p.name or "").lower()
                        if p_name in common_attack_names and is_eligible_culprit(p):
                            cmd = (p.cmdline or "").lower()
                            if p.is_suspicious or any(pat in cmd for pat in ("/dev/tcp/", "-e /bin", "-e /bin/sh", "-e /bin/bash")):
                                culprit_proc = p
                                break

                # KHÔNG CÓ BLIND FALLBACK: Giữ culprit_proc = None nếu không có bằng chứng tiến trình độc hại!

                if culprit_proc and culprit_proc.parent_pid and culprit_proc.parent_pid != culprit_proc.pid and not parent_proc:
                    if culprit_proc.parent_pid == 1:
                        parent_proc = ProcessInfo(
                            id="p_systemd",
                            agent_id=culprit_proc.agent_id,
                            pid=1,
                            name="systemd",
                            exe="/usr/lib/systemd/systemd",
                            exe_path="/usr/lib/systemd/systemd"
                        )
                    elif culprit_proc.parent_pid < 100:
                        parent_proc = None
                    else:
                        for p in procs:
                            if p.pid == culprit_proc.parent_pid:
                                parent_proc = p
                                break

            if culprit_proc:
                p_time = culprit_proc.created_at or inc_time
                if p_time > inc_time:
                    p_time = inc_time - timedelta(seconds=7)

                parent_info = None
                if parent_proc and parent_proc.name:
                    parent_info = {
                        "pid": parent_proc.pid,
                        "name": parent_proc.name
                    }
                    title = f"{parent_proc.name} spawned {culprit_proc.name}"
                elif culprit_proc.parent_pid is not None and culprit_proc.parent_pid >= 100:
                    parent_info = {
                        "pid": culprit_proc.parent_pid,
                        "name": None
                    }
                    title = f"Process {culprit_proc.name} (PID {culprit_proc.pid}) spawned by PID {culprit_proc.parent_pid}"
                else:
                    title = f"Process {culprit_proc.name} (PID {culprit_proc.pid}) active"

                details = {
                    "pid": culprit_proc.pid,
                    "name": culprit_proc.name,
                    "path": culprit_proc.exe_path or culprit_proc.exe or "",
                    "cmdline": culprit_proc.cmdline or "",
                }
                if parent_info:
                    details["parent"] = parent_info

                timeline.append({
                    "time": p_time.isoformat() if hasattr(p_time, "isoformat") else str(p_time),
                    "type": "process_spawn",
                    "severity": "critical" if culprit_proc.is_suspicious else "warning",
                    "title": title,
                    "details": details
                })

        # ------------------------------------------------------------------
        # 2. NETWORK CONNECTIONS & FLOWS
        # ------------------------------------------------------------------
        flows_found = False
        if agent_id:
            flow_stmt = (
                select(Flow)
                .where(Flow.agent_id == agent_id)
                .order_by(Flow.created_at.desc())
                .limit(10)
            )
            flow_res = await self.session.execute(flow_stmt)
            flows = list(flow_res.scalars().all())

            for fl in flows:
                if fl.dst_ip in ("0.0.0.0", "127.0.0.1", "::1", "localhost"):
                    continue
                flows_found = True
                fl_time = fl.start_time or fl.created_at or (inc_time - timedelta(seconds=5))
                is_susp_port = fl.dst_port in (4444, 5555, 1337, 8080, 23, 6667)
                flow_pid = fl.pid
                if not flow_pid and culprit_proc and fl.process_name and fl.process_name.lower() == (culprit_proc.name or "").lower():
                    flow_pid = culprit_proc.pid

                timeline.append({
                    "time": fl_time.isoformat() if hasattr(fl_time, "isoformat") else str(fl_time),
                    "type": "network",
                    "severity": "critical" if is_susp_port else "info",
                    "title": f"Outbound connection to {fl.dst_ip}:{fl.dst_port}",
                    "details": {
                        "dst_ip": fl.dst_ip,
                        "dst_port": fl.dst_port,
                        "protocol": fl.protocol,
                        "bytes_sent": fl.bytes_sent,
                        "packets_sent": fl.packets_sent,
                        "pid": flow_pid
                    }
                })

        # ------------------------------------------------------------------
        # 3. RULE TRIGGERS & RISK FACTORS
        # ------------------------------------------------------------------
        factors_found = False
        if agent_id:
            risk_stmt = (
                select(RiskScoreRecord)
                .where(RiskScoreRecord.agent_id == agent_id)
                .order_by(RiskScoreRecord.timestamp.desc())
                .limit(3)
            )
            risk_res = await self.session.execute(risk_stmt)
            risk_records = list(risk_res.scalars().all())

            for rrec in risk_records:
                if rrec.factors and isinstance(rrec.factors, dict):
                    factors_found = True
                    for r_name, r_reason in rrec.factors.items():
                        if r_name in ("total_score", "score"):
                            continue
                        r_time = rrec.timestamp or (inc_time - timedelta(seconds=2))
                        timeline.append({
                            "time": r_time.isoformat() if hasattr(r_time, "isoformat") else str(r_time),
                            "type": "rule_trigger",
                            "severity": "critical" if incident.severity.value in ("critical", "high") else "warning",
                            "title": f"Rule {r_name} triggered (+{int(rrec.score)})",
                            "details": {
                                "rule": r_name,
                                "score": rrec.score,
                                "reason": str(r_reason)
                            }
                        })
                    break

        if not factors_found:
            parsed_factors = _parse_factors(incident.description)
            if parsed_factors:
                for r_name, r_reason in parsed_factors.items():
                    if r_name in ("total_score", "score"):
                        continue
                    t_rule = inc_time - timedelta(seconds=2)
                    timeline.append({
                        "time": t_rule.isoformat() if hasattr(t_rule, "isoformat") else str(t_rule),
                        "type": "rule_trigger",
                        "severity": "critical" if incident.risk_score >= 70 else "warning",
                        "title": f"Rule {r_name} triggered (+{int(incident.risk_score)})",
                        "details": {
                            "rule": r_name,
                            "score": incident.risk_score,
                            "reason": str(r_reason)
                        }
                    })
            else:
                t_rule = inc_time - timedelta(seconds=2)
                timeline.append({
                    "time": t_rule.isoformat() if hasattr(t_rule, "isoformat") else str(t_rule),
                    "type": "rule_trigger",
                    "severity": "critical",
                    "title": f"Risk Threshold Exceeded (Score: {incident.risk_score}/100)",
                    "details": {
                        "rule": "composite_risk_spike",
                        "score": incident.risk_score,
                        "reason": incident.description.split("\n")[0] if incident.description else "High risk threat anomaly"
                    }
                })

        # ------------------------------------------------------------------
        # 4. RESPONSE ACTIONS & AUDIT LOGS
        # ------------------------------------------------------------------
        act_stmt = (
            select(ResponseAction)
            .where(
                (ResponseAction.incident_id == incident.id) |
                (
                    (ResponseAction.agent_id == agent_id) &
                    (ResponseAction.created_at >= inc_time - timedelta(minutes=5))
                )
            )
            .order_by(ResponseAction.created_at.asc())
        )
        act_res = await self.session.execute(act_stmt)
        actions = list(act_res.scalars().all())

        for act in actions:
            a_time = act.applied_at or act.created_at or inc_time
            title_prefix = "Auto-" if act.action_params.get("policy_id") or "Auto" in str(act.action_params.get("reason", "")) else ""
            timeline.append({
                "time": a_time.isoformat() if hasattr(a_time, "isoformat") else str(a_time),
                "type": "action",
                "severity": "success" if act.status == "applied" else ("warning" if act.status == "reverted" else "info"),
                "title": f"{title_prefix}{act.action_type.upper()} {act.status}",
                "details": {
                    "action_id": act.id,
                    "action_type": act.action_type,
                    "status": act.status,
                    "triggered_by": "policy_engine" if title_prefix else "analyst",
                    "snapshot": act.snapshot
                }
            })

        # Sort timeline chronologically
        timeline.sort(key=lambda item: item.get("time", ""))

        return {
            "incident_id": incident.id,
            "timeline": timeline
        }

    async def _evidence_timeline(self, incident, incident_time):
        evidence = incident.detection_evidence or {}
        network = evidence.get("network")
        observed = (network or {}).get("observed_at") or incident_time.isoformat()
        timeline = []
        process = evidence.get("process")
        if process:
            timeline.append({
                "time": observed, "type": "process_observed", "severity": "warning",
                "title": f"Observed socket holder {process['name']} (PID {process['pid']})",
                "details": process,
            })
        if network:
            timeline.append({
                "time": observed, "type": "network_connection", "severity": "warning",
                "title": evidence["story"], "details": network,
            })
        chain = evidence.get("chain") if isinstance(evidence.get("chain"), dict) else None
        if chain:
            anchor_id = (chain.get("anchor") or {}).get("id")
            for cond in chain.get("conditions") or []:
                if cond.get("status") in ("OBSERVED", "CORRELATED") and cond.get("observed_at"):
                    timeline.append({
                        "time": cond["observed_at"],
                        "type": "rule_trigger",
                        "severity": "critical" if cond.get("id") in ("outbound_connection", "privileged_execution", "web_spawned_shell") else "warning",
                        "title": cond.get("label") or cond.get("id"),
                        "details": {"rule": cond.get("id"), "score": cond.get("contribution"), "reason": cond.get("detail")},
                    })
            for proc in chain.get("process_tree") or []:
                if proc.get("id") != anchor_id and proc.get("started_at"):
                    timeline.append({
                        "time": proc["started_at"],
                        "type": "process_spawn",
                        "severity": "warning",
                        "title": f"Khởi chạy {proc.get('name') or 'tiến trình'} (PID {proc.get('pid')})",
                        "details": {**proc, "exe_path": proc.get("exe")},
                    })
            for net in chain.get("network") or []:
                if net.get("first_seen"):
                    dst_ip, _, dst_port = str(net.get("dst", "")).rpartition(":")
                    timeline.append({
                        "time": net["first_seen"],
                        "type": "network_connection",
                        "severity": "critical",
                        "title": f"Kết nối ra ngoài tới {net.get('dst')} (PID {net.get('pid')})",
                        "details": {"dst_ip": dst_ip, "dst_port": dst_port, "protocol": "TCP", "pid": net.get("pid")},
                    })
        signals = evidence.get("signals", evidence.get("factors", []))
        if not chain:
            for signal in signals:
                timeline.append({
                    "time": observed, "type": "rule_trigger", "severity": "warning",
                    "title": signal["reason"], "details": {"rule": evidence.get("rule_id"), **signal},
                })

        actions = (await self.session.execute(select(ResponseAction).where(
            ResponseAction.incident_id == incident.id,
        ).order_by(ResponseAction.created_at))).scalars().all()
        for action in actions:
            timeline.append({
                "time": (action.applied_at or action.created_at).isoformat(), "type": "action",
                "severity": "success" if action.status == "applied" else "info",
                "title": f"{action.action_type} {action.status}",
                "details": {"action_id": action.id, "action_type": action.action_type, "status": action.status},
            })
        timeline.sort(key=lambda item: item["time"])
        return {"incident_id": incident.id, "timeline": timeline}
