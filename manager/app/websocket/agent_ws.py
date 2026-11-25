import re
import asyncio
import ipaddress
import json
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.websocket.connection_manager import connection_manager
from app.websocket.dashboard_connection_manager import dashboard_manager
from app.services.rule_engine import rule_engine
from app.services.ai.ai_triage_service import AITriageService
from app.schemas.heartbeat import HeartbeatDTO
from app.core.response_safety import PROTECTED_COMMANDS, VERIFIED_KILL_COMMANDS
from app.schemas.command_ack import CommandAckDTO
from app.services.agent.agent_service import AgentService
from app.services.agent.activity import process_identity, record_sample
from app.services.core.command_dispatcher import command_dispatcher
from app.services.detection.risk_assessment_service import RiskAssessmentService
from app.services.detection.risk_rules.brute_force_rule import normalize_auth_event
from app.services.detection.behavior_evidence import REQUEST_ID, address, http_fields, observed_time, stable_id
from app.models.process_info import ProcessInfo
from app.repositories.process_info_repository import ProcessInfoRepository
from app.models.flow import Flow
from app.repositories.flow_repository import FlowRepository
from app.models.event import Event
from app.repositories.event_repository import EventRepository
from app.models.agent import Agent
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.enums import IncidentSeverity, IncidentStatus, AgentStatus, CommandStatus
from app.services.common.audit_log_service import ActionAuditLogService
from app.services.common.notification_service import NotificationService
from app.schemas.incident import IncidentCreate
from app.services.incident.incident_service import IncidentService
from app.models.auth_event import AuthEvent
from app.models.web_access_log import WebAccessLog
from app.repositories.web_access_log_repository import WebAccessLogRepository
from app.core.database import AsyncSessionLocal
from app.core.network_security import authenticate_agent, is_enrolled
from app.services.agent import network_service

logger = logging.getLogger(__name__)


async def _save_process_list(session: AsyncSession, target_agent_id: str, 
                              processes_data: list) -> int:
    """Replace one process snapshot using a batched insert."""
    if not processes_data or not isinstance(processes_data, list):
        return 0
    
    proc_repo = ProcessInfoRepository(session)
    await proc_repo.delete_by_agent(target_agent_id)
    await session.flush()
    
    now_dt = datetime.now(timezone.utc)
    rows = []
    skipped = 0
    
    def safe_str(val, max_len: int, default: str = "") -> str:
        """Truncate string to model max length."""
        if val is None:
            return default
        s = str(val).replace("\x00", "")
        return s[:max_len] if len(s) > max_len else s
    
    def safe_int(val, default=None):
        try:
            return int(val) if val is not None else default
        except (ValueError, TypeError, OverflowError):
            return default
    
    def safe_float(val, default=0.0):
        try:
            return float(val) if val is not None else default
        except (ValueError, TypeError, OverflowError):
            return default
    
    for proc_item in processes_data:
        # Skip invalid pid
        pid = safe_int(proc_item.get("pid")) if isinstance(proc_item, dict) else None
        if pid is None or not 0 <= pid < 2**31:
            skipped += 1
            continue
        
        try:
            parent_pid = safe_int(
                proc_item.get("parent_pid") 
                if proc_item.get("parent_pid") is not None 
                else proc_item.get("ppid")
            )
            
            if parent_pid is not None and not 0 <= parent_pid < 2**31:
                parent_pid = None
            cmd_raw = proc_item.get("cmdline") or ""
            if isinstance(cmd_raw, list):
                cmdline_str = " ".join(str(x) for x in cmd_raw)
            else:
                cmdline_str = str(cmd_raw)
            
            # ⚠️ CRITICAL: Truncate mọi string theo model limit
            pinfo = ProcessInfo(
                id=f"proc_{uuid.uuid4().hex[:12]}",
                agent_id=target_agent_id,
                pid=pid,
                parent_pid=parent_pid,
                process_start_time=safe_float(proc_item.get("process_start_time"), None),
                name=safe_str(proc_item.get("name"), 128, "unknown"),
                exe=safe_str(
                    proc_item.get("exe") or proc_item.get("path"), 512
                ),
                exe_path=safe_str(
                    proc_item.get("exe_path") or proc_item.get("exe") 
                    or proc_item.get("path"), 512
                ) or None,
                cmdline=safe_str(cmdline_str, 1024),
                cpu_percent=safe_float(
                    proc_item.get("cpu_percent") or proc_item.get("cpu")
                ),
                memory_percent=safe_float(
                    proc_item.get("memory_percent") or proc_item.get("ram")
                ),
                is_suspicious=bool(proc_item.get("is_suspicious", False)),
                hash=safe_str(proc_item.get("hash"), 128) or None,
                created_at=now_dt,
            )
            
            rows.append(pinfo)
        except Exception as e:
            logger.warning(
                f"[PROCESS_LIST] Skip pid={proc_item.get('pid')} "
                f"name={proc_item.get('name')}: {type(e).__name__}: {e}"
            )
            skipped += 1
            continue
    
    if rows:
        session.add_all(rows)
        await session.flush()
    count = len(rows)
    if skipped > 0:
        logger.warning(
            f"[PROCESS_LIST] {target_agent_id}: saved={count}, skipped={skipped}"
        )
    
    return count



async def _handle_heartbeat(agent_id: str, data: dict, session: AsyncSession) -> Tuple[Optional[dict], str]:
    payload = data.get("payload", {})
    if not payload.get("agent_id"):
        payload["agent_id"] = agent_id
    dto = HeartbeatDTO(**payload)
    active_agent_id = dto.agent_id or agent_id
    agent_svc = AgentService(session)
    agent = await agent_svc.process_heartbeat(dto)
    if isinstance(getattr(agent, "decommissioned_at", None), datetime):
        return {"status": "ack", "message": "Agent decommissioned", "pending_commands": []}, active_agent_id
    if str(dto.platform).lower() in {"windows", "darwin"}:
        await network_service.mark_unsupported(session, active_agent_id, dto.platform.lower())

    pending_cmds = await command_dispatcher.pull_pending_commands(active_agent_id, session)
    response_payload = {
        "status": "ack",
        "message": "Heartbeat processed",
        "pending_commands": [
            {"command_id": c.id, "action": c.action, "payload": c.payload}
            for c in pending_cmds
        ]
    }
    return response_payload, active_agent_id


async def _run_ai_triage(incident_id: str):
    """Background task: Chạy AI triage an toàn không block WebSocket, có sleep và retry loop để đảm bảo commit."""
    logger.info(f"Hook: Triggering AI Triage for {incident_id}")
    await asyncio.sleep(0.8)

    for attempt in range(1, 6):
        try:
            # Short session: check if incident exists and commit/close immediately
            async with AsyncSessionLocal() as session:
                inc = await session.get(Incident, incident_id)
                if not inc:
                    if attempt < 5:
                        logger.warning(
                            f"Incident {incident_id} not found in DB yet (attempt {attempt}/5), retrying in 1.0s..."
                        )
                        await asyncio.sleep(1.0)
                        continue
                    else:
                        logger.error(
                            f"Incident {incident_id} not found after 5 attempts. Aborting AI triage."
                        )
                        return

            # DB connection released to pool before running AI triage LLM call
            service = AITriageService()
            logger.info(f"Executing analyze_incident for {incident_id}...")
            analysis = await service.analyze_incident(incident_id)
            if analysis:
                logger.info(f"AI triage completed successfully for incident {incident_id}")
                try:
                    await dashboard_manager.broadcast({
                        "type": "AI_ANALYSIS_COMPLETED",
                        "event": "AI_ANALYSIS_COMPLETED",
                        "incident_id": incident_id,
                        "data": {
                            "id": analysis.id,
                            "summary": analysis.summary,
                            "confidence": analysis.confidence,
                            "mitre_techniques": analysis.mitre_techniques,
                            "root_cause": analysis.root_cause
                        }
                    })
                except Exception as b_err:
                    logger.debug(f"Dashboard broadcast AI analysis failed: {b_err}")
            else:
                logger.warning(f"AI triage returned no analysis for incident {incident_id}")
            return
        except Exception as e:
            logger.error(f"AI Triage failed: {e}", exc_info=True)
            if attempt < 5:
                await asyncio.sleep(1.0)


async def _evaluate_incident_rules(agent_id: str, telemetry: dict, session: AsyncSession) -> None:
    incidents = await rule_engine.evaluate({**telemetry, "agent_id": agent_id}, session)
    if not incidents:
        return

    message = {
        "type": "INCIDENT_NEW",
        "data": [
            {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity.value,
                "risk_score": incident.risk_score,
                "agent_id": agent_id,
            }
            for incident in incidents
        ],
    }
    context = getattr(session, "info", {})
    if context.get("defer_incident_events") is True:
        context.setdefault("dashboard_events", []).append(message)
        context.setdefault("new_incident_ids", []).extend(incident.id for incident in incidents)
        return
    for incident in incidents:
        asyncio.create_task(_run_ai_triage(incident.id))
    await dashboard_manager.broadcast(message)


async def _handle_process_list(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    procs_data = payload.get("processes", [])
    accepted = await record_sample(session, target_agent_id, "process", payload, procs_data)
    if accepted is False:
        return {"status": "ack", "count": 0, "message": "Observation already superseded"} if data.get("wait_ack", True) else None
    if accepted and not procs_data and payload["activity_sample"].get("complete") is True:
        await ProcessInfoRepository(session).delete_by_agent(target_agent_id)
    saved_count = await _save_process_list(session, target_agent_id, procs_data)
    logger.info(f"Saved {saved_count} processes for agent '{target_agent_id}' via PROCESS_LIST")

    try:
        await _evaluate_incident_rules(target_agent_id, payload, session)
    except Exception as e:
        if accepted:
            raise
        logger.error(f"rule_engine hook failed on PROCESS_LIST for agent '{target_agent_id}': {e}", exc_info=True)

    if data.get("wait_ack", True):
        return {
            "status": "ack",
            "message": "Process list stored successfully",
            "count": saved_count
        }
    return None


async def _handle_telemetry_risk(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    if target_agent_id != agent_id:
        return {"status": "error", "message": "Invalid telemetry Agent"}
    platform_name = payload.get("platform", "linux")
    logger.info(f"Processing TELEMETRY_RISK for agent '{target_agent_id}' (platform: {platform_name})")

    conns = payload.get("network_connections")
    accepted = await record_sample(session, target_agent_id, "socket", payload, conns)
    if accepted is False:
        return {"status": "ack", "message": "Observation already superseded"} if data.get("wait_ack", True) else None
    flows = []
    if isinstance(conns, list):
        now_dt = datetime.now(timezone.utc)
        for conn in conns[:200]:
            if not isinstance(conn, dict):
                continue
            try:
                source = str(ipaddress.ip_address(conn.get("src_ip") or "0.0.0.0"))
                destination = str(ipaddress.ip_address(conn.get("dst_ip")))
                src_port = int(conn.get("src_port") or 0)
                dst_port = int(conn["dst_port"])
                if not 0 <= src_port <= 65535 or not 0 < dst_port <= 65535:
                    continue
                socket_evidence = None
                if conn.get("attribution") or conn.get("direction") in ("inbound", "outbound"):
                    socket_evidence = {key: conn[key] for key in (
                        "status", "direction", "observed_at", "first_seen", "inode", "socket_id", "holders", "originator_pid",
                        "attribution", "attribution_reason", "interfaces", "overlay", "bytes_sent", "bytes_received",
                    ) if key in conn}
                pid = conn.get("pid")
                flows.append(Flow(
                    id=f"flow_{uuid.uuid4().hex[:12]}", agent_id=target_agent_id,
                    src_ip=source, dst_ip=destination, src_port=src_port, dst_port=dst_port,
                    protocol=str(conn.get("protocol") or "TCP")[:16],
                    bytes_sent=0 if socket_evidence else min(2**31 - 1, max(0, int(conn.get("bytes_sent") or 0))),
                    packets_sent=0 if socket_evidence else min(2**31 - 1, max(0, int(conn.get("packets_sent") or 1))),
                    start_time=now_dt, end_time=now_dt, created_at=now_dt,
                    process_name=str(conn.get("process_name") or conn.get("process") or "unknown")[:128],
                    pid=pid if type(pid) is int and 0 < pid < 2**31 else None, socket_evidence=socket_evidence,
                ))
            except (KeyError, ValueError, TypeError, OverflowError):
                logger.debug("Skipping malformed socket observation for Agent %s", target_agent_id)
        if flows:
            session.add_all(flows)

    try:
        await _evaluate_incident_rules(target_agent_id, payload, session)
    except Exception as e:
        if accepted:
            raise
        logger.error(f"rule_engine hook failed for agent '{target_agent_id}': {e}", exc_info=True)

    risk_service = RiskAssessmentService(session)
    inbound = [row for row in flows if (row.socket_evidence or {}).get("direction") == "inbound"]
    record = await risk_service.process_risk(
        agent_id=target_agent_id,
        data=payload,
        **({"flow_observations": inbound} if inbound else {}),
    )
    logger.info(f"Calculated risk score {record.score} for agent '{target_agent_id}'")
    if data.get("wait_ack", True):
        return {
            "status": "ack",
            "message": "Risk telemetry processed",
            "score": record.score
        }
    return None


async def _handle_flow_stats(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    bytes_sent = int(payload.get("bytes_sent_delta", 0))
    packets_sent = int(payload.get("packets_sent_delta", 0))
    tcp_pkts = int(payload.get("tcp_packets_delta", 0))
    udp_pkts = int(payload.get("udp_packets_delta", 0))
    agent_ip = str(payload.get("ip_address") or "192.168.10.10")
    process_name = payload.get("process_name") or payload.get("process")
    pid = payload.get("pid")
    now_dt = datetime.now(timezone.utc)

    flow_repo = FlowRepository(session)
    if tcp_pkts > 0 or (tcp_pkts == 0 and udp_pkts == 0):
        tcp_bytes = int(bytes_sent * (tcp_pkts / max(1, tcp_pkts + udp_pkts))) if (tcp_pkts + udp_pkts) > 0 else bytes_sent
        flow_tcp = Flow(
            id=f"flow_{uuid.uuid4().hex[:12]}",
            src_ip=agent_ip,
            dst_ip="192.168.10.1",
            src_port=0,
            dst_port=80,
            protocol="TCP",
            bytes_sent=tcp_bytes,
            packets_sent=tcp_pkts or packets_sent,
            start_time=now_dt,
            end_time=now_dt,
            agent_id=target_agent_id,
            created_at=now_dt,
            process_name=process_name,
            pid=pid
        )
        await flow_repo.add(flow_tcp)

    if udp_pkts > 0:
        udp_bytes = int(bytes_sent * (udp_pkts / max(1, tcp_pkts + udp_pkts)))
        flow_udp = Flow(
            id=f"flow_{uuid.uuid4().hex[:12]}",
            src_ip=agent_ip,
            dst_ip="192.168.10.1",
            src_port=0,
            dst_port=53,
            protocol="UDP",
            bytes_sent=udp_bytes,
            packets_sent=udp_pkts,
            start_time=now_dt,
            end_time=now_dt,
            agent_id=target_agent_id,
            created_at=now_dt,
            process_name=process_name,
            pid=pid
        )
        await flow_repo.add(flow_udp)

    flow_items = payload.get("flows") or payload.get("connections") or []
    if isinstance(flow_items, list) and flow_items:
        for flow_data in flow_items:
            f = Flow(
                id=f"flow_{uuid.uuid4().hex[:12]}",
                src_ip=flow_data.get("src_ip") or agent_ip,
                dst_ip=flow_data.get("dst_ip") or "192.168.10.1",
                src_port=int(flow_data.get("src_port") or 0),
                dst_port=int(flow_data.get("dst_port") or 80),
                protocol=flow_data.get("protocol") or "TCP",
                bytes_sent=int(flow_data.get("bytes_sent") or 0),
                packets_sent=int(flow_data.get("packets_sent") or 1),
                start_time=now_dt,
                end_time=now_dt,
                agent_id=target_agent_id,
                created_at=now_dt,
                process_name=flow_data.get("process_name") or flow_data.get("process"),
                pid=flow_data.get("pid")
            )
            await flow_repo.add(f)

    logger.info(f"Recorded FLOW_STATS for agent '{target_agent_id}': {packets_sent} pkts, {bytes_sent} bytes")
    if data.get("wait_ack", True):
        return {"status": "ack", "message": "Flow stats processed"}
    return None


async def _handle_fim_alert(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    file_path = str(payload.get("file_path", ""))
    action = str(payload.get("action", "MODIFIED"))
    now_dt = datetime.now(timezone.utc)

    fim_event = Event(
        id=f"evt_{uuid.uuid4().hex[:12]}",
        agent_id=target_agent_id,
        event_type="FIM_ALERT",
        severity=IncidentSeverity.HIGH,
        source="AGENT_FIM",
        details=payload,
        processed=False,
        created_at=now_dt
    )
    event_repo = EventRepository(session)
    await event_repo.add(fim_event)

    await _evaluate_incident_rules(target_agent_id, {"file_changes": [payload]}, session)

    logger.info(f"Recorded FIM_ALERT for agent '{target_agent_id}' on {file_path} ({action})")
    if data.get("wait_ack", True):
        return {"status": "ack", "message": "FIM alert processed"}
    return None




async def _handle_command_ack(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    dto = CommandAckDTO(**payload)
    from app.models.command import Command
    existing = await session.get(Command, dto.command_id)
    if existing and (existing.agent_id != agent_id or existing.action in network_service.ACTIONS):
        return {"status": "error", "message": "Invalid command acknowledgement"}
    if existing and existing.action in VERIFIED_KILL_COMMANDS and dto.status == CommandStatus.SUCCESS:
        target = (existing.payload or {}).get("pid")
        killed = payload.get("killed_pids")
        if payload.get("validation") != "validated" or not isinstance(killed, list) or target not in killed:
            dto.status = CommandStatus.FAILED
            dto.error_message = "Process validation or verified exit missing from Agent ACK"
    if existing and existing.action in PROTECTED_COMMANDS and existing.status != CommandStatus.SENT:
        return {"status": "ack", "message": "Response command no longer awaiting acknowledgement"}
    cmd = await command_dispatcher.verify_execution(dto, session)
    if not cmd:
        logger.warning(f"Command ack received for unknown command '{dto.command_id}' on agent '{agent_id}'")
        return {"status": "ack", "message": "Command ack recorded (command not found)"}

    target_agent_id = cmd.agent_id or agent_id

    # Find associated ResponseAction
    action = None
    action_id = (cmd.payload or {}).get("action_id")
    if action_id:
        action = await session.get(ResponseAction, action_id)

    if action and (action.agent_id != target_agent_id or (action.action_params or {}).get("command_id") != cmd.id
                   or action.status != "pending"):
        action = None
    now = datetime.now(timezone.utc)
    agent = await session.get(Agent, target_agent_id)

    if dto.status == CommandStatus.SUCCESS:
        if action:
            action.status = "applied"
            action.applied_at = now

            # Merge live ACK results into snapshot (e.g., exported .reg path, quarantine destination)
            backup_file = payload.get("backup_file")
            quarantine_path = payload.get("quarantine_path")
            sha256 = payload.get("sha256")
            if backup_file or quarantine_path or sha256:
                snap = dict(action.snapshot or {})
                if backup_file:
                    snap["backup_file"] = backup_file
                    reg = dict(snap.get("registry") or {})
                    reg["backup_file"] = backup_file
                    snap["registry"] = reg
                if quarantine_path or sha256:
                    if quarantine_path:
                        snap["quarantine_path"] = quarantine_path
                    f_info = dict(snap.get("file") or {})
                    if quarantine_path:
                        f_info["quarantine_path"] = quarantine_path
                    if sha256:
                        f_info["hash_sha256"] = sha256
                    snap["file"] = f_info
                action.snapshot = snap

            audit_svc = ActionAuditLogService(session)
            await audit_svc.record_event(
                action_id=action.id,
                event="applied",
                actor="agent",
                reason=action.action_params.get("reason"),
                metadata={
                    "command_id": cmd.id, "action_type": action.action_type, "incident_id": action.incident_id,
                    "target_pid": (cmd.payload or {}).get("pid"), "validation": payload.get("validation"),
                    "killed_pids": payload.get("killed_pids"), "result": "success", "executed_at": dto.executed_at.isoformat(),
                }
            )
            logger.info(f"ResponseAction '{action.id}' applied upon ACK success for command '{cmd.id}'.")

        if action and action.incident_id and cmd.action in VERIFIED_KILL_COMMANDS:
            incident = (await session.execute(select(Incident).where(
                Incident.id == action.incident_id, Incident.agent_id == target_agent_id,
            ).with_for_update())).scalar_one_or_none()
            evidence = incident.detection_evidence if incident else None
            target = cmd.payload or {}
            process = (evidence or {}).get("process") or {}
            if (process_identity(process) and process_identity(process) == process_identity(target)
                    and process.get("exe_path") == target.get("exe_path")):
                incident.detection_evidence = {**evidence, "containment": {
                    "action_id": action.id, "pid": target["pid"], "process_start_time": target["process_start_time"],
                    "verified_at": now.isoformat(),
                }}
                if incident.status in {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING}:
                    incident.status = IncidentStatus.CONTAINED

        # Update Agent state ONLY when agent successfully confirms
        if agent:
            if cmd.action in ("isolate", "auto_isolate"):
                agent.isolate()
                logger.info(f"Agent '{target_agent_id}' confirmed isolation -> status=ISOLATED, is_isolated=True")
            elif cmd.action == "unisolate":
                agent.unisolate()
                logger.info(f"Agent '{target_agent_id}' confirmed unisolation -> status=ACTIVE, is_isolated=False")
            elif cmd.action == "quarantine":
                agent.status = AgentStatus.QUARANTINE
                logger.info(f"Agent '{target_agent_id}' confirmed quarantine -> status=QUARANTINE")
    else:
        # Command failed on agent
        if action:
            action.status = "failed"
            await ActionAuditLogService(session).record_event(
                action_id=action.id, event="failed", actor="agent", reason=dto.error_message,
                metadata={
                    "command_id": cmd.id, "action_type": action.action_type, "incident_id": action.incident_id,
                    "target_pid": (cmd.payload or {}).get("pid"), "validation": payload.get("validation"),
                    "killed_pids": payload.get("killed_pids"), "result": "failed", "executed_at": dto.executed_at.isoformat(),
                },
            )
            logger.warning(f"ResponseAction '{action.id}' marked failed for command '{cmd.id}': {dto.error_message}")

    await session.flush()
    return {"status": "ack", "message": "Command ack recorded"}


async def _handle_auth_event(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload")
    if not isinstance(payload, dict) or payload.get("agent_id", agent_id) != agent_id:
        return {"status": "error", "message": "Invalid authentication Agent"}
    now = datetime.now(timezone.utc)
    await session.execute(select(Agent.id).where(Agent.id == agent_id).with_for_update())
    raw = payload.get("events")
    raw_events = raw if isinstance(raw, list) else [payload]
    events = []
    seen = set()
    for item in raw_events:
        event = normalize_auth_event(item) if isinstance(item, dict) else None
        if event is None:
            continue
        session_ref = item.get("session_ref")
        if is_enrolled(agent_id) and isinstance(session_ref, str) and re.fullmatch(r"[0-9a-f]{64}", session_ref):
            event["session_ref"] = session_ref
        source_id = item.get("event_id") or event.get("request_id")
        identifier = (
            stable_id("auth_", agent_id, event["service"], source_id)
            if isinstance(source_id, str) and REQUEST_ID.fullmatch(source_id)
            else f"auth_{uuid.uuid4().hex}"
        )
        if identifier in seen:
            continue
        seen.add(identifier)
        stamp = event["timestamp"]
        if stamp is None or stamp > now + timedelta(seconds=30):
            stamp = now
            event["timestamp_source"] = "manager_receipt"
        events.append({**event, "evidence_id": identifier, "timestamp": stamp})
    existing = set()
    identities = sorted(seen)
    for start in range(0, len(identities), 1024):
        existing.update(await session.scalars(
            select(AuthEvent.id).where(AuthEvent.id.in_(identities[start:start + 1024]))
        ))
    fresh = []
    for event in events:
        identifier = event["evidence_id"]
        if identifier in existing:
            continue
        stamp = event["timestamp"]
        session.add(AuthEvent(
            id=identifier, agent_id=agent_id, service=event["service"], source_ip=event["source_ip"],
            username=event["username"], status=event["status"], count=event["count"], timestamp=stamp, created_at=now,
        ))
        properties = {
            key: value for key, value in event.items()
            if key in {"request_id", "request_method", "request_path", "http_status", "user_agent",
                       "payload_indicators", "timestamp_source", "auth_method", "session_ref"} and value is not None
        }
        session.add(Event(
            id=identifier, agent_id=agent_id, event_type="AUTH_OBSERVATION",
            source="AGENT_AUTH", severity=IncidentSeverity.LOW, details=properties, created_at=now,
        ))
        if stamp >= now - timedelta(minutes=5):
            fresh.append(event)
    score = 0.0
    if fresh:
        await session.flush()
        record = await RiskAssessmentService(session).process_risk(
            agent_id=agent_id, data={"auth_events": fresh, "agent_id": agent_id},
            auth_history_before=now,
        )
        score = record.score
    logger.info("Recorded AUTH_EVENT for Agent %s (risk=%s)", agent_id, score)
    return {"status": "ack", "message": "Auth event processed", "score": score} if data.get("wait_ack", True) else None

async def _handle_yara_scan_alert(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    file_path = str(payload.get("file_path", ""))
    matched_rules = payload.get("matched_rules", [])
    now_dt = datetime.now(timezone.utc)

    evt_record = Event(
        id=f"evt_{uuid.uuid4().hex[:12]}",
        agent_id=target_agent_id,
        event_type="YARA_SCAN_ALERT",
        severity=IncidentSeverity.CRITICAL,
        source="AGENT_YARA",
        details=payload,
        processed=False,
        created_at=now_dt
    )
    event_repo = EventRepository(session)
    await event_repo.add(evt_record)

    inc_dto = IncidentCreate(
        id=f"inc_{uuid.uuid4().hex[:12]}",
        title=f"Malware Signature Alert: {', '.join(matched_rules)}",
        description=f"YARA rules {matched_rules} matched file '{file_path}' on agent '{target_agent_id}'. Details: {payload}",
        severity=IncidentSeverity.CRITICAL,
        agent_id=target_agent_id,
        risk_score=95.0,
        notes="Automated critical alert triggered by Agent YARA scanner."
    )
    inc_service = IncidentService(session)
    await inc_service.create_incident(inc_dto)

    risk_service = RiskAssessmentService(session)
    await risk_service.process_risk(
        agent_id=target_agent_id,
        data={"yara_matches": matched_rules, "agent_id": target_agent_id}
    )
    logger.warning(f"CRITICAL: YARA malware match on '{file_path}' for agent '{target_agent_id}'")
    if data.get("wait_ack", True):
        return {"status": "ack", "message": "YARA alert processed"}
    return None


async def _handle_web_access_log(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    if not isinstance(payload, dict) or payload.get("agent_id", agent_id) != agent_id:
        return None
    observation = http_fields(payload)
    if not observation.get("request_method") or not observation.get("request_path"):
        return None
    src_ip = address(payload.get("src_ip") or payload.get("client_ip")) or "unknown"
    host = str(payload.get("host") or "")[:128]
    service = payload.get("service")
    service = service if service == "flask_web" else host or "web"
    now = datetime.now(timezone.utc)
    stamp = observed_time(payload.get("timestamp"))
    time_source = payload.get("timestamp_source")
    time_source = time_source if time_source in ("log", "application", "agent_receipt") else "log"
    if stamp is None or stamp > now + timedelta(seconds=30):
        stamp = now
        time_source = "manager_receipt"
    session_ref = payload.get("session_ref")
    if is_enrolled(agent_id) and isinstance(session_ref, str) and re.fullmatch(r"[0-9a-f]{64}", session_ref):
        observation["session_ref"] = session_ref
    request_id = observation.get("request_id")
    identifier = stable_id("wlog_", agent_id, request_id) if request_id else f"wlog_{uuid.uuid4().hex}"
    await session.execute(select(Agent.id).where(Agent.id == agent_id).with_for_update())
    if request_id and await session.get(WebAccessLog, identifier) is not None:
        return {"status": "ack", "message": "Web access log already recorded"} if data.get("wait_ack") else None
    web_repo = WebAccessLogRepository(session)
    await web_repo.add(WebAccessLog(
        id=identifier, agent_id=agent_id, src_ip=src_ip, host=host,
        method=observation["request_method"], path=observation["request_path"],
        user_agent=observation.get("user_agent"), status_code=observation.get("http_status", 0),
        raw_message=json.dumps({"source": "normalized_http", "service": service, **observation}),
        timestamp=stamp, created_at=now,
    ))
    normalized = {
        **observation, "evidence_id": identifier, "agent_id": agent_id, "src_ip": src_ip,
        "host": host, "service": service, "timestamp": stamp.isoformat(), "timestamp_source": time_source,
        "method": observation["request_method"], "path": observation["request_path"],
    }
    for match in rule_engine.evaluate_web_log(normalized):
        session.add(Event(
            id=f"evt_{uuid.uuid4().hex[:12]}", agent_id=agent_id, event_type="WEB_ATTACK_DETECTED",
            severity=IncidentSeverity(match.severity), source="NDR_WEB_LOG",
            details={**normalized, "rule_id": match.rule_id}, created_at=now,
        ))
    record = await RiskAssessmentService(session).process_risk(
        agent_id=agent_id, data={"agent_id": agent_id, "web_logs": [normalized]}, trusted_web=True,
    )
    logger.info("Recorded WEB_ACCESS_LOG for Agent %s (risk=%s)", agent_id, record.score)
    return {"status": "ack", "message": "Web access log processed", "score": record.score} if data.get("wait_ack", False) else None


MESSAGE_HANDLERS = {
    "HEARTBEAT": _handle_heartbeat,
    "PROCESS_LIST": _handle_process_list,
    "TELEMETRY_RISK": _handle_telemetry_risk,
    "FLOW_STATS": _handle_flow_stats,
    "FIM_ALERT": _handle_fim_alert,
    "COMMAND_ACK": _handle_command_ack,
    "AUTH_EVENT": _handle_auth_event,
    "YARA_SCAN_ALERT": _handle_yara_scan_alert,
    "WEB_ACCESS_LOG": _handle_web_access_log,
}


async def agent_websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for persistent bi-directional communications with agents.
    Receives JSON messages, dispatches to appropriate services, and returns responses or commands.
    """
    agent_id = websocket.query_params.get("agent_id", "unknown")
    enrolled = is_enrolled(agent_id)
    authenticated = enrolled and authenticate_agent(agent_id, websocket.headers.get("x-larp-agent-token"))
    if enrolled and not authenticated:
        await websocket.close(code=1008)
        return
    previous_socket = connection_manager.active_connections.get(agent_id)
    await connection_manager.connect(agent_id, websocket)
    if authenticated:
        connection_manager.authenticated_connections[agent_id] = websocket
    if previous_socket is not None:
        try:
            await previous_socket.close(code=1008)
        except (RuntimeError, WebSocketDisconnect):
            logger.debug("Previous Agent socket already closed")

    try:
        while True:
            raw_text = await websocket.receive_text()
            if connection_manager.active_connections.get(agent_id, websocket) is not websocket:
                break
            if len(raw_text) > 2_000_000 and raw_text.lstrip().startswith('{"type": "NETWORK_'):
                await websocket.close(code=1009)
                break
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON format"})
                continue
            if not isinstance(data, dict) or not isinstance(data.get("payload", {}), dict):
                await websocket.send_json({"error": "Invalid message envelope"})
                continue
            payload = data.get("payload", {})
            claims = [claim for claim in (payload.get("agent_id"), data.get("agent_id")) if claim is not None]
            if any(not isinstance(claim, str) or (authenticated and claim != agent_id)
                   or (agent_id != "unknown" and claim != agent_id)
                   or (not authenticated and is_enrolled(claim)) for claim in claims):
                await websocket.close(code=1008)
                break
            msg_type = str(data.get("type", "")).upper()
            network_message = msg_type in {"NETWORK_SNAPSHOT", "NETWORK_ACK", "NETWORK_TRANSACTION"}
            if network_message and (not authenticated or connection_manager.authenticated_connections.get(agent_id) is not websocket):
                await websocket.close(code=1008)
                break

            response_payload = None
            committed = False
            dashboard_events = []
            new_incident_ids = []
            incident_alerts = []
            async with AsyncSessionLocal() as session:
                context = getattr(session, "info", None)
                if not isinstance(context, dict):
                    context = {}
                context["defer_incident_events"] = True
                try:
                    if msg_type == "NETWORK_SNAPSHOT":
                        await network_service.store_snapshot(session, agent_id, payload)
                    elif msg_type == "NETWORK_ACK":
                        await network_service.acknowledge(session, agent_id, payload)
                    elif msg_type == "NETWORK_TRANSACTION":
                        await network_service.record_transaction(session, agent_id, payload.get("transaction", {}))
                    elif msg_type == "HEARTBEAT":
                        response_payload, heartbeat_id = await _handle_heartbeat(agent_id, data, session)
                        if heartbeat_id != agent_id:
                            connection_manager.disconnect(agent_id)
                            agent_id = heartbeat_id
                            connection_manager.active_connections[agent_id] = websocket
                        if authenticated and response_payload.get("message") != "Agent decommissioned":
                            response_payload["network_command"] = await network_service.pull_network_command(
                                session, agent_id, reported_safety=payload.get("firewall_safety_version")
                            )
                    elif handler := MESSAGE_HANDLERS.get(msg_type):
                        response_payload = await handler(agent_id, data, session)
                    else:
                        response_payload = {"error": f"Unknown message type '{msg_type}'"}
                    await session.commit()
                    committed = True
                    dashboard_events = context.get("dashboard_events", [])
                    new_incident_ids = context.get("new_incident_ids", [])
                    incident_alerts = context.get("incident_alerts", [])
                except (ValidationError, ValueError) as error:
                    await session.rollback()
                    logger.warning("Invalid %s for Agent '%s': %s", msg_type, agent_id, type(error).__name__)
                    if not network_message:
                        response_payload = {"error": "Validation error"}
                except Exception:
                    await session.rollback()
                    logger.exception("Failed to process %s for Agent '%s'", msg_type, agent_id)
                    if not network_message:
                        response_payload = {"error": "Message processing failed"}

            if response_payload:
                await websocket.send_json(response_payload)
            if committed:
                for incident_id in set(new_incident_ids):
                    asyncio.create_task(_run_ai_triage(incident_id))
                for alert in incident_alerts:
                    asyncio.create_task(NotificationService().send_alert(alert))
                for event in dashboard_events:
                    await dashboard_manager.broadcast(event)
                if msg_type in {"TELEMETRY_RISK", "PROCESS_LIST", "COMMAND_ACK", "AUTH_EVENT"}:
                    sample = payload.get("activity_sample")
                    version = sample.get("captured_at") if isinstance(sample, dict) else payload.get("timestamp")
                    await dashboard_manager.broadcast({
                        "type": "ACTIVITY_UPDATED", "agent_id": agent_id, "stream": msg_type, "version": version,
                    })
    except (WebSocketDisconnect, RuntimeError):
        logger.info("Agent '%s' disconnected from WebSocket.", agent_id)
    finally:
        if connection_manager.active_connections.get(agent_id) is websocket:
            connection_manager.disconnect(agent_id)
        if connection_manager.authenticated_connections.get(agent_id) is websocket:
            connection_manager.authenticated_connections.pop(agent_id, None)
