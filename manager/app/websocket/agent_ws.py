import asyncio
import json
import uuid
import logging
from datetime import datetime, timezone
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
from app.schemas.command_ack import CommandAckDTO
from app.services.agent.agent_service import AgentService
from app.services.core.command_dispatcher import command_dispatcher
from app.services.detection.risk_assessment_service import RiskAssessmentService
from app.services.detection.risk_rules.brute_force_rule import normalize_auth_event
from app.models.process_info import ProcessInfo
from app.repositories.process_info_repository import ProcessInfoRepository
from app.models.flow import Flow
from app.repositories.flow_repository import FlowRepository
from app.models.event import Event
from app.repositories.event_repository import EventRepository
from app.models.agent import Agent
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.enums import IncidentSeverity, AgentStatus, CommandStatus
from app.services.common.audit_log_service import ActionAuditLogService
from app.schemas.incident import IncidentCreate
from app.services.incident.incident_service import IncidentService
from app.models.auth_event import AuthEvent
from app.repositories.auth_event_repository import AuthEventRepository
from app.models.web_access_log import WebAccessLog
from app.repositories.web_access_log_repository import WebAccessLogRepository
from app.core.database import AsyncSessionLocal
from app.core.network_security import authenticate_agent, is_enrolled
from app.services.agent import network_service

logger = logging.getLogger(__name__)


async def _save_process_list(session: AsyncSession, target_agent_id: str, 
                              processes_data: list) -> int:
    """Save process list with truncation + per-process savepoints."""
    if not processes_data or not isinstance(processes_data, list):
        return 0
    
    proc_repo = ProcessInfoRepository(session)
    await proc_repo.delete_by_agent(target_agent_id)
    await session.flush()
    
    now_dt = datetime.now(timezone.utc)
    count = 0
    skipped = 0
    
    def safe_str(val, max_len: int, default: str = "") -> str:
        """Truncate string to model max length."""
        if val is None:
            return default
        s = str(val)
        return s[:max_len] if len(s) > max_len else s
    
    def safe_int(val, default=None):
        try:
            return int(val) if val is not None else default
        except (ValueError, TypeError):
            return default
    
    def safe_float(val, default=0.0):
        try:
            return float(val) if val is not None else default
        except (ValueError, TypeError):
            return default
    
    for proc_item in processes_data:
        # Skip invalid pid
        pid = safe_int(proc_item.get("pid"))
        if pid is None or pid < 0:
            skipped += 1
            continue
        
        try:
            parent_pid = safe_int(
                proc_item.get("parent_pid") 
                if proc_item.get("parent_pid") is not None 
                else proc_item.get("ppid")
            )
            
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
            
            # ✅ Savepoint per process — nếu fail, chỉ rollback process đó
            async with session.begin_nested():
                await proc_repo.add(pinfo)
            count += 1
            
        except Exception as e:
            logger.warning(
                f"[PROCESS_LIST] Skip pid={proc_item.get('pid')} "
                f"name={proc_item.get('name')}: {type(e).__name__}: {e}"
            )
            skipped += 1
            continue
    
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
    await agent_svc.process_heartbeat(dto)
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

                service = AITriageService()
                logger.info(f"Executing analyze_incident for {incident_id}...")
                analysis = await service.analyze_incident(incident_id, session)
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

    for incident in incidents:
        asyncio.create_task(_run_ai_triage(incident.id))
    await dashboard_manager.broadcast({
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
    })


async def _handle_process_list(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    procs_data = payload.get("processes", [])
    saved_count = await _save_process_list(session, target_agent_id, procs_data)
    logger.info(f"Saved {saved_count} processes for agent '{target_agent_id}' via PROCESS_LIST")

    try:
        await _evaluate_incident_rules(target_agent_id, payload, session)
    except Exception as e:
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
    platform_name = payload.get("platform", "linux")
    logger.info(f"Processing TELEMETRY_RISK for agent '{target_agent_id}' (platform: {platform_name})")

    # Record network connections into flows table with process info
    conns = payload.get("network_connections", [])
    if isinstance(conns, list) and conns:
        try:
            flow_repo = FlowRepository(session)
            now_dt = datetime.now(timezone.utc)
            for c in conns:
                dst_ip = c.get("dst_ip")
                dst_port = c.get("dst_port")
                if dst_ip and dst_port:
                    conn_flow = Flow(
                        id=f"flow_{uuid.uuid4().hex[:12]}",
                        src_ip=c.get("src_ip") or "0.0.0.0",
                        dst_ip=str(dst_ip),
                        src_port=int(c.get("src_port") or 0),
                        dst_port=int(dst_port),
                        protocol=c.get("protocol") or "TCP",
                        bytes_sent=int(c.get("bytes_sent") or 0),
                        packets_sent=int(c.get("packets_sent") or 1),
                        start_time=now_dt,
                        end_time=now_dt,
                        agent_id=target_agent_id,
                        created_at=now_dt,
                        process_name=c.get("process_name") or c.get("process"),
                        pid=c.get("pid")
                    )
                    await flow_repo.add(conn_flow)
        except Exception as e:
            logger.warning(f"Failed to record network connections from telemetry: {e}")

    try:
        await _evaluate_incident_rules(target_agent_id, payload, session)
    except Exception as e:
        logger.error(f"rule_engine hook failed for agent '{target_agent_id}': {e}", exc_info=True)

    risk_service = RiskAssessmentService(session)
    record = await risk_service.process_risk(
        agent_id=target_agent_id,
        data=payload
    )
    if hasattr(record, "incident") and record.incident:
        logger.info(f"Hook: Triggering AI Triage for {record.incident.id}")
        asyncio.create_task(_run_ai_triage(record.incident.id))
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

    if not action:
        # Fallback: find latest pending ResponseAction for this agent with matching action_type
        stmt = (
            select(ResponseAction)
            .where(
                ResponseAction.agent_id == target_agent_id,
                ResponseAction.action_type == cmd.action,
                ResponseAction.status == "pending"
            )
            .order_by(ResponseAction.created_at.desc())
            .limit(1)
        )
        res = await session.execute(stmt)
        action = res.scalar_one_or_none()

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
                metadata={"command_id": cmd.id, "action_type": action.action_type}
            )
            logger.info(f"ResponseAction '{action.id}' applied upon ACK success for command '{cmd.id}'.")

        # Update Agent state ONLY when agent successfully confirms
        if agent:
            if cmd.action in ("isolate", "auto_isolate"):
                agent.isolate()
                logger.info(f"Agent '{target_agent_id}' confirmed isolation -> status=ISOLATED, is_isolated=True")
            elif cmd.action == "unisolate":
                agent.unisolate()
                logger.info(f"Agent '{target_agent_id}' confirmed unisolation -> status=ACTIVE, is_isolated=False")
                from app.repositories.incident_repository import IncidentRepository
                inc_repo = IncidentRepository(session)
                resolved_incidents = await inc_repo.resolve_active_incidents_for_agent(
                    target_agent_id,
                    resolved_reason="Auto-resolved upon agent unisolation confirmed by agent"
                )
                if resolved_incidents:
                    logger.info(f"Auto-resolved {len(resolved_incidents)} incidents for agent '{target_agent_id}' after unisolation")
                    try:
                        from app.websocket.dashboard_connection_manager import dashboard_manager
                        await dashboard_manager.broadcast({
                            "type": "INCIDENTS_RESOLVED",
                            "event": "INCIDENTS_RESOLVED",
                            "agent_id": target_agent_id,
                            "incident_ids": [i.id for i in resolved_incidents],
                            "action": "unisolate"
                        })
                    except Exception as e:
                        logger.warning(f"Failed to broadcast unisolation incident resolution to dashboard: {e}")
            elif cmd.action == "quarantine":
                agent.status = AgentStatus.QUARANTINE
                logger.info(f"Agent '{target_agent_id}' confirmed quarantine -> status=QUARANTINE")
    else:
        # Command failed on agent
        if action:
            action.status = "failed"
            logger.warning(f"ResponseAction '{action.id}' marked failed for command '{cmd.id}': {dto.error_message}")

    await session.flush()
    return {"status": "ack", "message": "Command ack recorded"}


async def _handle_auth_event(agent_id: str, data: dict, session: AsyncSession) -> Optional[dict]:
    payload = data.get("payload", {})
    target_agent_id = payload.get("agent_id", agent_id)
    now_dt = datetime.now(timezone.utc)
    auth_repo = AuthEventRepository(session)

    raw_events = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
    events_list = []
    for raw_event in raw_events:
        evt = normalize_auth_event(raw_event) if isinstance(raw_event, dict) else None
        if evt is None:
            continue
        events_list.append(evt)
        auth_record = AuthEvent(
            id=f"auth_{uuid.uuid4().hex[:12]}",
            agent_id=target_agent_id,
            service=evt["service"],
            source_ip=evt["source_ip"],
            username=evt["username"],
            status=evt["status"],
            count=evt["count"],
            timestamp=now_dt,
            created_at=now_dt
        )
        await auth_repo.add(auth_record)

    score = 0.0
    if events_list:
        record = await RiskAssessmentService(session).process_risk(
            agent_id=target_agent_id,
            data={"auth_events": events_list, "agent_id": target_agent_id},
            auth_history_before=now_dt,
        )
        score = record.score
    logger.info(f"Recorded AUTH_EVENT for agent '{target_agent_id}' (risk: {score})")
    if data.get("wait_ack", True):
        return {"status": "ack", "message": "Auth event processed", "score": score}
    return None


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
    if not isinstance(payload, dict):
        return None

    target_agent_id = payload.get("agent_id", agent_id)
    src_ip = str(payload.get("src_ip") or payload.get("client_ip") or "unknown")[:64]
    host = str(payload.get("host") or "")[:128]
    method = str(payload.get("method") or payload.get("http_method") or "GET").upper()[:16]
    path = str(payload.get("path") or payload.get("url") or "/")[:1024]
    user_agent = str(payload.get("user_agent") or "")[:512]

    try:
        status_code = int(payload.get("status_code") or payload.get("status") or 200)
    except (ValueError, TypeError):
        status_code = 200

    raw_message = str(payload.get("raw_message") or payload.get("raw_log") or "")

    # Parse timestamp
    now_dt = datetime.now(timezone.utc)
    ts_val = payload.get("timestamp")
    if ts_val:
        try:
            if isinstance(ts_val, (int, float)):
                ts_dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            elif isinstance(ts_val, str):
                ts_dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            else:
                ts_dt = now_dt
        except Exception:
            ts_dt = now_dt
    else:
        ts_dt = now_dt

    # 1. Persist to database
    web_repo = WebAccessLogRepository(session)
    log_record = WebAccessLog(
        id=f"wlog_{uuid.uuid4().hex[:12]}",
        agent_id=target_agent_id,
        src_ip=src_ip,
        host=host,
        method=method,
        path=path,
        user_agent=user_agent,
        status_code=status_code,
        raw_message=raw_message,
        timestamp=ts_dt,
        created_at=now_dt
    )
    await web_repo.add(log_record)

    # 2. Evaluate single log with rule engine
    normalized_log = {
        "agent_id": target_agent_id,
        "src_ip": src_ip,
        "host": host,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "status_code": status_code,
        "raw_message": raw_message,
        "timestamp": ts_dt.isoformat()
    }
    matches = rule_engine.evaluate_web_log(normalized_log)
    if matches:
        event_repo = EventRepository(session)
        sev_map = {
            "low": IncidentSeverity.LOW,
            "medium": IncidentSeverity.MEDIUM,
            "high": IncidentSeverity.HIGH,
            "critical": IncidentSeverity.CRITICAL,
        }
        for m in matches:
            evt_record = Event(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                agent_id=target_agent_id,
                event_type="WEB_ATTACK_DETECTED",
                severity=sev_map.get(m.severity.lower(), IncidentSeverity.HIGH),
                source="NDR_WEB_LOG",
                details={**normalized_log, "rule_id": m.rule_id, "detail": m.detail},
                processed=False,
                created_at=now_dt
            )
            await event_repo.add(evt_record)

    # 3. Trigger Risk Assessment & AI Triage
    risk_service = RiskAssessmentService(session)
    telemetry = {
        "agent_id": target_agent_id,
        "web_log": normalized_log,
        "web_logs": [normalized_log]
    }
    rec = await risk_service.process_risk(agent_id=target_agent_id, data=telemetry)
    if hasattr(rec, "incident") and rec.incident:
        logger.info(f"Hook: Triggering AI Triage for web attack incident {rec.incident.id}")
        asyncio.create_task(_run_ai_triage(rec.incident.id))

    logger.info(f"Recorded WEB_ACCESS_LOG for agent '{target_agent_id}' from {src_ip} {method} {path} (risk: {rec.score if rec else 0.0})")
    if data.get("wait_ack", False):
        return {"status": "ack", "message": "Web access log processed", "score": rec.score if rec else 0.0}
    return None


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
    await connection_manager.connect(agent_id, websocket)
    if authenticated:
        previous = connection_manager.authenticated_connections.get(agent_id)
        connection_manager.authenticated_connections[agent_id] = websocket
        if previous is not None:
            try:
                await previous.close(code=1008)
            except (RuntimeError, WebSocketDisconnect):
                logger.debug("Previous Agent socket already closed")

    try:
        while True:
            raw_text = await websocket.receive_text()
            if authenticated and connection_manager.authenticated_connections.get(agent_id) is not websocket:
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
                   or (not authenticated and is_enrolled(claim)) for claim in claims):
                await websocket.close(code=1008)
                break
            msg_type = str(data.get("type", "")).upper()
            network_message = msg_type in {"NETWORK_SNAPSHOT", "NETWORK_ACK", "NETWORK_TRANSACTION"}
            if network_message and (not authenticated or connection_manager.authenticated_connections.get(agent_id) is not websocket):
                await websocket.close(code=1008)
                break

            async with AsyncSessionLocal() as session:
                try:
                    if msg_type == "NETWORK_SNAPSHOT":
                        await network_service.store_snapshot(session, agent_id, payload)
                        response_payload = None
                    elif msg_type == "NETWORK_ACK":
                        await network_service.acknowledge(session, agent_id, payload)
                        response_payload = None
                    elif msg_type == "NETWORK_TRANSACTION":
                        await network_service.record_transaction(session, agent_id, payload.get("transaction", {}))
                        response_payload = None
                    elif msg_type == "HEARTBEAT":
                        response_payload, agent_id = await _handle_heartbeat(agent_id, data, session)
                        if authenticated:
                            response_payload["network_command"] = await network_service.pull_network_command(session, agent_id)
                    elif handler := MESSAGE_HANDLERS.get(msg_type):
                        response_payload = await handler(agent_id, data, session)
                    else:
                        response_payload = {"error": f"Unknown message type '{msg_type}'"}
                    await session.commit()
                    if response_payload:
                        await websocket.send_json(response_payload)
                except (ValidationError, ValueError) as error:
                    await session.rollback()
                    logger.warning("Invalid %s for Agent '%s': %s", msg_type, agent_id, type(error).__name__)
                    if not network_message:
                        await websocket.send_json({"error": "Validation error"})
                except Exception:
                    await session.rollback()
                    logger.exception("Failed to process %s for Agent '%s'", msg_type, agent_id)
                    if not network_message:
                        await websocket.send_json({"error": "Message processing failed"})
    except (WebSocketDisconnect, RuntimeError):
        logger.info("Agent '%s' disconnected from WebSocket.", agent_id)
    finally:
        if connection_manager.active_connections.get(agent_id) is websocket:
            connection_manager.disconnect(agent_id)
        if connection_manager.authenticated_connections.get(agent_id) is websocket:
            connection_manager.authenticated_connections.pop(agent_id, None)
