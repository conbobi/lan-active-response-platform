import json
import uuid
import logging
from datetime import datetime, timezone
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from app.websocket.connection_manager import connection_manager
from app.schemas.heartbeat import HeartbeatDTO
from app.schemas.topology import TopologyUpdateDTO
from app.schemas.path_release import PathReleaseDTO
from app.schemas.command_ack import CommandAckDTO
from app.services.topology_service import topology_facade
from app.services.command_dispatcher import command_dispatcher
from app.services.risk_assessment_service import RiskAssessmentService
from app.models.process_info import ProcessInfo
from app.repositories.process_info_repository import ProcessInfoRepository
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


async def _save_process_list(session, target_agent_id: str, processes_data: list) -> int:
    if not processes_data or not isinstance(processes_data, list):
        return 0
    proc_repo = ProcessInfoRepository(session)
    await proc_repo.delete_by_agent(target_agent_id)
    now_dt = datetime.now(timezone.utc)
    count = 0
    for proc_item in processes_data:
        pid = proc_item.get("pid")
        if not pid:
            continue
        ppid_val = proc_item.get("parent_pid") if proc_item.get("parent_pid") is not None else proc_item.get("ppid")
        pinfo = ProcessInfo(
            id=f"proc_{uuid.uuid4().hex[:12]}",
            agent_id=target_agent_id,
            pid=int(pid),
            parent_pid=int(ppid_val) if ppid_val is not None else None,
            name=str(proc_item.get("name") or "unknown"),
            exe=str(proc_item.get("exe") or proc_item.get("path") or ""),
            exe_path=str(proc_item.get("exe_path") or proc_item.get("exe") or proc_item.get("path") or ""),
            cmdline=str(proc_item.get("cmdline") or ""),
            cpu_percent=float(proc_item.get("cpu_percent") or proc_item.get("cpu") or 0.0),
            memory_percent=float(proc_item.get("memory_percent") or proc_item.get("ram") or 0.0),
            is_suspicious=bool(proc_item.get("is_suspicious", False)),
            created_at=now_dt
        )
        await proc_repo.add(pinfo)
        count += 1
    return count


async def agent_websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for persistent bi-directional communications with agents.
    Receives JSON messages, dispatches to appropriate services, and returns responses or commands.
    """
    # Extract agent_id from query params e.g. /ws/agent?agent_id=agent-123
    agent_id = websocket.query_params.get("agent_id", "unknown")
    await connection_manager.connect(agent_id, websocket)

    try:
        while True:
            try:
                raw_text = await websocket.receive_text()
                
            except Exception as e:
                logger.warning(f"WebSocket receive error: {e}")
                break
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON format"})
                continue

            msg_type = data.get("type", "").upper()
            async with AsyncSessionLocal() as session:
                try:
                    response_payload = None

                    if msg_type == "HEARTBEAT":
                        dto = HeartbeatDTO(**data.get("payload", {}))
                        agent_id = dto.agent_id
                        await topology_facade.process_heartbeat(dto, session)
                        # Check for pending commands to attach to heartbeat ack
                        pending_cmds = await command_dispatcher.pull_pending_commands(agent_id, session)
                        response_payload = {
                            "status": "ack",
                            "message": "Heartbeat processed",
                            "pending_commands": [
                                {"command_id": c.id, "action": c.action, "payload": c.payload}
                                for c in pending_cmds
                            ]
                        }

                    elif msg_type == "PROCESS_LIST":
                        payload = data.get("payload", {})
                        target_agent_id = payload.get("agent_id", agent_id)
                        procs_data = payload.get("processes", [])
                        saved_count = await _save_process_list(session, target_agent_id, procs_data)
                        logger.info(f"Saved {saved_count} processes for agent '{target_agent_id}' via PROCESS_LIST")
                        response_payload = {
                            "status": "ack",
                            "message": "Process list stored successfully",
                            "count": saved_count
                        }

                    elif msg_type == "TELEMETRY_RISK":
                        payload = data.get("payload", {})
                        target_agent_id = payload.get("agent_id", agent_id)
                        logger.info(f"Processing TELEMETRY_RISK for agent '{target_agent_id}'")
                        
                        # Store process telemetry into ProcessInfo table if process_list provided
                        procs_data = payload.get("process_list") or payload.get("processes")
                        if procs_data:
                            await _save_process_list(session, target_agent_id, procs_data)

                        risk_service = RiskAssessmentService(session)
                        record = await risk_service.process_risk(
                            agent_id=target_agent_id,
                            data=payload
                        )
                        logger.info(f"Calculated risk score {record.score} for agent '{target_agent_id}'")
                        response_payload = {
                            "status": "ack",
                            "message": "Risk telemetry processed",
                            "score": record.score,
                            "record_id": record.id
                        }

                    elif msg_type == "TOPOLOGY_UPDATE":
                        dto = TopologyUpdateDTO(**data.get("payload", {}))
                        await topology_facade.handle_topology_update(dto, session)
                        response_payload = {"status": "ack", "message": "Topology update processed"}

                    elif msg_type == "PATH_RELEASE":
                        dto = PathReleaseDTO(**data.get("payload", {}))
                        released = await topology_facade.release_path(dto, session)
                        response_payload = {"status": "ack", "released": released}

                    elif msg_type == "COMMAND_ACK":
                        dto = CommandAckDTO(**data.get("payload", {}))
                        await command_dispatcher.verify_execution(dto, session)
                        response_payload = {"status": "ack", "message": "Command ack recorded"}

                    else:
                        response_payload = {"error": f"Unknown message type '{msg_type}'"}

                    await session.commit()
                    if response_payload:
                        await websocket.send_json(response_payload)
                    logger.info(f"Successfully processed WS msg '{msg_type}' for agent '{agent_id}'")
                except ValidationError as ve:
                    await session.rollback()
                    logger.error(f"WebSocket validation error: {ve}")
                    await websocket.send_json({"error": "Validation error", "details": ve.errors()})
                except Exception as e:
                    await session.rollback()
                    logger.error(f"Error processing WS message: {e}", exc_info=True)
                    await websocket.send_json({"error": str(e)})

    except WebSocketDisconnect:
        connection_manager.disconnect(agent_id)
        logger.info(f"Agent '{agent_id}' disconnected from WebSocket.")
