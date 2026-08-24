import json
import logging
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
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


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
            raw_text = await websocket.receive_text()
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

                    elif msg_type == "TELEMETRY_RISK":
                        risk_service = RiskAssessmentService(session)
                        payload = data.get("payload", {})
                        target_agent_id = payload.get("agent_id", agent_id)
                        record = await risk_service.process_risk(
                            agent_id=target_agent_id,
                            data=payload
                        )
                        response_payload = {
                            "status": "ack",
                            "message": "Risk telemetry processed",
                            "score": record.score
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
