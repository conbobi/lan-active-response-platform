from datetime import datetime, timedelta
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_session
from app.core.network_security import authenticate_agent, is_enrolled, require_network_admin, require_network_read
from app.models.agent import Agent
from app.models.command import Command
from app.models.network_snapshot import NetworkSnapshot
from app.repositories.network_repository import NetworkRepository
from app.schemas.network import FirewallRequest, NetworkQueued, NetworkView
from app.services.agent import network_service, ssh_probe
from app.websocket.connection_manager import connection_manager

router = APIRouter(prefix="/network", tags=["network"])

@router.get("/suspicious")
async def suspicious_connections(
    agent: Optional[str] = Query(None),
    time: str = Query("1h", pattern="^(1h|24h|7d)$"),
    risk: Optional[str] = Query(None, pattern="^(high|medium|low)$"),
    limit: int = Query(50, le=200),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    repo = NetworkRepository(session)
    return await repo.get_suspicious(
        agent_id=agent, time_range=time, risk=risk, limit=limit
    )

@router.get("/top-talkers")
async def top_talkers(
    agent: Optional[str] = Query(None),
    time: str = Query("1h", pattern="^(1h|24h|7d)$"),
    limit: int = Query(10, le=50),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    repo = NetworkRepository(session)
    return await repo.get_top_talkers(agent_id=agent, time_range=time, limit=limit)

@router.get("/protocols")
async def protocols(
    agent: Optional[str] = Query(None),
    time: str = Query("1h", pattern="^(1h|24h|7d)$"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    repo = NetworkRepository(session)
    return await repo.get_protocols(agent_id=agent, time_range=time)

@router.get("/{flow_id}")
async def flow_detail(
    flow_id: str,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    repo = NetworkRepository(session)
    flow = await repo.get_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return {
        'id': flow.id,
        'process_name': flow.process_name or 'unknown',
        'pid': flow.pid,
        'src_ip': flow.src_ip,
        'src_port': flow.src_port,
        'dst_ip': flow.dst_ip,
        'dst_port': flow.dst_port,
        'protocol': flow.protocol,
        'agent_id': flow.agent_id,
        'bytes_sent': flow.bytes_sent,
        'packets_sent': flow.packets_sent,
        'created_at': flow.created_at.isoformat() if flow.created_at else None,
    }


def _network_online(agent_id):
    return agent_id in connection_manager.authenticated_connections


@router.get("/agents/{agent_id}/probe", status_code=204, include_in_schema=False)
async def network_probe(agent_id: str, x_larp_agent_token: str | None = Header(None)):
    if not authenticate_agent(agent_id, x_larp_agent_token):
        raise HTTPException(401, "Valid Agent credential required")
    return Response(status_code=204)


@router.get("/agents/{agent_id}/ssh-probe", include_in_schema=False)
async def network_ssh_probe(agent_id: str, x_larp_agent_token: str | None = Header(None)):
    if not authenticate_agent(agent_id, x_larp_agent_token):
        raise HTTPException(401, "Valid Agent credential required")
    if not _network_online(agent_id):
        raise HTTPException(503, "Authenticated Agent WebSocket is disconnected")
    try:
        result = await ssh_probe.verify(agent_id)
    except (RuntimeError, OSError):
        raise HTTPException(503, "External SSH verification failed") from None
    if not _network_online(agent_id):
        raise HTTPException(503, "Authenticated Agent WebSocket is disconnected")
    return result


@router.get("/agents/{agent_id}/commands/{command_id}")
async def network_command_status(agent_id: str, command_id: str, session=Depends(get_session),
                                 _operator=Depends(require_network_read)):
    await network_service.expire_commands(session, agent_id)
    command = await session.get(Command, command_id)
    if not command or command.agent_id != agent_id or command.action not in network_service.ACTIONS:
        raise HTTPException(404, "Network command not found")
    return {"command_id": command.id, "status": command.status.value, "error": command.error_message,
            "executed_at": command.executed_at}


@router.post("/agents/{agent_id}/refresh", response_model=NetworkQueued, status_code=202)
async def refresh_agent_network(agent_id: str, session=Depends(get_session), operator=Depends(require_network_read)):
    if not _network_online(agent_id):
        raise HTTPException(409, "Agent is offline or is not enrolled for network telemetry")
    return await network_service.queue_command(session, agent_id, operator[0])


@router.post("/agents/{agent_id}/firewall/actions", response_model=NetworkQueued, status_code=202)
async def firewall_action(agent_id: str, request: FirewallRequest, session=Depends(get_session),
                          operator=Depends(require_network_admin)):
    if not _network_online(agent_id):
        raise HTTPException(409, "Agent is offline or is not enrolled for network telemetry")
    if request.operation == "set_policy":
        raise HTTPException(409, "Default policy changes require local administration")
    if request.operation != "rollback" and (not settings.NETWORK_LEGACY_ADMIN_TOKEN or not ssh_probe.configured(agent_id)):
        raise HTTPException(503, "Protected administrative APIs and an external SSH verifier are required")
    return await network_service.queue_command(session, agent_id, operator[0], request.model_dump(exclude_none=True))


@router.get("/agents/{agent_id}/{section}", response_model=NetworkView)
@router.get("/agents/{agent_id}/firewall/{section}", response_model=NetworkView, include_in_schema=False)
async def network_section(
    agent_id: str,
    section: Literal["overview", "firewall", "ports", "connections", "interfaces", "routes", "policy",
                     "neighbors", "nat", "events", "audit", "groups"],
    session=Depends(get_session),
    operator=Depends(require_network_read),
    offset: int = Query(0, ge=0, le=5000),
    limit: int = Query(50, ge=1, le=200),
    q: str = Query("", max_length=128),
    protocol: Literal["TCP", "UDP"] | None = None,
    state: str = Query("", max_length=24),
    direction: Literal["inbound", "outbound", "unknown"] | None = None,
    remote_ip: str = Query("", max_length=64),
    port: int | None = Query(None, ge=1, le=65535),
    process: str = Query("", max_length=128),
):
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")
    online = _network_online(agent_id)
    snapshot = await session.get(NetworkSnapshot, agent_id)
    payload = snapshot.payload if snapshot else {}
    stale = not snapshot or network_service.now() - network_service.utc(snapshot.received_at) > timedelta(seconds=90)
    status = payload.get("status", "unavailable" if is_enrolled(agent_id) else "unenrolled")
    collected_at = payload.get("collected_at")
    data = {}
    if section == "audit":
        await network_service.expire_commands(session, agent_id)
        data = await network_service.audit_history(session, agent_id, offset, limit)
    elif payload:
        key = "connections" if section == "groups" else section
        data = dict(payload["sections"].get(key, {}))
        collected_at = data.get("collected_at", collected_at)
        if isinstance(collected_at, str):
            try:
                maximum_age = 170 if section in {"interfaces", "routes", "policy", "neighbors", "nat", "firewall"} else 90
                stale = stale or network_service.now() - network_service.utc(datetime.fromisoformat(collected_at)) > timedelta(seconds=maximum_age)
            except ValueError:
                stale = True
        if section == "firewall":
            data["controls_configured"] = bool(data.get("controls_configured") and data.get("safety_version") == 2
                                                and settings.NETWORK_LEGACY_ADMIN_TOKEN and ssh_probe.configured(agent_id))
            for key in ("rules", "kernel_rules"):
                data[key] = data.get(key, [])[:500]
        if section in {"groups", "connections", "ports", "events", "interfaces", "routes", "policy", "neighbors", "nat"}:
            rows = data.pop("groups", []) if section == "groups" else data.get("rows", [])
            data.pop("groups", None)
            data.pop("rows", None)
            def matches(row):
                if protocol and str(row.get("protocol", "")).upper() != protocol:
                    return False
                if state and row.get("status", "").lower() != state.lower():
                    return False
                if direction and row.get("direction") != direction:
                    return False
                if remote_ip and row.get("dst_ip", row.get("remote_ip")) != remote_ip:
                    return False
                if port and port not in (row.get("src_port"), row.get("dst_port")):
                    return False
                if process and process.casefold() not in str(row.get("process_name", "")).casefold():
                    return False
                return not q or q.casefold() in str(row).casefold()
            matched = [row for row in rows if matches(row)]
            page = matched[offset:offset + limit]
            if section in {"groups", "connections"}:
                page = await network_service.add_context(session, agent_id, page, groups=section == "groups")
            data.update(rows=page, matched=len(matched))
    return {"agent_id": agent_id, "online": online, "stale": stale, "status": status, "role": operator[1].role,
            "snapshot_id": payload.get("snapshot_id"), "collected_at": collected_at, "data": data}
