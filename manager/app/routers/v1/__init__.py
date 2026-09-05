from fastapi import APIRouter

from app.routers.v1.agent_router import router as agent_router
from app.routers.v1.flow_router import router as flow_router
from app.routers.v1.command_router import router as command_router
from app.routers.v1.incident_router import router as incident_router
from app.routers.v1.rule_router import router as rule_router
from app.routers.v1.topology_router import router as topology_router
from app.routers.v1.path_router import router as path_router
from app.routers.v1.event_router import router as event_router
from app.routers.v1.attack_router import router as attack_router
from app.routers.v1.notification_router import router as notification_router
from app.routers.v1.report_router import router as report_router
from app.routers.v1.whitelist_router import router as whitelist_router
from app.routers.v1.risk_router import router as risk_router
from app.routers.v1.threat_intel_router import router as threat_intel_router
from app.routers.v1.process_router import router as process_router
from app.routers.v1.setting_router import router as setting_router
from app.routers.v1.docker_router import router as docker_router
from app.routers.v1.process_group_router import router as process_group_router
from app.routers.v1.process_chain_rule_router import router as process_chain_rule_router

api_router = APIRouter()

api_router.include_router(agent_router, prefix="/agents", tags=["Agents"])
api_router.include_router(flow_router, prefix="/flows", tags=["Flows"])
api_router.include_router(command_router, prefix="/commands", tags=["Commands"])
api_router.include_router(incident_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(rule_router, prefix="/rules", tags=["Rules"])
api_router.include_router(topology_router, prefix="/topology", tags=["Topology"])
api_router.include_router(path_router, prefix="/path", tags=["Pathfinding"])
api_router.include_router(event_router, prefix="/events", tags=["Event"])
api_router.include_router(attack_router, prefix="/attack", tags=["Attack"])
api_router.include_router(notification_router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(report_router, prefix="/reports", tags=["Reports"])
api_router.include_router(whitelist_router, prefix="/whitelist", tags=["Whitelist"])
api_router.include_router(risk_router, prefix="/risk", tags=["Risk Assessment"])
api_router.include_router(threat_intel_router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(process_router, prefix="/process", tags=["Process & Root Cause Analysis"])
api_router.include_router(setting_router, prefix="/settings", tags=["Settings"])
api_router.include_router(docker_router, prefix="/docker", tags=["Docker Monitor"])
api_router.include_router(process_group_router, prefix="/process-groups", tags=["Process Groups"])
api_router.include_router(process_chain_rule_router, prefix="/process-chain-rules", tags=["Process Chain Rules"])

__all__ = ["api_router"]

