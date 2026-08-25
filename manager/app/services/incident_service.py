import uuid
import logging
from typing import List, Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.command import Command
from app.repositories.incident_repository import IncidentRepository
from app.repositories.command_repository import CommandRepository
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.schemas.enums import IncidentSeverity, IncidentStatus, CommandStatus
from app.core.exceptions import NotFoundError, BadRequestError
from app.services.base import AbstractService
from app.services.command_dispatcher import command_dispatcher
from app.services.notification_service import NotificationService

logger = logging.getLogger(__name__)


class IncidentService(AbstractService[IncidentRepository]):
    def __init__(self, session: AsyncSession):
        repo = IncidentRepository(session)
        super().__init__(repository=repo)
        self.session = session
        self.notification_service = NotificationService()

    async def create_incident(self, dto: IncidentCreate) -> Incident:
        inc = Incident(
            id=dto.id,
            title=dto.title,
            description=dto.description,
            severity=dto.severity,
            agent_id=dto.agent_id,
            assigned_to=dto.assigned_to,
            risk_score=dto.risk_score,
            notes=dto.notes
        )
        created = await self.repository.add(inc)
        await self.add_note(created.id, f"Incident created manually with severity {dto.severity}.", user="system")
        return created

    async def create_from_risk(
        self,
        agent_id: str,
        risk_score: float,
        factors: Dict[str, Any]
    ) -> Incident:
        """Automated incident creation triggered by high risk score (> 50). Deduplicates active incidents for agent."""
        # Check if active (OPEN/INVESTIGATING/CONTAINED) incident exists for agent
        stmt = (
            select(Incident)
            .where(
                Incident.agent_id == agent_id,
                Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED])
            )
            .order_by(Incident.created_at.desc())
        )
        result = await self.session.execute(stmt)
        existing = result.scalars().first()

        severity = IncidentSeverity.CRITICAL if risk_score >= 85.0 else (
            IncidentSeverity.HIGH if risk_score >= 70.0 else IncidentSeverity.MEDIUM
        )

        if existing:
            existing.risk_score = max(existing.risk_score, risk_score)
            if severity == IncidentSeverity.CRITICAL and existing.severity != IncidentSeverity.CRITICAL:
                existing.severity = IncidentSeverity.CRITICAL
            existing.description += f"\n\n[Auto Update] Additional Risk Telemetry Spike: Score {risk_score}. Factors: {factors}"
            await self.add_note(existing.id, f"Automated risk spike recorded. Score: {risk_score}", user="system")
            await self.session.flush()
            logger.info(f"Updated existing incident '{existing.id}' for agent '{agent_id}' with score {risk_score}.")
            return existing

        inc_id = f"inc_{uuid.uuid4().hex[:12]}"
        title = f"High Risk Threat Spike on Agent '{agent_id}' (Score: {risk_score})"
        desc = f"Automated incident generated due to risk score {risk_score}.\nFactors: {factors}"

        inc = Incident(
            id=inc_id,
            title=title,
            description=desc,
            severity=severity,
            status=IncidentStatus.OPEN,
            agent_id=agent_id,
            risk_score=risk_score,
            notes="Auto-generated incident on risk assessment threshold breach."
        )
        created = await self.repository.add(inc)
        await self.session.flush()

        await self.add_note(inc_id, f"Automated incident created due to risk score {risk_score}.", user="system")

        # Trigger notification
        msg = (
            f"🚨 <b>NEW AUTOMATED INCIDENT ({severity.upper()})</b> 🚨\n"
            f"<b>Incident ID:</b> {inc_id}\n"
            f"<b>Agent ID:</b> {agent_id}\n"
            f"<b>Risk Score:</b> {risk_score}/100\n"
            f"<b>Title:</b> {title}"
        )
        await self.notification_service.send_alert(msg)

        logger.warning(f"Automated incident '{inc_id}' created for agent '{agent_id}'.")
        return created

    async def update_incident(self, incident_id: str, dto: IncidentUpdate) -> Incident:
        inc = await self.get_incident(incident_id)
        old_status = inc.status

        for field, value in dto.model_dump(exclude_unset=True).items():
            if value is not None:
                setattr(inc, field, value)

        await self.session.flush()

        if dto.status and dto.status != old_status:
            await self.add_note(
                incident_id,
                f"Incident status updated from '{old_status.value}' to '{dto.status.value}'.",
                user=dto.assigned_to or "admin"
            )
            msg = f"🔔 <b>INCIDENT STATUS CHANGED</b>\n<b>ID:</b> {incident_id}\n<b>New Status:</b> {dto.status.value}"
            await self.notification_service.send_alert(msg)

        return inc

    async def get_incident(self, incident_id: str) -> Incident:
        inc = await self.repository.get(incident_id)
        if not inc:
            raise NotFoundError(f"Incident '{incident_id}' not found.")
        return inc

    async def list_incidents(self, skip: int = 0, limit: int = 200) -> List[Incident]:
        return await self.repository.list(skip=skip, limit=limit)

    async def assign_incident(self, incident_id: str, user_id: str) -> Incident:
        inc = await self.get_incident(incident_id)
        inc.assign_to(user_id)
        await self.add_note(incident_id, f"Incident assigned to analyst '{user_id}'. Status set to INVESTIGATING.", user=user_id)
        await self.session.flush()
        return inc

    async def contain_incident(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.status = IncidentStatus.CONTAINED
        await self.add_note(incident_id, f"Incident marked as CONTAINED by {user}.", user=user)
        await self.session.flush()
        return inc

    async def resolve_incident(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.resolve()
        await self.add_note(incident_id, f"Incident marked as RESOLVED by {user}.", user=user)
        await self.session.flush()
        return inc

    async def mark_false_positive(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.mark_false_positive()
        await self.add_note(incident_id, f"Incident flagged as FALSE_POSITIVE by {user}.", user=user)
        await self.session.flush()
        return inc

    async def close_incident(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.status = IncidentStatus.CLOSED
        await self.add_note(incident_id, f"Incident CLOSED by {user}.", user=user)
        await self.session.flush()
        return inc

    async def execute_action(
        self,
        incident_id: str,
        action_type: str,
        params: Dict[str, Any],
        user: str = "admin"
    ) -> Dict[str, Any]:
        """Execute a quick SOC mitigation action from an Incident (Isolate, Kill Tree, Block IP)."""
        inc = await self.get_incident(incident_id)
        agent_id = inc.agent_id

        if not agent_id and action_type in ("isolate", "unisolate", "kill_process_tree"):
            raise BadRequestError("Cannot execute agent action: Incident has no associated agent_id.")

        cmd_repo = CommandRepository(self.session)
        result_msg = ""

        if action_type == "isolate":
            from app.repositories.agent_repository import AgentRepository
            agent_repo = AgentRepository(self.session)
            agent = await agent_repo.get(agent_id)
            if agent:
                agent.isolate()

            cmd = Command(
                id=f"cmd_{uuid.uuid4().hex[:12]}",
                agent_id=agent_id,
                action="isolate",
                payload={"reason": f"SOC Quick Action from Incident '{incident_id}' by {user}"},
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)
            inc.status = IncidentStatus.CONTAINED
            result_msg = f"Isolated Agent '{agent_id}' and updated status to CONTAINED."

        elif action_type == "unisolate":
            from app.repositories.agent_repository import AgentRepository
            agent_repo = AgentRepository(self.session)
            agent = await agent_repo.get(agent_id)
            if agent:
                agent.activate()

            cmd = Command(
                id=f"cmd_{uuid.uuid4().hex[:12]}",
                agent_id=agent_id,
                action="unisolate",
                payload={"reason": f"SOC Action from Incident '{incident_id}' by {user}"},
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)
            result_msg = f"Unisolated Agent '{agent_id}'."

        elif action_type == "kill_process_tree":
            pid = params.get("pid")
            process_name = params.get("process_name")
            if not pid:
                raise BadRequestError("Parameter 'pid' is required for kill_process_tree action.")

            cmd = Command(
                id=f"cmd_{uuid.uuid4().hex[:12]}",
                agent_id=agent_id,
                action="kill_process_tree",
                payload={
                    "pid": int(pid),
                    "process_name": process_name,
                    "reason": f"SOC Quick Action from Incident '{incident_id}' by {user}"
                },
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)
            result_msg = f"Dispatched kill_process_tree for PID {pid} ({process_name or 'unknown'}) on agent '{agent_id}'."

        elif action_type == "block_ip":
            target_ip = params.get("ip") or params.get("target_ip")
            if not target_ip:
                raise BadRequestError("Parameter 'ip' is required for block_ip action.")
            result_msg = f"Blocked IP '{target_ip}' in firewall rules for Incident '{incident_id}'."

        else:
            raise BadRequestError(f"Unknown action_type '{action_type}'.")

        await self.add_note(incident_id, f"SOC Quick Action executed: [{action_type.upper()}] - {result_msg}", user=user)
        await self.session.flush()

        # Send notification
        msg = (
            f"⚡ <b>SOC QUICK ACTION EXECUTED</b>\n"
            f"<b>Incident:</b> {incident_id}\n"
            f"<b>Action:</b> {action_type.upper()}\n"
            f"<b>Executed By:</b> {user}\n"
            f"<b>Details:</b> {result_msg}"
        )
        await self.notification_service.send_alert(msg)

        return {"status": "success", "message": result_msg, "action": action_type, "incident_id": incident_id}

    async def add_note(self, incident_id: str, content: str, user: str = "system") -> IncidentNote:
        inc = await self.get_incident(incident_id)
        note = IncidentNote(
            incident_id=inc.id,
            user=user,
            content=content
        )
        self.session.add(note)

        current_notes = inc.notes or ""
        inc.notes = f"{current_notes}\n[{user}]: {content}".strip()

        await self.session.flush()
        await self.session.refresh(note)
        return note

    async def list_notes(self, incident_id: str) -> List[IncidentNote]:
        stmt = select(IncidentNote).where(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at.asc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
