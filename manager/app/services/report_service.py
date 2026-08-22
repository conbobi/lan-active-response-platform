import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from calendar import monthrange
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from app.models.report import Report
from app.models.agent import Agent
from app.models.incident import Incident
from app.models.event import Event
from app.models.command import Command
from app.schemas.enums import AgentStatus, IncidentSeverity, IncidentStatus
from app.repositories.report_repository import ReportRepository

logger = logging.getLogger(__name__)


class ReportService:
    """
    Facade service responsible for aggregating SOC metrics and building executive monthly PDF reports.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.report_repo = ReportRepository(session)

    async def generate_monthly_report(
        self,
        month: Optional[int] = None,
        year: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Report:
        """
        Generate a monthly PDF security report containing:
        - Agent online/offline/isolated statistics
        - Incidents breakdown & resolution metrics
        - High/Critical severity events summary
        """
        now = datetime.now(timezone.utc)
        if start_date and end_date:
            period_start = start_date
            period_end = end_date
        else:
            r_year = year or now.year
            r_month = month or now.month
            _, last_day = monthrange(r_year, r_month)
            period_start = datetime(r_year, r_month, 1, 0, 0, 0, tzinfo=timezone.utc)
            period_end = datetime(r_year, r_month, last_day, 23, 59, 59, tzinfo=timezone.utc)

        # 1. Gather Agent Metrics
        agents_total = (await self.session.execute(select(func.count(Agent.id)))).scalar() or 0
        agents_active = (await self.session.execute(select(func.count(Agent.id)).where(Agent.status == AgentStatus.ACTIVE))).scalar() or 0
        agents_isolated = (await self.session.execute(select(func.count(Agent.id)).where(Agent.is_isolated == True))).scalar() or 0
        agents_dead = (await self.session.execute(select(func.count(Agent.id)).where(Agent.status == AgentStatus.DEAD))).scalar() or 0

        # 2. Gather Incident Metrics
        incidents_total = (await self.session.execute(
            select(func.count(Incident.id)).where(Incident.created_at >= period_start, Incident.created_at <= period_end)
        )).scalar() or 0

        incidents_resolved = (await self.session.execute(
            select(func.count(Incident.id)).where(
                Incident.created_at >= period_start,
                Incident.created_at <= period_end,
                Incident.status == IncidentStatus.RESOLVED
            )
        )).scalar() or 0

        isolate_cmds = (await self.session.execute(
            select(func.count(Command.id)).where(
                Command.created_at >= period_start,
                Command.created_at <= period_end,
                Command.action == "isolate"
            )
        )).scalar() or 0

        block_ip_cmds = (await self.session.execute(
            select(func.count(Command.id)).where(
                Command.created_at >= period_start,
                Command.created_at <= period_end,
                Command.action == "block_ip"
            )
        )).scalar() or 0

        # 3. Gather High/Critical Events Metrics
        high_crit_events = (await self.session.execute(
            select(func.count(Event.id)).where(
                Event.created_at >= period_start,
                Event.created_at <= period_end,
                Event.severity.in_([IncidentSeverity.HIGH, IncidentSeverity.CRITICAL])
            )
        )).scalar() or 0

        # 4. Generate PDF using ReportLab
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        filename = f"report_{period_start.strftime('%Y%m%d')}_{period_end.strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}.pdf"
        file_path = os.path.join(reports_dir, filename)

        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e293b"),
            alignment=1,
            spaceAfter=20
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#64748b"),
            alignment=1,
            spaceAfter=25
        )
        section_style = ParagraphStyle(
            "ReportSection",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=15,
            spaceAfter=10
        )

        elements = []

        # Title
        report_title = f"LARP Security Operations Monthly Report ({period_start.strftime('%B %Y')})"
        elements.append(Paragraph(report_title, title_style))
        elements.append(Paragraph(f"Period: {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}", subtitle_style))
        elements.append(Spacer(1, 15))

        # Agent Summary Table
        elements.append(Paragraph("1. Agent Infrastructure Summary", section_style))
        agent_data = [
            ["Metric", "Count"],
            ["Total Registered Agents", str(agents_total)],
            ["Active Agents", str(agents_active)],
            ["Isolated Agents", str(agents_isolated)],
            ["Offline / Dead Agents", str(agents_dead)]
        ]
        t1 = Table(agent_data, colWidths=[300, 150])
        t1.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#3b82f6")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t1)
        elements.append(Spacer(1, 20))

        # Incident Summary Table
        elements.append(Paragraph("2. Incident & Action Breakdown", section_style))
        incident_data = [
            ["Metric", "Count"],
            ["Total Incidents Recorded", str(incidents_total)],
            ["Resolved Incidents", str(incidents_resolved)],
            ["Isolate Commands Issued", str(isolate_cmds)],
            ["Block IP Commands Issued", str(block_ip_cmds)],
            ["High/Critical Severity Events", str(high_crit_events)]
        ]
        t2 = Table(incident_data, colWidths=[300, 150])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t2)

        # Build PDF
        doc.build(elements)
        logger.info(f"Generated PDF report successfully at '{file_path}'.")

        # 5. Save Report Record to DB
        report_record = Report(
            id=f"rep_{uuid.uuid4().hex[:12]}",
            title=report_title,
            period_start=period_start,
            period_end=period_end,
            file_path=file_path,
            format="pdf"
        )
        created_report = await self.report_repo.add(report_record)
        return created_report
