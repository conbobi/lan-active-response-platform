from typing import List, Dict, Optional, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.flow import Flow
from app.models.threat_indicator import ThreatIndicator
from app.services.detection.network_shell import detect_network_shell
from app.services.detection.risk_rules.network_connection_rule import NetworkConnectionRule


class NetworkRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    def _time_filter(self, time_range: str) -> datetime:
        now = datetime.now(timezone.utc)
        mapping = {"1h": 1, "24h": 24, "7d": 168}
        hours = mapping.get(time_range, 1)
        return now - timedelta(hours=hours)

    async def get_suspicious(
        self,
        agent_id: Optional[str] = None,
        time_range: str = "1h",
        risk: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        since = self._time_filter(time_range)

        SUSPICIOUS_PROCS = [
            'msbuild.exe', 'certutil.exe', 'rundll32.exe',
            'regsvr32.exe', 'mshta.exe', 'wmic.exe',
            'powershell.exe', 'cmd.exe', 'bitsadmin.exe',
        ]

        stmt = select(Flow).where(Flow.created_at >= since)
        if agent_id and agent_id != 'all':
            stmt = stmt.where(Flow.agent_id == agent_id)

        stmt = stmt.order_by(Flow.created_at.desc()).limit(limit * 5)
        result = await self.session.execute(stmt)
        flows = result.scalars().all()

        # Get threat IOC IPs
        ioc_result = await self.session.execute(
            select(ThreatIndicator.value).where(
                ThreatIndicator.indicator_type.in_(['ip', 'ip:port'])
            )
        )
        ioc_ips = {row[0] for row in ioc_result.all()}

        out = []
        for f in flows:
            risk_level = 'low'
            reasons = []
            socket = f.socket_evidence or {}
            match = detect_network_shell({**socket, "protocol": f.protocol, "src_ip": f.src_ip,
                                          "src_port": f.src_port, "dst_ip": f.dst_ip, "dst_port": f.dst_port})
            holders = socket.get("holders")
            holder = None
            if isinstance(holders, list):
                holder = next((proc for proc in holders[:16] if isinstance(proc, dict) and proc.get("pid") == f.pid), None)

            if match:
                risk_level = match["severity"]
                reasons.append(match["classification"])
                holder = match["process"]
            elif f.dst_port in NetworkConnectionRule.DEFAULT_SUSPICIOUS_PORTS and socket.get("direction") != "inbound":
                reasons.append(f'Uncommon destination port {f.dst_port}')

            if f.process_name and f.process_name.lower() in SUSPICIOUS_PROCS:
                if risk_level == 'low':
                    risk_level = 'medium'
                reasons.append(f'{f.process_name} không nên connect mạng')

            if f.dst_ip in ioc_ips:
                risk_level = 'high'
                reasons.append(f'IP {f.dst_ip} trong threat feed')

            if not reasons:
                continue  # Không suspicious

            if risk and risk_level != risk:
                continue

            name = (f.process_name or "unknown") if not match else "unknown"
            pid = f.pid if not match else None
            if holder:
                name = holder.get("name") or holder.get("process_name") or "unknown"
                pid = holder["pid"]
            out.append({
                'id': f.id,
                'process_name': name,
                'pid': pid,
                'process_start_time': holder.get("process_start_time") if holder else None,
                'socket_evidence': socket or None,
                'dst_ip': f.dst_ip,
                'dst_port': f.dst_port,
                'src_ip': f.src_ip,
                'src_port': f.src_port,
                'protocol': f.protocol,
                'agent_id': f.agent_id,
                'risk_level': risk_level,
                'reason': '; '.join(reasons),
                'reasons': reasons,
                'last_seen': f.created_at.isoformat() if f.created_at else datetime.now(timezone.utc).isoformat(),
                'bytes_sent': f.bytes_sent,
            })

        seen = set()
        deduped = []
        for item in out:
            key = tuple(item[field] for field in ('agent_id', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                                                  'pid', 'process_start_time'))
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        return deduped[:limit]

    async def get_top_talkers(
        self,
        agent_id: Optional[str] = None,
        time_range: str = "1h",
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        since = self._time_filter(time_range)
        stmt = (
            select(
                Flow.process_name,
                func.count(Flow.id).label('conn_count'),
                func.count(func.distinct(Flow.dst_ip)).label('unique_dst'),
                func.count(func.distinct(Flow.dst_port)).label('unique_ports'),
            )
            .where(Flow.created_at >= since)
            .where(Flow.process_name.isnot(None))
            .group_by(Flow.process_name)
            .order_by(func.count(Flow.id).desc())
            .limit(limit)
        )
        if agent_id and agent_id != 'all':
            stmt = stmt.where(Flow.agent_id == agent_id)

        result = await self.session.execute(stmt)
        return [
            {
                'process_name': row.process_name,
                'connections': row.conn_count,
                'unique_destinations': row.unique_dst,
                'unique_ports': row.unique_ports,
            }
            for row in result.all()
        ]

    async def get_protocols(
        self,
        agent_id: Optional[str] = None,
        time_range: str = "1h",
    ) -> List[Dict[str, Any]]:
        since = self._time_filter(time_range)
        stmt = (
            select(Flow.protocol, func.count(Flow.id).label('count'))
            .where(Flow.created_at >= since)
            .group_by(Flow.protocol)
            .order_by(func.count(Flow.id).desc())
        )
        if agent_id and agent_id != 'all':
            stmt = stmt.where(Flow.agent_id == agent_id)

        result = await self.session.execute(stmt)
        return [{'protocol': row.protocol or 'Unknown', 'count': row.count} for row in result.all()]

    async def get_by_id(self, flow_id: str) -> Optional[Flow]:
        stmt = select(Flow).where(Flow.id == flow_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
