import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.flow import Flow
from app.repositories.flow_repository import FlowRepository
from app.schemas.flow import FlowCreate
from app.core.exceptions import NotFoundError
from app.services.base import AbstractService


class FlowService(AbstractService[FlowRepository]):
    def __init__(self, session: AsyncSession):
        repo = FlowRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def create_flow(self, dto: FlowCreate) -> Flow:
        flow = Flow(
            id=dto.id,
            src_ip=dto.src_ip,
            dst_ip=dto.dst_ip,
            src_port=dto.src_port,
            dst_port=dto.dst_port,
            protocol=dto.protocol,
            bytes_sent=dto.bytes_sent,
            packets_sent=dto.packets_sent,
            start_time=dto.start_time,
            end_time=dto.end_time,
            agent_id=dto.agent_id
        )
        return await self.repository.add(flow)

    async def get_flow(self, flow_id: str) -> Flow:
        flow = await self.repository.get(flow_id)
        if not flow:
            raise NotFoundError(f"Flow '{flow_id}' not found.")
        return flow

    async def list_flows(
        self,
        skip: int = 0,
        limit: int = 100,
        agent_id: Optional[str] = None,
        minutes: int = 5
    ) -> List[Flow]:
        """
        List network flows. If no flows found in the recent window, checks whether
        any flows exist in the system before generating synthetic flows for initial demo.
        """
        flows = await self.repository.find_recent_flows(minutes=minutes, agent_id=agent_id)
        if not flows:
            flows = await self.repository.find_flows_paginated(skip=skip, limit=limit, agent_id=agent_id)

        if not flows:
            # Check if ANY real flow exists in the database at all
            any_real_flows = await self.repository.find_flows_paginated(skip=0, limit=1)
            if not any_real_flows:
                flows = self.generate_synthetic_flows(agent_id=agent_id, minutes=minutes)
            else:
                flows = []

        return flows

    def generate_synthetic_flows(self, agent_id: Optional[str] = None, minutes: int = 5) -> List[Flow]:
        """
        Generate in-memory realistic 5-minute time-series flows for the requested agent or all devices.
        """
        target_agent = agent_id if (agent_id and agent_id.lower() not in ("all", "none", "null")) else "all"
        now = datetime.now(timezone.utc)
        points = 20
        step_seconds = max(5, (minutes * 60) // points)
        generated_flows = []

        agent_ip_map = {
            "client1": "192.168.10.11",
            "client2": "192.168.10.12",
            "client3": "192.168.10.13",
            "client4": "192.168.10.14",
            "attacker": "192.168.10.99",
            "manager": "192.168.10.1"
        }
        src_ip = agent_ip_map.get(target_agent, "192.168.10.10")

        for i in range(points):
            flow_time = now - timedelta(seconds=(points - 1 - i) * step_seconds)
            is_udp = (i % 3 == 0)
            protocol = "UDP" if is_udp else "TCP"

            wave = (i % 6) * 6
            if target_agent == "attacker":
                tcp_packets = random.randint(45, 95) + wave
                udp_packets = random.randint(35, 75) + wave
            elif target_agent == "manager":
                tcp_packets = random.randint(30, 60) + wave
                udp_packets = random.randint(15, 35) + wave
            else:
                tcp_packets = random.randint(12, 38) + wave
                udp_packets = random.randint(4, 18) + wave

            packets = udp_packets if protocol == "UDP" else tcp_packets
            bytes_sent = packets * random.randint(64, 1400)

            flow = Flow(
                id=f"syn_flow_{i}_{uuid.uuid4().hex[:6]}",
                src_ip=src_ip,
                dst_ip="192.168.10.1" if src_ip != "192.168.10.1" else "192.168.10.11",
                src_port=random.randint(1024, 65535),
                dst_port=53 if protocol == "UDP" else random.choice([80, 443, 8000, 22]),
                protocol=protocol,
                bytes_sent=bytes_sent,
                packets_sent=packets,
                start_time=flow_time,
                end_time=flow_time + timedelta(seconds=1),
                agent_id=target_agent if target_agent not in ("manager", "all") else None,
                created_at=flow_time
            )
            generated_flows.append(flow)

        return generated_flows

    async def get_traffic_series(
        self,
        agent_id: Optional[str] = None,
        minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Aggregate flow metrics into time series with syn, udp, total metrics.
        """
        flows = await self.list_flows(agent_id=agent_id, minutes=minutes)
        series = []
        for f in flows:
            proto = (f.protocol or "TCP").upper()
            pkts = f.packets_sent or 0
            if proto in ("TCP", "SYN"):
                syn = pkts
                udp = 0
            elif proto == "UDP":
                syn = 0
                udp = pkts
            else:
                syn = int(pkts * 0.7)
                udp = pkts - syn
            total = syn + udp

            series.append({
                "id": f.id,
                "agent_id": f.agent_id or ("manager" if f.src_ip == "192.168.10.1" else "unknown"),
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "protocol": proto,
                "syn": syn,
                "udp": udp,
                "total": total,
                "bytes": f.bytes_sent or (total * 80),
                "timestamp": f.start_time.isoformat() if hasattr(f.start_time, "isoformat") else str(f.start_time)
            })
        return series

    async def check_agent_beaconing(self, agent_id: str) -> bool:
        flows = await self.repository.find_by_agent(agent_id)
        return Flow.check_beaconing(flows)
