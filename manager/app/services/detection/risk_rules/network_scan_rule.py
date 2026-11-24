from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select

from app.models.flow import Flow
from app.services.detection.behavior_evidence import SCAN, address, observed_time, stable_id
from app.services.detection.risk_rules.base import RiskRule

WINDOW = 60
PORT_THRESHOLD = 8


def inbound_socket(row):
    evidence = row.socket_evidence or {}
    if not isinstance(evidence, dict):
        return None
    observed = observed_time(evidence.get("observed_at"))
    source, target = address(row.dst_ip), address(row.src_ip)  # Agent reports local endpoint first.
    if (evidence.get("direction") != "inbound" or row.protocol != "TCP" or observed is None
            or evidence.get("status") not in ("ESTABLISHED", "SYN-RECV", "SYN_RECV")
            or not source or not target or source == target
            or not 0 < row.src_port <= 65535 or not 0 < row.dst_port <= 65535):
        return None
    return (source, target, row.protocol), observed


def scan_findings(rows, current, agent_id):
    groups = defaultdict(dict)
    for row in rows:
        if row.agent_id != agent_id or (normalized := inbound_socket(row)) is None:
            continue
        group, observed = normalized
        if group not in current or not current[group] - timedelta(seconds=WINDOW) <= observed <= current[group]:
            continue
        socket = row.socket_evidence
        inode = socket.get("socket_id") or socket.get("inode")
        key = row.src_port, row.dst_port, inode if isinstance(inode, str) else None
        previous = groups[group].get(key)
        if previous is None or observed > previous[1]:
            groups[group][key] = (row, observed)
    for group, recorded in groups.items():
        ports = sorted({row.src_port for row, _ in recorded.values()})
        if len(ports) < PORT_THRESHOLD:
            continue
        source, target, protocol = group
        records = sorted(recorded.values(), key=lambda item: (item[1], item[0].id))
        ids = [row.id for row, _ in records]
        samples = []
        for row, stamp in records:
            socket = row.socket_evidence
            holders = socket.get("holders")
            holders = holders if isinstance(holders, list) else []
            samples.append({
                "event_id": row.id, "source_port": row.dst_port, "destination_port": row.src_port,
                "observed_at": stamp.isoformat(), "socket_id": socket.get("socket_id"),
                "inode": socket.get("inode"),
                "holders": [
                    {key: holder.get(key) for key in ("pid", "process_start_time", "socket_fds")}
                    for holder in holders[:8] if isinstance(holder, dict)
                ] if socket.get("attribution") in ("inode_verified", "inode_verified_partial", "holders_truncated") else [],
            })
        yield {
            "evidence_id": stable_id("scan_", agent_id, *group, *ids),
            "evidence_type": "network", "source": "flows", "source_event_ids": ids,
            "agent_id": agent_id, "classification": SCAN, "protocol": protocol, "direction": "inbound",
            "source_ip": source, "destination_ip": target, "destination_ports": ports,
            "connection_count": len(records), "detection_window_seconds": WINDOW,
            "first_attempt_at": records[0][1].isoformat(), "last_attempt_at": records[-1][1].isoformat(),
            "connections": samples,
        }


class NetworkScanRule(RiskRule):
    rule_id = SCAN
    name = "Observed Inbound Service Scanning"
    description = "Detects at least eight observed local TCP ports from the same remote source in 60 seconds."
    enabled = True
    weight = 1.0
    base_score = 65.0
    category = "network"

    async def evaluate(self, telemetry, context):
        agent_id = context.get("agent_id")
        rows = context.get("flow_observations") or []
        current = {}
        for row in rows:
            if row.agent_id == agent_id and (normalized := inbound_socket(row)):
                group, stamp = normalized
                current[group] = max(current.get(group, stamp), stamp)
        if not current:
            return 0.0, ""
        session = context.get("session")
        if session is not None:
            start = min(current.values()) - timedelta(seconds=WINDOW)
            # Flow.start_time is ingestion time. Evidence timestamps are rechecked per cohort.
            received = max(observed_time(row.start_time) for row in rows)
            start = max(start, received - timedelta(minutes=3))
            history = await session.scalars(select(Flow).where(
                Flow.agent_id == agent_id, Flow.dst_ip.in_({group[0] for group in current}),
                Flow.protocol == "TCP", Flow.start_time.between(start, received),
                Flow.socket_evidence.is_not(None),
            ).order_by(Flow.start_time.desc()).limit(1024))
            rows = [*rows, *history]
        findings = list(scan_findings(rows, current, agent_id))
        if not findings:
            return 0.0, ""
        context.setdefault("behavior_findings", {})[self.rule_id] = [(self.base_score, item) for item in findings]
        return self.base_score, f"Observed inbound TCP traffic to {len(findings[0]['destination_ports'])} distinct local ports"
