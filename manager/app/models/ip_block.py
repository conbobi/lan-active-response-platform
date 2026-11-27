"""Host IP blocks applied by the Agent firewall adapter (nftables table inet larp_blocklist).

``status`` is the action state (approval/dispatch/verification); ``effective_state`` is what the
firewall is believed to enforce, from the latest Agent evidence. They are deliberately separate:
an accepted request or HTTP 200 says nothing about the firewall. History is append-only: an
unblock is its own row linked to the block, and every transition is an IpBlockEvent.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

JSONT = JSON().with_variant(JSONB, "postgresql")


def _now():
    return datetime.now(timezone.utc)


class IpBlock(Base):
    __tablename__ = "ip_blocks"
    __table_args__ = (Index("ix_ip_blocks_agent_ip", "agent_id", "target_ip"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # block_id = idempotency key on the Agent
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    target_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    firewall_backend: Mapped[str] = mapped_column(String(16), default="nftables", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="PENDING_APPROVAL", nullable=False, index=True)
    effective_state: Mapped[str] = mapped_column(String(24), default="NOT_BLOCKED", nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    command_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    firewall_rules: Mapped[Optional[Any]] = mapped_column(JSONT, nullable=True)
    receipt: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    last_verification: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dispatched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    traffic_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class IpUnblock(Base):
    __tablename__ = "ip_unblocks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # unblock_action_id
    block_id: Mapped[str] = mapped_column(String(32), ForeignKey("ip_blocks.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="PENDING_APPROVAL", nullable=False)
    access_state: Mapped[str] = mapped_column(String(24), default="PENDING", nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    command_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    firewall_removal_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    connectivity_verification: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dispatched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class IpBlockEvent(Base):
    __tablename__ = "ip_block_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    block_id: Mapped[str] = mapped_column(String(32), ForeignKey("ip_blocks.id", ondelete="CASCADE"), nullable=False, index=True)
    unblock_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    event: Mapped[str] = mapped_column(String(48), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONT, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
