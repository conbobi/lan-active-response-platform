"""block_ip / unblock_ip / blocklist_status: host firewall blocking through ip_blocklist (nftables)."""
import asyncio
import os

from firewall_control import firewall_lock
from ip_blocklist import Blocklist
from network_sources import CollectionError

from .base import BaseCommand


def _blocklist(websocket):
    return Blocklist(manager_url=os.getenv("MANAGER_URL", ""), websocket_peer=getattr(websocket, "remote_address", None))


def _result(receipt):
    return {"status": receipt.get("status", "failed"), "message": receipt.get("message"), "receipt": receipt}


class BlockIpCommand(BaseCommand):
    name = "block_ip"

    async def execute(self, params, websocket):
        def apply():
            with firewall_lock():
                return _blocklist(websocket).block(params.get("block_id"), params.get("ip"))
        try:
            return _result(await asyncio.to_thread(apply))
        except (CollectionError, OSError, ValueError) as error:
            return {"status": "failed", "message": str(error), "receipt": {"status": "failed", "code": "EXECUTION_ERROR",
                                                                         "message": str(error)}}


class UnblockIpCommand(BaseCommand):
    name = "unblock_ip"

    async def execute(self, params, websocket):
        def apply():
            with firewall_lock():
                return _blocklist(websocket).unblock(params.get("block_id"), params.get("unblock_id"), params.get("ip"),
                                                     int(params.get("verify_seconds") or 300))
        try:
            return _result(await asyncio.to_thread(apply))
        except (CollectionError, OSError, ValueError) as error:
            return {"status": "failed", "message": str(error), "receipt": {"status": "failed", "code": "EXECUTION_ERROR",
                                                                         "message": str(error)}}


class BlocklistStatusCommand(BaseCommand):
    name = "blocklist_status"

    async def execute(self, params, websocket):
        def read():
            with firewall_lock():
                return {"status": "success", **_blocklist(websocket).status()}
        try:
            return _result(await asyncio.to_thread(read))
        except (CollectionError, OSError, ValueError) as error:
            return {"status": "failed", "message": str(error), "receipt": {"status": "failed", "code": "STATUS_UNAVAILABLE",
                                                                         "message": str(error)}}
