"""Network extensions to the existing authenticated Agent heartbeat."""
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import inspect
import json
import os
import time
from urllib.parse import urlsplit

import websockets

from firewall_control import controls_configured, read_transaction, request, IN_PROGRESS, IO_ERRORS, SAFETY_VERSION
from network_monitor import NetworkMonitor
from network_sources import CollectionError

TOKEN = os.getenv("LARP_NETWORK_AGENT_TOKEN")
SNAPSHOT_SIZE = 1_700_000


def websocket_auth(url):
    if not TOKEN:
        return {}
    if urlsplit(url).scheme != "wss":
        raise RuntimeError("Network Agent enrollment requires a wss:// Manager")
    parameter = "additional_headers" if "additional_headers" in inspect.signature(websockets.connect).parameters else "extra_headers"
    return {parameter: {"X-LARP-Agent-Token": TOKEN}}


class NetworkChannel:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.monitor = NetworkMonitor()
        self.queue = asyncio.Queue(maxsize=1)
        self.seen = {}

    def deliver(self, command):
        if isinstance(command, dict) and not self.queue.full():
            self.queue.put_nowait(command)

    async def _snapshot(self, send, command_id=None, *, force_inventory=False):
        full = force_inventory or command_id is not None
        payload = await asyncio.to_thread(self.monitor.collect, self.agent_id, full, command_id)
        firewall = payload.get("sections", {}).get("firewall")
        if firewall is not None:
            firewall.update(controls_configured=await asyncio.to_thread(controls_configured),
                            safety_version=SAFETY_VERSION, transaction=await asyncio.to_thread(read_transaction))
        if len(json.dumps(payload, ensure_ascii=False).encode()) > SNAPSHOT_SIZE:
            payload["status"] = "partial"
            for key in ("ports", "connections", "events", "nat", "firewall", "routes", "neighbors", "policy"):
                source = payload["sections"].get(key, {})
                for field in ("rows", "groups", "rules", "kernel_rules"):
                    if isinstance(source.get(field), list):
                        source[field] = source[field][:160]
            payload["sections"]["overview"]["errors"] = {"payload": "Snapshot trimmed to transport limit"}
            if len(json.dumps(payload, ensure_ascii=False).encode()) > SNAPSHOT_SIZE:
                raise CollectionError("Network snapshot exceeds the bounded transport size")
        await send({"type": "NETWORK_SNAPSHOT", "payload": payload})
        return payload

    async def _execute(self, command_id, expiration, command):
        if command["action"] == "network_refresh":
            return None
        if command["action"] != "network_firewall":
            raise CollectionError("Unsupported network command")
        if command.get("firewall_safety_version") != SAFETY_VERSION:
            raise CollectionError("Unsupported firewall safety policy")
        params = command["params"]
        if not isinstance(params, dict):
            raise CollectionError("Invalid firewall parameters")
        result = await asyncio.to_thread(request, command_id, params, expiration)
        expected = params["operation"]
        deadline = time.monotonic() + 95
        while result["status"] in IN_PROGRESS - {"awaiting_commit"} and time.monotonic() < deadline:
            await asyncio.sleep(0.5)
            result = await asyncio.to_thread(read_transaction)
        if result.get("id") != (params.get("transaction_id") or command_id):
            raise CollectionError("Firewall result does not match the transaction")
        return result

    async def _handle(self, send, command):
        command_id = command.get("command_id")
        if not isinstance(command_id, str) or len(command_id) != 32 or any(c not in "0123456789abcdef" for c in command_id):
            return
        if command.get("agent_id") != self.agent_id or command.get("schema_version") != 1:
            return
        self.seen = {key: expiry for key, expiry in self.seen.items() if expiry > time.time()}
        if command_id in self.seen:
            return
        self.seen[command_id] = time.time() + 240
        outcome, error, snapshot, result = "failed", None, None, None
        try:
            expiry = datetime.fromisoformat(command["expires_at"]).timestamp()
            if not time.time() < expiry <= time.time() + 60:
                raise CollectionError("Network command expired or outside the allowed delivery window")
            result = await self._execute(command_id, expiry, command)
            snapshot = await self._snapshot(send, command_id)
            if result:
                operation = command["params"]["operation"]
                approved = {"commit": "committed", "rollback": "rolled_back"}.get(operation, "awaiting_commit")
                if result["status"] != approved:
                    raise CollectionError(result.get("error") or f"Unexpected firewall result: {result['status']}")
                firewall = snapshot["sections"].get("firewall", {})
                after = result.get("after", {})
                if firewall.get("provider") != "ufw" or any(firewall.get(key) != after.get(key) for key in ("status", "defaults", "logging")):
                    raise CollectionError("Fresh firewall snapshot does not match the transaction")
            outcome = "success"
        except IO_ERRORS + (KeyError, TypeError) as exc:
            error = str(exc)[:480]
        await send({"type": "NETWORK_ACK", "payload": {
            "agent_id": self.agent_id, "schema_version": 1, "command_id": command_id,
            "snapshot_id": snapshot["snapshot_id"] if snapshot else None,
            "timestamp": datetime.now(timezone.utc).isoformat(), "status": outcome,
            "error": error, "transaction": result,
        }})

    async def run(self, send):
        next_snapshot = time.monotonic() + 2
        last_transaction = None
        while True:
            try:
                delay = max(0, min(5, next_snapshot - time.monotonic()))
                command = self.queue.get_nowait() if not self.queue.empty() else None
                if command is None and delay:
                    with suppress(asyncio.TimeoutError):
                        command = await asyncio.wait_for(self.queue.get(), delay)
                if command:
                    await self._handle(send, command)
                    next_snapshot = time.monotonic() + 25
                if time.monotonic() >= next_snapshot:
                    await self._snapshot(send)
                    next_snapshot = time.monotonic() + 25
                transaction = await asyncio.to_thread(read_transaction)
                if transaction and transaction != last_transaction:
                    if transaction.get("status") in {"rolled_back", "rollback_failed", "committed", "awaiting_commit"}:
                        if last_transaction is not None:
                            await self._snapshot(send, force_inventory=True)
                            next_snapshot = time.monotonic() + 25
                        await send({"type": "NETWORK_TRANSACTION", "payload": {
                            "agent_id": self.agent_id, "schema_version": 1, "transaction": transaction,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }})
                        last_transaction = transaction
            except IO_ERRORS as exc:
                print(f"Network snapshot collection failed: {exc}", flush=True)
                next_snapshot = time.monotonic() + 25
                await asyncio.sleep(5)
