# agent/agent.py
import asyncio
import json
import os
import socket
import subprocess
import psutil
import websockets
from datetime import datetime, timezone
from commands import COMMAND_HANDLERS

MANAGER_URL = os.getenv("MANAGER_URL", "ws://manager:8000/ws/agent")
AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())

def get_ip_address():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "0.0.0.0"

def get_mac_address():
    try:
        with open('/sys/class/net/eth0/address', 'r') as f:
            return f.read().strip()
    except:
        return "00:00:00:00:00:00"

def collect_stats():
    return {
        "agent_id": AGENT_ID,
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "ip_address": get_ip_address(),
        "mac_address": get_mac_address(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

async def execute_command(websocket, cmd):
    action = cmd.get("action")
    params = cmd.get("payload", {})
    handler = COMMAND_HANDLERS.get(action)
    if not handler:
        return {"status": "error", "message": f"Unknown action '{action}'"}

    result = await handler.execute(params, websocket)
    return result

async def send_stats(websocket):
    while True:
        stats = collect_stats()
        message = {"type": "HEARTBEAT", "payload": stats}
        await websocket.send(json.dumps(message))
        try:
            response_text = await asyncio.wait_for(websocket.recv(), timeout=2)
            response = json.loads(response_text)
            if "pending_commands" in response:
                for cmd in response["pending_commands"]:
                    ack_payload = await execute_command(websocket, cmd)
                    ack_message = {
                        "type": "COMMAND_ACK",
                        "payload": {
                            "command_id": cmd.get("command_id"),
                            "status": ack_payload.get("status", "success"),
                            "error_message": ack_payload.get("message"),
                            "executed_at": datetime.now(timezone.utc).isoformat()
                        }
                    }
                    await websocket.send(json.dumps(ack_message))
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(5)

async def main_agent():
    while True:
        try:
            async with websockets.connect(MANAGER_URL) as ws:
                print(f"Connected to {MANAGER_URL}", flush=True)
                await send_stats(ws)
        except Exception as e:
            print(f"Error: {e}. Retrying in 5s...", flush=True)
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main_agent())