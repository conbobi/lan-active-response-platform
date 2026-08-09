# agent/agent.py
import asyncio
import json
import os
import socket
import psutil
import websockets
import subprocess

MANAGER_URL = os.getenv("MANAGER_URL", "ws://manager:8000/ws/agent")
AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())

def get_firewall_status():
    try:
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        return "Status: active" in r.stdout
    except:
        return False

def collect_stats():
    return {
        "agent_id": AGENT_ID,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "firewall_active": get_firewall_status(),
        "timestamp": int(asyncio.get_event_loop().time())
    }

async def send_stats():
    while True:
        try:
            async with websockets.connect(MANAGER_URL) as ws:
                print(f"Connected to {MANAGER_URL}")
                while True:
                    stats = collect_stats()
                    await ws.send(json.dumps(stats))
                    await asyncio.sleep(5)
        except Exception as e:
            print(f"Error: {e}. Retrying in 5s...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(send_stats())