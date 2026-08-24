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

def get_process_list():
    """Lấy danh sách process đang chạy, đánh dấu suspicious nếu tên nằm trong blacklist."""
    suspicious_names = {"mimikatz.exe", "netcat", "nc.exe", "nmap", "chisel", "vssadmin.exe", "powershell.exe", "cmd.exe"}
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                info = proc.info
                name = info.get('name') or ""
                path = info.get('exe') or ""
                cmdline = " ".join(info.get('cmdline') or [])
                is_suspicious = any(s in name.lower() for s in suspicious_names)
                processes.append({
                    "pid": info.get('pid'),
                    "name": name,
                    "path": path,
                    "cmdline": cmdline,
                    "is_suspicious": is_suspicious
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass
    return processes[:50]   # Giới hạn 50 process

def get_network_connections():
    """Lấy các kết nối mạng đang mở, đánh dấu suspicious nếu cổng đích nằm trong danh sách lạ."""
    suspicious_ports = {4444, 1337, 31337, 6667, 23}
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                laddr = conn.laddr
                raddr = conn.raddr
                dst_ip = raddr.ip if raddr else "0.0.0.0"
                dst_port = raddr.port if raddr else (laddr.port if laddr else 0)
                connections.append({
                    "src_ip": laddr.ip if laddr else "0.0.0.0",
                    "src_port": laddr.port if laddr else 0,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "status": conn.status,
                    "is_suspicious": dst_port in suspicious_ports
                })
    except Exception:
        pass
    return connections[:30]

def get_file_changes_count():
    """Đếm số file .encrypted hoặc có thay đổi gần đây trong /tmp."""
    count = 0
    try:
        for f in os.listdir('/tmp'):
            if f.endswith('.encrypted'):
                count += 1
    except Exception:
        pass
    return count

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

async def send_risk_telemetry(websocket):
    await asyncio.sleep(2)
    while True:
        try:
            procs = get_process_list()
            file_changes = get_file_changes_count()
            suspicious_cmds = [p["cmdline"] for p in procs if p.get("is_suspicious") and p.get("cmdline")]
            payload = {
                "agent_id": AGENT_ID,
                "cpu_usage": psutil.cpu_percent(interval=1),
                "process_list": procs,
                "network_connections": get_network_connections(),
                "file_changes_count": file_changes,
                "suspicious_commands": suspicious_cmds,
                "shadow_copy_deletion": False,
                "mass_file_modification": file_changes > 20,
                "registry_changes": [],
                "credential_access_events": [],
                "lateral_movement_events": [],
                "dns_queries": [],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            message = {"type": "TELEMETRY_RISK", "payload": payload}
            await websocket.send(json.dumps(message))
        except Exception as e:
            print(f"Error sending risk telemetry: {e}", flush=True)
        await asyncio.sleep(10)

async def main_agent():
    while True:
        try:
            async with websockets.connect(MANAGER_URL) as ws:
                print(f"Connected to {MANAGER_URL}", flush=True)
                await asyncio.gather(
                    send_stats(ws),
                    send_risk_telemetry(ws),
                )
        except Exception as e:
            print(f"Error: {e}. Retrying in 5s...", flush=True)
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main_agent())