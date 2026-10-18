import sys
import os
import json
import time
import asyncio
from typing import List, Dict, Any
import psutil
import websockets

AGENT_ID = os.getenv("AGENT_ID", "WIN-DEMO-01")
MANAGER_URL = os.getenv("MANAGER_URL", "ws://192.168.30.105:8005/ws/agent")
INTERVAL = 15


def collect_processes() -> List[Dict[str, Any]]:
    """
    Collect running processes on Windows using psutil.
    Extracts pid, ppid, name, exe path, and command line arguments.
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            cmdline_raw = info.get('cmdline')
            if isinstance(cmdline_raw, list):
                cmdline = " ".join(str(arg) for arg in cmdline_raw)
            else:
                cmdline = str(cmdline_raw or "")

            processes.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name") or "",
                "exe": info.get("exe") or "",
                "cmdline": cmdline,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    return processes


def collect_network() -> List[Dict[str, Any]]:
    """
    Collect established network connections with associated PID and process name.
    """
    connections = []
    try:
        net_conns = psutil.net_connections(kind='inet')
    except Exception as e:
        return connections

    for conn in net_conns:
        try:
            if conn.status != 'ESTABLISHED' or not conn.pid:
                continue

            proc_name = "unknown"
            try:
                p = psutil.Process(conn.pid)
                proc_name = p.name()
            except Exception:
                pass

            src_ip = conn.laddr.ip if conn.laddr else ""
            src_port = conn.laddr.port if conn.laddr else 0
            dst_ip = conn.raddr.ip if conn.raddr else ""
            dst_port = conn.raddr.port if conn.raddr else 0

            connections.append({
                "pid": conn.pid,
                "process_name": proc_name,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            })
        except Exception:
            continue
    return connections


async def send_telemetry(ws) -> None:
    """Gửi heartbeat + telemetry mỗi 15s."""
    while True:
        try:
            # 1. Gửi HEARTBEAT trước
            heartbeat = {
                "type": "HEARTBEAT",
                "payload": {
                    "agent_id": AGENT_ID,
                    "hostname": os.environ.get("COMPUTERNAME", "WIN-DEMO-01"),
                    "platform": "windows",
                    "ip_address": os.getenv("AGENT_IP", "192.168.30.106"),
                }
            }
            await ws.send(json.dumps(heartbeat))

            # 2. Rồi gửi telemetry
            procs = collect_processes()
            conns = collect_network()
            msg = {
                "type": "TELEMETRY_RISK",
                "payload": {
                    "agent_id": AGENT_ID,
                    "platform": "windows",
                    "process_list": procs,
                    "network_connections": conns,
                    "timestamp": time.time(),
                }
            }
            await ws.send(json.dumps(msg))
            print(f"[+] Heartbeat + telemetry: {len(procs)} procs, {len(conns)} conns")
            await asyncio.sleep(INTERVAL)
        except websockets.exceptions.ConnectionClosed:
            print("[!] Connection closed by server, reconnect...")
            raise
        except Exception as e:
            print(f"[!] Send error: {type(e).__name__}: {e}")
            raise


async def main() -> None:
    """Main loop — KHÔNG gửi heartbeat riêng, để send_telemetry xử lý."""
    while True:
        try:
            print(f"[*] Connecting to {MANAGER_URL} ...")
            async with websockets.connect(MANAGER_URL) as ws:
                print(f"[+] Connected")
                await send_telemetry(ws)  # Heartbeat + telemetry trong 1 loop
        except Exception as e:
            print(f"[!] Error: {type(e).__name__}: {e}, retry in 5s")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
