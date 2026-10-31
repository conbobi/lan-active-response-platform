import sys
import os
import json
import time
import asyncio
from typing import List, Dict, Any
from datetime import datetime
import psutil
import websockets

AGENT_ID = os.getenv("AGENT_ID", "WIN-DEMO-01")
MANAGER_URL = os.getenv("MANAGER_URL", "wss://edr.alwayready.id.vn/ws/agent")

# ⚠️ QUAN TRỌNG: 15 giây (không phải 0.5s)
# 0.5s = test nhanh (spam log), 15s = production
INTERVAL = float(os.getenv("AGENT_INTERVAL", "15"))


import subprocess
import shutil
import hashlib
from urllib.parse import urlparse
import socket
import re

# ============ ISOLATION ============
ISOLATE_RULE_PREFIX = "LARP_ISOLATE_"

def get_manager_ip_port():
    """Parse IP + port của Manager từ MANAGER_URL."""
    parsed = urlparse(MANAGER_URL)
    host = parsed.hostname or "192.168.30.105"
    port = parsed.port or 8005
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    return ip, port


def handle_isolate(payload):
    """Selective isolation: block all except Manager IP:port."""
    manager_ip, manager_port = get_manager_ip_port()
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_OUT"], capture_output=True)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_IN"], capture_output=True)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_OUT",
            "dir=out", "action=allow",
            f"remoteip={manager_ip}", f"remoteport={str(manager_port)}", "protocol=TCP"
        ], check=True, capture_output=True)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_IN",
            "dir=in", "action=allow",
            f"remoteip={manager_ip}", "protocol=TCP"
        ], check=True, capture_output=True)
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,blockoutbound"],
                       check=False, capture_output=True)
        return {"status": "success",
                "message": f"Isolated. Manager {manager_ip}:{manager_port} whitelisted",
                "manager_ip": manager_ip, "manager_port": manager_port}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_unisolate(payload):
    try:
        for rule_name in [f"{ISOLATE_RULE_PREFIX}ALLOW_MGR_OUT",
                          f"{ISOLATE_RULE_PREFIX}ALLOW_MGR_IN"]:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={rule_name}"], capture_output=True)
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "allowinbound,allowoutbound"], capture_output=True)
        return {"status": "success", "message": "Network unisolated"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============ KILL PROCESS ============
def handle_kill_process(payload):
    pid = payload.get("pid")
    if not pid:
        return {"status": "error", "message": "Missing PID"}
    try:
        result = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return {"status": "success", "message": f"Killed PID {pid}"}
        return {"status": "error", "message": result.stderr or result.stdout}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_kill_process_tree(payload):
    pid = payload.get("pid")
    if not pid:
        return {"status": "error", "message": "Missing PID"}
    try:
        result = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return {"status": "success", "message": f"Killed tree PID {pid}"}
        return {"status": "error", "message": result.stderr or result.stdout}
    except Exception as e:
        return {"status": "error", "message": str(e)}

handle_kill_tree = handle_kill_process_tree


# ============ QUARANTINE ============
QUARANTINE_DIR = "C:\\ProgramData\\LARP\\Quarantine"

def handle_quarantine(payload):
    file_path = payload.get("file_path") or payload.get("path")
    if not file_path:
        return {"status": "error", "message": "Missing file_path"}
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"Not found: {file_path}"}
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        ts = int(time.time())
        basename = os.path.basename(file_path)
        dest_path = os.path.join(QUARANTINE_DIR, f"{ts}_{basename}.quarantine")
        shutil.move(file_path, dest_path)
        meta = {"original_path": file_path, "quarantine_path": dest_path,
                "sha256": file_hash, "quarantined_at": ts}
        with open(f"{dest_path}.meta", "w") as f:
            json.dump(meta, f, indent=2)
        return {"status": "success", "quarantine_path": dest_path, "sha256": file_hash}
    except Exception as e:
        return {"status": "error", "message": str(e)}


COMMAND_HANDLERS = {
    "isolate": handle_isolate,
    "unisolate": handle_unisolate,
    "kill": handle_kill_process,
    "kill_process": handle_kill_process,
    "kill_tree": handle_kill_process_tree,
    "kill_process_tree": handle_kill_process_tree,
    "quarantine": handle_quarantine,
}


SUSPICIOUS_PATTERNS = [
    r"\bmimikatz\b", r"\bmeterpreter\b", r"\bcobaltstrike\b", r"\blazagne\b",
    r"\bprocdump(?:\.exe)?\b.*\blsass\b", r"\bcomsvcs\.dll\b.*MiniDump",
    r"\bsekurlsa::", r"\blsadump::", r"\bkerberos::golden",
    r"\bnc(?:\.exe)?\b.*-e\b.*(?:cmd|powershell|sh|bash)", r"\bncat\b.*-e\b",
    r"\bpowershell\b.*-enc\b.*[A-Za-z0-9+/=]{50,}",
    r"\bpowershell\b.*-w(?:indowstyle)?\s+hidden",
    r"\bmsbuild(?:\.exe)?\b.*/t:Run",
    r"\bcertutil\b.*-urlcache.*-split.*-f\s+http",
    r"\bcertutil\b.*-decodehex",
    r"\\users\\public\\[^\\/\s\"']+\.(?:exe|dll|ps1|vbs|js)\b",
    r"\\appdata\\local\\temp\\[^\\/\s\"']+\.(?:exe|dll|ps1|vbs|js)\b",
]


def is_process_suspicious(name: str, cmdline: str, exe: str = "") -> bool:
    if not cmdline or not name:
        return False
    full_str = f"{name} {cmdline} {exe}".lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, full_str, re.IGNORECASE):
            return True
    return False


def collect_processes() -> List[Dict[str, Any]]:
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            cmdline_raw = info.get('cmdline')
            cmdline = " ".join(str(arg) for arg in cmdline_raw) if isinstance(cmdline_raw, list) else str(cmdline_raw or "")
            processes.append({
                "pid": info.get("pid"), "ppid": info.get("ppid"),
                "name": info.get("name") or "", "exe": info.get("exe") or "",
                "cmdline": cmdline, "is_suspicious": False,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    return processes


def collect_network() -> List[Dict[str, Any]]:
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or not conn.pid:
                continue
            try:
                proc = psutil.Process(conn.pid)
                proc_name = proc.name()
                cmdline = ' '.join(proc.cmdline() or [])[:200]
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                proc_name = 'unknown'
                cmdline = ''
            laddr, raddr = conn.laddr, conn.raddr
            if not raddr:
                continue
            connections.append({
                "pid": conn.pid, "process_name": proc_name, "cmdline": cmdline,
                "src_ip": laddr.ip if laddr else "", "src_port": laddr.port if laddr else 0,
                "dst_ip": raddr.ip if raddr else "", "dst_port": raddr.port if raddr else 0,
                "protocol": "TCP",
            })
    except Exception as e:
        print(f"[!] collect_network error: {e}")
    return connections


# ============ HEARTBEAT ACK TRACKING (fix half-open) ============
_last_message_time = time.time()
_last_heartbeat_sent = 0.0


def _log(msg: str):
    """Log với timestamp để dễ debug timeline."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


async def send_telemetry(ws) -> None:
    """Gửi heartbeat + telemetry mỗi INTERVAL giây."""
    global _last_heartbeat_sent
    while True:
        try:
            now = time.time()
            _last_heartbeat_sent = now
            
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

            procs = collect_processes()
            conns = collect_network()

            await ws.send(json.dumps({
                "type": "PROCESS_LIST",
                "payload": {"agent_id": AGENT_ID, "processes": procs, "timestamp": now},
                "wait_ack": False,
            }))

            await ws.send(json.dumps({
                "type": "TELEMETRY_RISK",
                "payload": {
                    "agent_id": AGENT_ID, "platform": "windows",
                    "process_list": procs, "network_connections": conns,
                    "timestamp": now,
                }
            }))
            
            _log(f"[+] Sent HB + PROCESS_LIST ({len(procs)}) + telemetry ({len(conns)} conns)")
            await asyncio.sleep(INTERVAL)
            
        except websockets.exceptions.ConnectionClosed as e:
            _log(f"[!] Connection closed (send): code={e.code} — reconnect")
            raise
        except Exception as e:
            _log(f"[!] Send error: {type(e).__name__}: {e}")
            raise


async def _execute_and_ack(ws, command_id, action, params):
    _log(f"[*] Received command: {action} (id={command_id})")
    handler = COMMAND_HANDLERS.get(action)
    result = handler(params) if handler else {"status": "error", "message": f"Unknown: {action}"}
    status_str = "success" if result.get("status") == "success" else "failed"
    ack = {
        "type": "COMMAND_ACK",
        "payload": {
            "command_id": command_id, "status": status_str,
            "error_message": result.get("message") if status_str == "failed" else None,
            "result": result, "executed_at": time.time(),
        }
    }
    await ws.send(json.dumps(ack))
    _log(f"[+] ACK sent: {action} -> {result.get('status')}")


async def receive_commands(ws) -> None:
    """Nhận mọi message từ Manager — cập nhật _last_message_time mỗi lần."""
    global _last_message_time
    async for raw in ws:
        _last_message_time = time.time()  # ← BẤT KỲ message nào = Manager còn sống
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "COMMAND":
                payload = msg.get("payload", {})
                await _execute_and_ack(
                    ws,
                    payload.get("command_id"),
                    payload.get("action"),
                    payload.get("params") or payload.get("payload") or {},
                )
            elif "pending_commands" in msg:
                # Heartbeat response = ack (đã update _last_message_time ở trên)
                for cmd in msg["pending_commands"]:
                    await _execute_and_ack(
                        ws,
                        cmd.get("command_id"),
                        cmd.get("action"),
                        cmd.get("payload") or {},
                    )
            # else: heartbeat_ack, ping, etc → đã update time, không cần log
        except websockets.exceptions.ConnectionClosed:
            _log("[!] Connection closed (recv) — reconnect")
            raise
        except Exception as e:
            _log(f"[!] Recv error: {type(e).__name__}: {e}")


async def monitor_connection():
    """
    Watchdog: nếu > 90 giây không nhận message từ Manager → force close.
    Fix trường hợp Manager process còn sống nhưng heartbeat handler crash.
    """
    global _last_message_time
    while True:
        await asyncio.sleep(30)
        idle = time.time() - _last_message_time
        if idle > 90:
            _log(f"[!] WATCHDOG: No message from Manager in {idle:.0f}s — forcing reconnect")
            raise ConnectionError(f"No message from Manager in {idle:.0f}s")


async def main() -> None:
    """Reconnect loop với exponential backoff + ping/pong."""
    retry = 1
    max_retry = 30
    
    while True:
        try:
            _log(f"[*] Connecting to {MANAGER_URL} ...")
            
            # ⚠️ KEY FIX: ping_interval + ping_timeout
            # Library tự gửi PING mỗi 20s, expect PONG trong 10s
            # Nếu không nhận PONG → raise ConnectionClosed → exit async with → reconnect
            async with websockets.connect(
                MANAGER_URL,
                ping_interval=20,       # ← Gửi PING mỗi 20s
                ping_timeout=10,        # ← Timeout PONG sau 10s
                close_timeout=5,
                open_timeout=15,
                max_size=16 * 1024 * 1024,  # 16MB cho process list lớn
            ) as ws:
                _log(f"[+] Connected — ping_interval=20s")
                retry = 1  # Reset backoff
                
                # Reset watchdog time
                global _last_message_time
                _last_message_time = time.time()
                
                # Chạy SONG SONG: send + receive + watchdog
                await asyncio.gather(
                    send_telemetry(ws),
                    receive_commands(ws),
                    monitor_connection(),
                )
                
        except websockets.exceptions.ConnectionClosed as e:
            _log(f"[!] ConnectionClosed: code={e.code} reason={e.reason}")
        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
            _log(f"[!] Network error: {type(e).__name__}: {e}")
        except Exception as e:
            _log(f"[!] Unexpected: {type(e).__name__}: {e}")
        
        _log(f"[*] Reconnect in {retry}s...")
        await asyncio.sleep(retry)
        retry = min(retry * 2, max_retry)


if __name__ == "__main__":
    asyncio.run(main())