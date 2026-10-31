import sys
import os
import json
import time
import asyncio
from typing import List, Dict, Any
import psutil
import websockets

AGENT_ID = os.getenv("AGENT_ID", "WIN-DEMO-01")
MANAGER_URL = os.getenv("MANAGER_URL", "wss://edr.alwayready.id.vn/ws/agent")
INTERVAL = 0.5


import subprocess
import shutil
import hashlib
from urllib.parse import urlparse
import socket

# ============ ISOLATION ============
ISOLATE_RULE_PREFIX = "LARP_ISOLATE_"

def get_manager_ip_port():
    """Parse IP + port của Manager từ MANAGER_URL."""
    parsed = urlparse(MANAGER_URL)
    host = parsed.hostname or "192.168.30.105"
    port = parsed.port or 8005
    # Resolve hostname → IP nếu cần
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    return ip, port


def handle_isolate(payload):
    """Selective isolation: block all except Manager IP:port."""
    manager_ip, manager_port = get_manager_ip_port()
    
    try:
        # Xóa rules cũ (idempotent)
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_OUT"],
            capture_output=True
        )
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_IN"],
            capture_output=True
        )
        
        # Cho phép Manager IP outbound (WebSocket)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_OUT",
            "dir=out", "action=allow",
            f"remoteip={manager_ip}",
            f"remoteport={str(manager_port)}",
            "protocol=TCP"
        ], check=True, capture_output=True)
        
        # Cho phép Manager inbound (response packets)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={ISOLATE_RULE_PREFIX}ALLOW_MGR_IN",
            "dir=in", "action=allow",
            f"remoteip={manager_ip}",
            "protocol=TCP"
        ], check=True, capture_output=True)
        
        # Block tất cả outbound còn lại
        subprocess.run([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,blockoutbound"
        ], check=False, capture_output=True)
        
        return {
            "status": "success",
            "message": f"Isolated. Manager {manager_ip}:{manager_port} whitelisted",
            "manager_ip": manager_ip,
            "manager_port": manager_port,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_unisolate(payload):
    """Remove isolation rules, restore network."""
    try:
        for rule_name in [f"{ISOLATE_RULE_PREFIX}ALLOW_MGR_OUT",
                          f"{ISOLATE_RULE_PREFIX}ALLOW_MGR_IN"]:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True
            )
        
        # Restore allow all
        subprocess.run([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "allowinbound,allowoutbound"
        ], capture_output=True)
        
        return {"status": "success", "message": "Network unisolated"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============ KILL PROCESS ============
def handle_kill_process(payload):
    pid = payload.get("pid")
    if not pid:
        return {"status": "error", "message": "Missing PID"}
    
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, text=True, timeout=10
        )
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
        result = subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            return {"status": "success", "message": f"Killed tree PID {pid}"}
        return {"status": "error", "message": result.stderr or result.stdout}
    except Exception as e:
        return {"status": "error", "message": str(e)}

handle_kill_tree = handle_kill_process_tree


# ============ QUARANTINE FILE ============
QUARANTINE_DIR = "C:\\ProgramData\\LARP\\Quarantine"

def handle_quarantine(payload):
    file_path = payload.get("file_path") or payload.get("path")
    if not file_path:
        return {"status": "error", "message": "Missing file_path"}
    
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"Not found: {file_path}"}
    
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        
        # Hash trước khi move
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        
        # Move vào quarantine
        ts = int(time.time())
        basename = os.path.basename(file_path)
        dest_name = f"{ts}_{basename}.quarantine"
        dest_path = os.path.join(QUARANTINE_DIR, dest_name)
        
        shutil.move(file_path, dest_path)
        
        # Metadata
        meta = {
            "original_path": file_path,
            "quarantine_path": dest_path,
            "sha256": file_hash,
            "quarantined_at": ts,
        }
        with open(f"{dest_path}.meta", "w") as f:
            json.dump(meta, f, indent=2)
        
        return {
            "status": "success",
            "quarantine_path": dest_path,
            "sha256": file_hash,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============ DISPATCH MAP ============
COMMAND_HANDLERS = {
    "isolate": handle_isolate,
    "unisolate": handle_unisolate,
    "kill": handle_kill_process,
    "kill_process": handle_kill_process,
    "kill_tree": handle_kill_process_tree,
    "kill_process_tree": handle_kill_process_tree,
    "quarantine": handle_quarantine,
}


import re

SUSPICIOUS_PATTERNS = [
    # Tool tấn công cụ thể — match full word/pattern
    r"\bmimikatz\b",
    r"\bmeterpreter\b",
    r"\bcobaltstrike\b",
    r"\blazagne\b",
    r"\bprocdump(?:\.exe)?\b.*\blsass\b",       # procdump dump lsass
    r"\bcomsvcs\.dll\b.*MiniDump",              # LOLBin
    r"\bsekurlsa::",                            # mimikatz commands
    r"\blsadump::",
    r"\bkerberos::golden",

    # Reverse shell patterns
    r"\bnc(?:\.exe)?\b.*-e\b.*(?:cmd|powershell|sh|bash)",  # nc reverse shell
    r"\bncat\b.*-e\b",
    r"\bpowershell\b.*-enc\b.*[A-Za-z0-9+/=]{50,}",         # PS encoded
    r"\bpowershell\b.*-w(?:indowstyle)?\s+hidden",

    # MSBuild inline exec (đã có trong living_off_land nhưng backup)
    r"\bmsbuild(?:\.exe)?\b.*/t:Run",

    # Certificate abuse
    r"\bcertutil\b.*-urlcache.*-split.*-f\s+http",
    r"\bcertutil\b.*-decodehex",

    # Suspicious paths (chỉ match file thực thi trực tiếp trong thư mục temp/public)
    r"\\users\\public\\[^\\/\s\"']+\.(?:exe|dll|ps1|vbs|js)\b",
    r"\\appdata\\local\\temp\\[^\\/\s\"']+\.(?:exe|dll|ps1|vbs|js)\b",
]


def is_process_suspicious(name: str, cmdline: str, exe: str = "") -> bool:
    """Check process suspicion — KHÔNG dựa vào tên process, chỉ cmdline/path."""
    if not cmdline or not name:
        return False

    full_str = f"{name} {cmdline} {exe}".lower()

    # Match patterns (regex)
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, full_str, re.IGNORECASE):
            return True

    return False


def collect_processes() -> List[Dict[str, Any]]:
    """
    Collect running processes on Windows using psutil.
    Extracts pid, ppid, name, exe path, command line arguments.
    Agent sends raw data; manager performs authoritative risk evaluation.
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

            name = info.get("name") or ""
            exe = info.get("exe") or ""

            processes.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "is_suspicious": False,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    return processes


def collect_network() -> List[Dict[str, Any]]:
    """
    Collect established network connections with associated PID, process name, and cmdline.
    """
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

            laddr = conn.laddr
            raddr = conn.raddr
            if not raddr:
                continue

            connections.append({
                "pid": conn.pid,
                "process_name": proc_name,
                "cmdline": cmdline,
                "src_ip": laddr.ip if laddr else "",
                "src_port": laddr.port if laddr else 0,
                "dst_ip": raddr.ip if raddr else "",
                "dst_port": raddr.port if raddr else 0,
                "protocol": "TCP",
            })
    except Exception as e:
        print(f"[!] collect_network error: {e}")
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

            # 2. Thu thập processes & network
            procs = collect_processes()
            conns = collect_network()

            # 3. Gửi PROCESS_LIST để Manager lưu vào bảng process_info phục vụ Process Tree UI
            proc_list_msg = {
                "type": "PROCESS_LIST",
                "payload": {
                    "agent_id": AGENT_ID,
                    "processes": procs,
                    "timestamp": time.time(),
                },
                "wait_ack": False,
            }
            await ws.send(json.dumps(proc_list_msg))

            # 4. Gửi TELEMETRY_RISK để tính toán risk score
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
            print(f"[+] Heartbeat + PROCESS_LIST ({len(procs)}) + telemetry: {len(conns)} conns")

            await asyncio.sleep(INTERVAL)
        except websockets.exceptions.ConnectionClosed:
            print("[!] Connection closed by server, reconnect...")
            raise
        except Exception as e:
            print(f"[!] Send error: {type(e).__name__}: {e}")
            raise


async def _execute_and_ack(ws, command_id, action, params):
    print(f"[*] Received command: {action} (id={command_id})")
    handler = COMMAND_HANDLERS.get(action)
    if handler:
        result = handler(params)
    else:
        result = {"status": "error", "message": f"Unknown action: {action}"}

    # Map status to valid CommandStatus ('success' or 'failed') for backend schema validation
    status_str = "success" if result.get("status") == "success" else "failed"
    ack = {
        "type": "COMMAND_ACK",
        "payload": {
            "command_id": command_id,
            "status": status_str,
            "error_message": result.get("message") if status_str == "failed" else None,
            "result": result,
            "executed_at": time.time(),
        }
    }
    await ws.send(json.dumps(ack))
    print(f"[+] ACK sent: {action} -> {result.get('status')}")


async def receive_commands(ws) -> None:
    """Lắng nghe command từ Manager và thực thi."""
    async for raw in ws:
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "COMMAND":
                payload = msg.get("payload", {})
                command_id = payload.get("command_id")
                action = payload.get("action")
                params = payload.get("params") or payload.get("payload") or {}
                await _execute_and_ack(ws, command_id, action, params)
            elif "pending_commands" in msg:
                # Commands piggybacked in HEARTBEAT response
                for cmd in msg["pending_commands"]:
                    command_id = cmd.get("command_id")
                    action = cmd.get("action")
                    params = cmd.get("payload") or {}
                    await _execute_and_ack(ws, command_id, action, params)
            else:
                if msg_type:
                    print(f"[*] Ignored msg type: {msg_type}")
        except websockets.exceptions.ConnectionClosed:
            print("[!] Connection closed by server in receive_commands, reconnect...")
            raise
        except Exception as e:
            print(f"[!] Receive error: {type(e).__name__}: {e}")


async def main() -> None:
    """Chạy SEND và RECEIVE song song."""
    while True:
        try:
            print(f"[*] Connecting to {MANAGER_URL} ...")
            async with websockets.connect(MANAGER_URL) as ws:
                print(f"[+] Connected")

                # Chạy SONG SONG: gửi telemetry + nhận command
                await asyncio.gather(
                    send_telemetry(ws),
                    receive_commands(ws),
                )
        except Exception as e:
            print(f"[!] Error: {type(e).__name__}: {e}, retry in 5s")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
