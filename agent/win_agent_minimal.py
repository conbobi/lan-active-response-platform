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
def handle_isolate(payload: dict) -> dict:
    """Isolate host — bật firewall, block outbound + inbound, whitelist manager, kill active sessions."""
    import subprocess
    import platform
    from urllib.parse import urlparse
    import socket
    
    system = platform.system()
    parsed = urlparse(MANAGER_URL)
    manager_host = parsed.hostname or (
        MANAGER_URL.split("//")[1].split("/")[0].split(":")[0] 
        if "//" in MANAGER_URL else "unknown"
    )
    try:
        manager_ip = socket.gethostbyname(manager_host)
    except Exception:
        manager_ip = manager_host
    
    try:
        if system == "Windows":
            # ─── BƯỚC 1: Bật firewall state ON trước ───
            enable_fw = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                capture_output=True, text=True, timeout=15
            )
            if enable_fw.returncode != 0:
                return {"status": "failed", 
                        "message": f"Enable firewall failed: {enable_fw.stderr or enable_fw.stdout}"}
            print(f"[AGENT] Firewall state enabled ON")
            
            # ─── BƯỚC 2: Clean rules cũ (idempotent) ───
            for rule_name in ("LARP_ALLOW_MANAGER", "LARP_BLOCK_OUT", "LARP_BLOCK_IN"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, timeout=5
                )
            
            # ─── BƯỚC 3: Allow manager TRƯỚC (tránh lockout) ───
            r_allow = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=LARP_ALLOW_MANAGER", "dir=out", "action=allow",
                f"remoteip={manager_ip}", "enable=yes", "profile=any"
            ], capture_output=True, text=True, timeout=10)
            if r_allow.returncode != 0:
                return {"status": "failed", 
                        "message": f"Allow manager rule failed: {r_allow.stderr}"}
            print(f"[AGENT] Allowed manager {manager_ip}")
            
            # ─── BƯỚC 4: Block outbound ───
            r_block_out = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=LARP_BLOCK_OUT", "dir=out", "action=block",
                "enable=yes", "profile=any"
            ], capture_output=True, text=True, timeout=10)
            if r_block_out.returncode != 0:
                return {"status": "failed", 
                        "message": f"Block outbound failed: {r_block_out.stderr}"}
            print(f"[AGENT] Block outbound enabled")
            
            # ─── BƯỚC 5: Block inbound ───
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=LARP_BLOCK_IN", "dir=in", "action=block",
                "enable=yes", "profile=any"
            ], capture_output=True, timeout=10)
            print(f"[AGENT] Block inbound enabled")
            
            # ─── BƯỚC 6: Kill established TCP sessions (trừ manager + localhost) ───
            ps_script = f"""
$excluded = @('127.0.0.1', '::1', '{manager_ip}')
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
    Where-Object {{ $excluded -notcontains $_.RemoteAddress }} | 
    ForEach-Object {{ 
        try {{ 
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue 
        }} catch {{ }} 
    }}
"""
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True, timeout=20
                )
                print(f"[AGENT] Killed established sessions (except manager {manager_ip})")
            except subprocess.TimeoutExpired:
                print(f"[AGENT] WARNING: kill sessions timeout — continuing anyway")
            except Exception as e:
                print(f"[AGENT] WARNING: kill sessions failed: {e} — continuing anyway")
            
            return {
                "status": "success",
                "message": f"Host isolated (firewall ON, manager={manager_ip} whitelisted)"
            }
        
        elif system == "Linux":
            # Giữ nguyên logic iptables hiện tại (không đổi)
            subprocess.run(["iptables", "-F", "OUTPUT"], check=False)
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", manager_ip, "-j", "ACCEPT"],
                check=True, timeout=10
            )
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                check=True, timeout=10
            )
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-j", "DROP"],
                check=True, timeout=10
            )
            return {"status": "success", "message": "Host isolated via iptables"}
        
        else:
            return {"status": "failed", "message": f"Unsupported platform: {system}"}
    
    except subprocess.TimeoutExpired as e:
        return {"status": "failed", "message": f"Command timeout: {e}"}
    except Exception as e:
        return {"status": "failed", "message": f"{type(e).__name__}: {e}"}


def handle_unisolate(payload: dict) -> dict:
    """Remove isolation rules. KHÔNG tắt firewall state (giữ ON cho bảo mật)."""
    import subprocess
    import platform
    
    system = platform.system()
    try:
        if system == "Windows":
            # Chỉ xóa 3 rules LARP
            for rule_name in ("LARP_BLOCK_OUT", "LARP_BLOCK_IN", "LARP_ALLOW_MANAGER"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, timeout=5
                )
            # KHÔNG chạy: netsh advfirewall set allprofiles state off
            # Lý do: firewall OFF làm giảm bảo mật toàn hệ thống
            return {"status": "success", 
                    "message": "Host unisolated (rules removed, firewall still ON)"}
        
        elif system == "Linux":
            subprocess.run(["iptables", "-F", "OUTPUT"], check=False)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=False)
            return {"status": "success", "message": "Host unisolated"}
        
        else:
            return {"status": "failed", "message": f"Unsupported platform: {system}"}
    except Exception as e:
        return {"status": "failed", "message": f"{type(e).__name__}: {e}"}


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
    "auto_isolate": handle_isolate,
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


def _get_ip_address() -> str:
    env_ip = os.getenv("AGENT_IP")
    if env_ip:
        return env_ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


async def send_telemetry(ws) -> None:
    """Gửi heartbeat + telemetry mỗi INTERVAL giây và xử lý pending_commands."""
    global _last_heartbeat_sent, _last_message_time
    while True:
        try:
            now = time.time()
            _last_heartbeat_sent = now

            cpu_val = float(psutil.cpu_percent(interval=None))
            ram_val = float(psutil.virtual_memory().percent)
            try:
                disk_val = float(
                    psutil.disk_usage('C:\\').percent 
                    if os.name == 'nt' 
                    else psutil.disk_usage('/').percent
                )
            except Exception:
                disk_val = 0.0

            heartbeat = {
                "type": "HEARTBEAT",
                "payload": {
                    "agent_id": AGENT_ID,
                    "hostname": socket.gethostname(),
                    "platform": "windows",
                    "ip_address": _get_ip_address(),
                    "cpu": cpu_val,
                    "ram": ram_val,
                    "disk": disk_val,
                }
            }
            await ws.send(json.dumps(heartbeat))

            # === FIX: Parse response và handle pending_commands ===
            try:
                response_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                _last_message_time = time.time()
                response = json.loads(response_raw)

                pending = response.get("pending_commands", [])
                if pending:
                    _log(f"[AGENT] Received {len(pending)} pending commands from heartbeat")
                    for cmd in pending:
                        command_id = cmd.get("command_id") or cmd.get("id")
                        action = cmd.get("action")
                        params = cmd.get("payload") or cmd.get("params") or {}
                        _log(f"[AGENT] Executing command {command_id}: {action}")
                        await _execute_and_ack(ws, command_id, action, params)
            except asyncio.TimeoutError:
                _log("[AGENT] Heartbeat response timeout (5s)")
            except json.JSONDecodeError as e:
                _log(f"[AGENT] Failed to parse heartbeat response: {e}")
                _log(f"[AGENT] Raw: {response_raw[:200]}")
            except Exception as e:
                _log(f"[AGENT] Error handling heartbeat response: {type(e).__name__}: {e}")

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
                },
                "wait_ack": False,
            }))

            _log(f"[+] Sent HB + PROCESS_LIST ({len(procs)}) + telemetry ({len(conns)} conns)")
            await asyncio.sleep(INTERVAL)

        except websockets.exceptions.ConnectionClosed as e:
            _log(f"[!] Connection closed in send_telemetry: code={e.code} — reconnect")
            raise
        except Exception as e:
            _log(f"[!] send_telemetry error: {type(e).__name__}: {e}")
            await asyncio.sleep(INTERVAL)


async def _execute_and_ack(ws, command_id: str, action: str, params: dict) -> None:
    """Execute command và gửi COMMAND_ACK với status thật."""
    if not command_id:
        _log(f"[AGENT] WARNING: missing command_id for action {action}")
        return

    handler = COMMAND_HANDLERS.get(action)
    if not handler:
        _log(f"[AGENT] No handler for action: {action}")
        ack = {
            "type": "COMMAND_ACK",
            "payload": {
                "command_id": command_id,
                "status": "failed",
                "error_message": f"No handler registered for action '{action}'",
            }
        }
        try:
            await ws.send(json.dumps(ack))
        except Exception as e:
            _log(f"[AGENT] Failed to send error ACK: {e}")
        return

    try:
        result = await handler(params) if asyncio.iscoroutinefunction(handler) else handler(params)
        # Handler trả dict {"status": "success"|"failed", "message": "..."}
        # Hoặc trả None (legacy) -> coi như success
        if result is None:
            status = "success"
            error = None
        elif isinstance(result, dict):
            status = result.get("status", "success")
            error = result.get("message") if status == "failed" else None
        else:
            status = "success"
            error = None

        ack = {
            "type": "COMMAND_ACK",
            "payload": {
                "command_id": command_id,
                "status": status,
                "executed_at": time.time(),
            }
        }
        if error:
            ack["payload"]["error_message"] = error

        await ws.send(json.dumps(ack))
        _log(f"[AGENT] Sent ACK for {command_id}: {status}" + (f" ({error})" if error else ""))

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        _log(f"[AGENT] Handler {action} raised exception: {error_msg}")
        ack = {
            "type": "COMMAND_ACK",
            "payload": {
                "command_id": command_id,
                "status": "failed",
                "error_message": error_msg,
            }
        }
        try:
            await ws.send(json.dumps(ack))
        except Exception as send_err:
            _log(f"[AGENT] Failed to send failure ACK: {send_err}")


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
                
                # Chạy SONG SONG: send_telemetry (pull commands + telemetry) + watchdog
                await asyncio.gather(
                    send_telemetry(ws),
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


