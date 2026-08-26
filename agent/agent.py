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
import time

MANAGER_URL = os.getenv("MANAGER_URL", "ws://manager:8000/ws/agent")
AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())

ws_lock = asyncio.Lock()
def get_container_cpu_percent():
    """
    Tính CPU % sử dụng của container dựa trên cgroup v1/v2.
    Hỗ trợ cả cgroup v1 và v2.
    """
    try:
        # Thử cgroup v1 trước
        with open('/sys/fs/cgroup/cpu/cpuacct.usage', 'r') as f:
            usage = int(f.read().strip())
        with open('/sys/fs/cgroup/cpu/cpu.cfs_period_us', 'r') as f:
            period = int(f.read().strip())
        with open('/sys/fs/cgroup/cpu/cpu.cfs_quota_us', 'r') as f:
            quota = int(f.read().strip())
        if quota <= 0:  # Không giới hạn
            return psutil.cpu_percent(interval=0.1)
    except FileNotFoundError:
        # Thử cgroup v2
        try:
            with open('/sys/fs/cgroup/cpu.max', 'r') as f:
                line = f.read().strip()
                parts = line.split()
                if len(parts) == 2:
                    quota = parts[0]
                    period = parts[1]
                    if quota == "max":
                        return psutil.cpu_percent(interval=0.1)
                    quota = int(quota)
                    period = int(period)
                    # Đọc cpuacct.usage trong cgroup v2
                    with open('/sys/fs/cgroup/cpu.stat', 'r') as f2:
                        for line2 in f2:
                            if line2.startswith('usage_usec'):
                                usage_usec = int(line2.split()[1])
                                usage = usage_usec * 1000  # chuyển sang nanoseconds
                                break
        except Exception:
            return psutil.cpu_percent(interval=0.1)

    # Lần đầu, lưu giá trị
    now = time.time()
    if not hasattr(get_container_cpu_percent, 'prev_usage'):
        get_container_cpu_percent.prev_usage = usage
        get_container_cpu_percent.prev_time = now
        return 0.0

    prev_usage = get_container_cpu_percent.prev_usage
    prev_time = get_container_cpu_percent.prev_time
    delta_usage = usage - prev_usage
    delta_time = now - prev_time
    if delta_time <= 0:
        return 0.0

    # Tính số cores = quota / period
    cores = quota / period
    # CPU % = (delta_usage / 1e9) / (delta_time * cores) * 100
    cpu_percent = (delta_usage / 1e9) / (delta_time * cores) * 100
    get_container_cpu_percent.prev_usage = usage
    get_container_cpu_percent.prev_time = now
    return cpu_percent

def get_container_memory_percent():
    """Lấy % RAM sử dụng của container từ cgroup v1/v2."""
    try:
        # cgroup v1
        with open('/sys/fs/cgroup/memory/memory.usage_in_bytes', 'r') as f:
            usage = int(f.read().strip())
        with open('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'r') as f:
            limit = int(f.read().strip())
        if limit > 0:
            return (usage / limit) * 100
    except FileNotFoundError:
        # cgroup v2
        try:
            with open('/sys/fs/cgroup/memory.current', 'r') as f:
                usage = int(f.read().strip())
            with open('/sys/fs/cgroup/memory.max', 'r') as f:
                limit_str = f.read().strip()
                if limit_str == "max":
                    return psutil.virtual_memory().percent
                limit = int(limit_str)
                if limit > 0:
                    return (usage / limit) * 100
        except Exception:
            pass
    return psutil.virtual_memory().percent

def get_container_disk_percent():
    """Lấy % disk sử dụng của container (dựa trên thư mục /app)."""
    try:
        usage = psutil.disk_usage('/app')
        return usage.percent
    except Exception:
        return psutil.disk_usage('/').percent

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
        "cpu": get_container_cpu_percent(),
        "ram": get_container_memory_percent(),
        "disk": get_container_disk_percent(),
        "ip_address": get_ip_address(),
        "mac_address": get_mac_address(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def collect_process_info():
    """
    Thu thập thông tin toàn bộ tiến trình đang chạy trên host agent.
    Bao gồm PID, parent PID (ppid), name, exe, cmdline, cpu/memory %, và đánh dấu is_suspicious.
    """
    suspicious_keywords = [
        "mimikatz", "netcat", "nc", "nc.openbsd", "nc.traditional", "nmap", "chisel",
        "vssadmin", "powershell", "cmd.exe", "lsass.dump", "ransomware_sim",
        "backdoor_sim", "credential_dump", "lateral_movement", "c2_communication", "sleep", "certutil"
    ]
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                pid = info.get('pid')
                ppid = info.get('ppid')
                name = str(info.get('name') or "")
                exe = str(info.get('exe') or "")
                cmdline_list = info.get('cmdline') or []
                cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list)
                cpu_pct = float(info.get('cpu_percent') or 0.0)
                mem_pct = float(info.get('memory_percent') or 0.0)

                full_str = f"{name} {exe} {cmdline}".lower()
                is_suspicious = any(s in full_str for s in suspicious_keywords)

                processes.append({
                    "pid": pid,
                    "parent_pid": ppid,
                    "name": name,
                    "exe": exe,
                    "exe_path": exe,
                    "cmdline": cmdline,
                    "cpu_percent": cpu_pct,
                    "memory_percent": mem_pct,
                    "is_suspicious": is_suspicious
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"Error collecting process info: {e}", flush=True)

    return processes

def get_process_list():
    """Lấy danh sách process đang chạy, ưu tiên các process suspicious."""
    all_procs = collect_process_info()
    suspicious_procs = [p for p in all_procs if p["is_suspicious"]]
    normal_procs = [p for p in all_procs if not p["is_suspicious"]]
    return (suspicious_procs + normal_procs)[:30]

def get_network_connections():
    """Lấy các kết nối mạng đang mở, đánh dấu suspicious nếu cổng đích/nguồn nằm trong danh sách lạ."""
    suspicious_ports = {4444, 5555, 1337, 31337, 6667, 23, 8080, 445}
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ('ESTABLISHED', 'LISTEN'):
                laddr = conn.laddr
                raddr = conn.raddr
                src_ip = laddr.ip if laddr else "0.0.0.0"
                src_port = laddr.port if laddr else 0
                dst_ip = raddr.ip if raddr else "0.0.0.0"
                dst_port = raddr.port if raddr else src_port

                is_susp = (dst_port in suspicious_ports or src_port in suspicious_ports)

                connections.append({
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "status": conn.status,
                    "is_suspicious": is_susp
                })
    except Exception:
        pass

    suspicious_conns = [c for c in connections if c["is_suspicious"]]
    normal_conns = [c for c in connections if not c["is_suspicious"]]
    return (suspicious_conns + normal_conns)[:20]

def get_file_changes_count():
    """Đếm số file .encrypted hoặc có thay đổi gần đây trong /tmp (bao gồm thư mục con)."""
    count = 0
    try:
        for root, dirs, files in os.walk('/tmp'):
            for f in files:
                if f.endswith('.encrypted') or f.endswith('.dump') or f.endswith('.bak'):
                    count += 1
    except Exception:
        pass
    return count

def collect_registry_changes():
    """
    Thu thập các file .reg và nội dung registry / system config persistence giả lập trong /tmp và /etc/hosts.
    """
    changes = []
    try:
        if os.path.exists('/tmp'):
            for root, dirs, files in os.walk('/tmp'):
                for f in files:
                    if f.endswith('.reg'):
                        path = os.path.join(root, f)
                        try:
                            with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                                content = fp.read()
                            if 'CurrentVersion\\Run' in content or 'CurrentVersion\\RunOnce' in content or 'HKEY_LOCAL_MACHINE' in content or 'HKEY_CURRENT_USER' in content:
                                changes.append({
                                    "path": path,
                                    "action": "write",
                                    "key_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                    "value_name": "BackdoorService",
                                    "value_data": "C:\\Windows\\System32\\cmd.exe /c start /b malware.exe"
                                })
                        except Exception:
                            pass
        if os.path.exists('/etc/hosts'):
            try:
                with open('/etc/hosts', 'r', encoding='utf-8', errors='ignore') as fp:
                    content = fp.read()
                if 'persistence.test.local' in content or 'CurrentVersion\\Run' in content:
                    changes.append({
                        "path": "/etc/hosts",
                        "action": "modify",
                        "key_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "value_name": "hosts_persistence",
                        "value_data": "127.0.0.2 persistence.test.local"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"Error collecting registry changes: {e}", flush=True)

    return changes

async def send_ws_json(websocket, message):
    async with ws_lock:
        await websocket.send(json.dumps(message))
        try:
            raw_res = await asyncio.wait_for(websocket.recv(), timeout=5)
            return json.loads(raw_res)
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            print(f"WS response read error: {e}", flush=True)
            return None

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
        try:
            stats = collect_stats()
            message = {"type": "HEARTBEAT", "payload": stats}
            response = await send_ws_json(websocket, message)
            if response and isinstance(response, dict) and "pending_commands" in response:
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
                    await send_ws_json(websocket, ack_message)
        except Exception as e:
            print(f"Error in send_stats loop: {e}", flush=True)
        await asyncio.sleep(10)

async def send_risk_telemetry(websocket):
    await asyncio.sleep(2)
    while True:
        try:
            procs = get_process_list()
            conns = get_network_connections()
            file_changes = get_file_changes_count()
            registry_changes = collect_registry_changes()
            suspicious_cmds = [p["cmdline"] for p in procs if p.get("is_suspicious") and p.get("cmdline")]

            cred_events = []
            if os.path.exists("/tmp/lsass.dump"):
                cred_events.append({"target_object": "lsass.dump", "action": "read"})

            payload = {
                "agent_id": AGENT_ID,
                "cpu_usage": get_container_cpu_percent(),
                "ram_usage": get_container_memory_percent(),
                "disk_usage": get_container_disk_percent(),
                "process_list": procs,
                "network_connections": conns,
                "file_changes_count": file_changes,
                "suspicious_commands": suspicious_cmds,
                "shadow_copy_deletion": False,
                "mass_file_modification": file_changes > 20,
                "registry_changes": registry_changes,
                "credential_access_events": cred_events,
                "lateral_movement_events": [],
                "dns_queries": [],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            message = {"type": "TELEMETRY_RISK", "payload": payload}
            print(f"[TELEMETRY_RISK] Sending payload for '{AGENT_ID}' (procs: {len(procs)}, conns: {len(conns)}, file_changes: {file_changes})", flush=True)
            res = await send_ws_json(websocket, message)
            if res:
                print(f"[TELEMETRY_RISK] Server ACK response: {res}", flush=True)
        except Exception as e:
            print(f"Error sending risk telemetry: {e}", flush=True)
        await asyncio.sleep(15)

async def send_process_list(websocket):
    """
    Gửi danh sách toàn bộ process định kỳ mỗi 15-20s tới Manager qua WebSocket message 'PROCESS_LIST'.
    """
    await asyncio.sleep(3)
    while True:
        try:
            procs = collect_process_info()
            message = {
                "type": "PROCESS_LIST",
                "payload": {
                    "agent_id": AGENT_ID,
                    "processes": procs,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
            print(f"[PROCESS_LIST] Sending complete process list for '{AGENT_ID}' ({len(procs)} processes)", flush=True)
            res = await send_ws_json(websocket, message)
            if res:
                print(f"[PROCESS_LIST] Server ACK response: {res}", flush=True)
        except Exception as e:
            print(f"Error sending process list: {e}", flush=True)
        await asyncio.sleep(20)

async def main_agent():
    while True:
        try:
            async with websockets.connect(
                MANAGER_URL,
                ping_interval=20,
                ping_timeout=20,
            ) as ws:
                print(f"Connected to {MANAGER_URL}", flush=True)
                await asyncio.gather(
                    send_stats(ws),
                    send_risk_telemetry(ws),
                    send_process_list(ws),
                )
        except Exception as e:
            print(f"Error: {e}. Retrying in 5s...", flush=True)
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main_agent())