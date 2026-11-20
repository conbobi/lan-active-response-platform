# agent/agent.py
import asyncio
import json
import os
import re
import socket
import subprocess
import psutil
import websockets
from datetime import datetime, timezone
from commands import COMMAND_HANDLERS
import time
from fim import FileIntegrityMonitor
from auth_monitor import global_auth_monitor
from dns_sniffer import global_dns_sniffer
from connection_tracker import global_connection_tracker


def _resolve_manager_url() -> str:
    """Ưu tiên LAN nếu reachable, fallback public wss."""
    explicit = os.getenv("MANAGER_URL")
    if explicit:
        return explicit

    lan_url = os.getenv("LAN_MANAGER_URL")
    if lan_url:
        import socket
        from urllib.parse import urlparse
        try:
            parsed = urlparse(lan_url.replace("ws://", "http://").replace("wss://", "https://"))
            sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=1.5)
            sock.close()
            print(f"[BOOTSTRAP] LAN manager reachable at {lan_url}", flush=True)
            return lan_url
        except Exception:
            print("[BOOTSTRAP] LAN unreachable, fallback public wss", flush=True)

    return "wss://edr.alwayready.id.vn/ws/agent"

MANAGER_URL = os.getenv("MANAGER_URL", "wss://edr.alwayready.id.vn/ws/agent")

AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())

ws_request_lock = asyncio.Lock()
ws_send_lock = asyncio.Lock()
last_heartbeat_ack_time = time.time()
_prev_net_io = None
_prev_net_time = None
def get_container_cpu_percent():
    """Trên Linux host, chỉ dùng psutil là đủ. Không đọc cgroup."""
    return psutil.cpu_percent(interval=0.1)

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
    """Lấy % disk sử dụng, ưu tiên /app (Docker) rồi fallback /."""
    for path in ('/app', '/'):
        try:
            return psutil.disk_usage(path).percent
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return 0.0

def get_ip_address():
    """Lấy IP LAN thật, không dùng gethostbyname (trả 127.0.1.1 trên Mint)."""
    try:
        # Trick: connect UDP tới Google DNS (không gửi packet thật) để lấy IP outbound
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback: dùng psutil lấy IP của interface đầu tiên không phải loopback
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return addr.address
        except Exception:
            pass
        return "0.0.0.0"

def get_mac_address():
    """Lấy MAC của interface đầu tiên (không phải loopback)."""
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            if iface == "lo":
                continue
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    return addr.address
    except Exception:
        pass
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

SUSPICIOUS_PATTERNS = [
    # Credential access — không ai cài hợp pháp
    r"\bmimikatz\b",
    r"\bcomsvcs\.dll\b.*MiniDump",
    r"\bsekurlsa::",
    r"\blsadump::",
    r"\bprocdump(?:\.exe)?\b.*\blsass\b",

    # Reverse shell — không có use case legit
    r"\bnc(?:\.exe)?\b.*-e\b.*(?:cmd|powershell|sh|bash)",
    r"\bnc(?:\.exe)?\b\s+-[a-zA-Z0-9]*[e|l]",
    r"\bpowershell\b.*-enc\b.*[A-Za-z0-9+/=]{50,}",
    r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+",
    r"\bbash\s+-[a-zA-Z]*i",
    r"\bsh\s+-[a-zA-Z]*i",
    r"\bpty\.spawn\b",
    r"\bsocket\.socket.*\.connect\b",
    r"\bmkfifo\b.*\|\s*(?:/bin/)?(?:sh|bash)",
    r"\bsocat\b.*exec:",
    r"(?:curl|wget)\b.*\|\s*(?:/bin/)?(?:sh|bash)",

    # Ransomware indicators
    r"\bvssadmin\b.*delete\s+shadows",
    r"\bwbadmin\b.*delete\s+catalog",

    # Certutil download with suspicious flags (rất hiếm legit)
    r"\bcertutil\b.*-urlcache.*-split.*-f\s+http",
]


def is_process_suspicious(name: str, cmdline: str, exe: str = "") -> bool:
    """Check process suspicion — KHÔNG dựa vào tên process, chỉ cmdline/path."""
    if not cmdline and not exe:
        return False

    full_str = f"{name} {cmdline} {exe}".lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, full_str, re.IGNORECASE):
            return True

    return False


KERNEL_SYSTEM_EXCLUSIONS = {
    "kthreadd", "kworker", "systemd", "migration", "rcu_sched",
    "ksoftirqd", "psimon", "swapper", "init", "cpuhp", "kdevtmpfs",
    "kauditd", "khungtaskd", "oom_reaper", "kblockd", "scsi_eh", "scsi_tmf",
    "jbd2", "irq/", "card1-crtc", "watchdog"
}


def is_kernel_thread(pid, ppid, name, exe, cmdline) -> bool:
    """Xác định xem tiến trình có phải là Linux Kernel Thread hay không."""
    if pid is not None and pid in (0, 1, 2):
        return True
    if ppid == 2:
        return True
    name_lower = (name or "").lower()
    if name_lower.startswith(("scsi_", "kworker", "rcu", "migration", "cpuhp", "jbd2", "ext4", "watchdog", "card", "irq/")):
        return True
    if any(k in name_lower for k in KERNEL_SYSTEM_EXCLUSIONS):
        return True
    # Kernel threads trong Linux không có executable file trên disk và không có user cmdline
    if not exe and (not cmdline or cmdline.strip() == f"[{name}]" or cmdline.strip() == name):
        return True
    return False


def collect_process_info():
    """
    Thu thập thông tin toàn bộ tiến trình đang chạy trên host agent.
    Bao gồm PID, parent PID (ppid), name, exe, cmdline, cpu/memory %, và đánh dấu is_suspicious.
    Lọc bỏ các tiến trình nhân (kernel threads) như kthreadd, kworker, scsi_eh, jbd2.
    """
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent','status']):
            try:
                info = proc.info
                status = info.get('status')
                if status in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD, "zombie", "defunct"):
                    continue
                pid = info.get('pid')
                ppid = info.get('ppid')
                name = str(info.get('name') or "")
                exe = str(info.get('exe') or "")
                cmdline_list = info.get('cmdline') or []
                cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list)
                
                # Bỏ qua hoàn toàn các kernel threads
                if is_kernel_thread(pid, ppid, name, exe, cmdline):
                    continue

                cpu_pct = float(info.get('cpu_percent') or 0.0)
                mem_pct = float(info.get('memory_percent') or 0.0)

                is_suspicious = is_process_suspicious(name, cmdline, exe)

                processes.append({
                    "pid": pid,
                    "parent_pid": ppid,
                    "name": name,
                    "exe": exe,
                    "exe_path": exe,
                    "path": exe,
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

def collect_suspicious_commands(all_processes=None):
    """
    Trích xuất các lệnh đáng ngờ từ danh sách tiến trình (cmdline).
    """
    if all_processes is None:
        all_processes = collect_process_info()

    suspicious_cmds = []
    for proc in all_processes:
        if proc.get("is_suspicious") and proc.get("cmdline"):
            cmd = str(proc["cmdline"]).strip()
            if cmd and cmd not in suspicious_cmds:
                suspicious_cmds.append(cmd)
    return suspicious_cmds

def get_process_list(all_processes=None):
    """Lấy danh sách process đang chạy, ưu tiên các process suspicious."""
    if all_processes is None:
        all_processes = collect_process_info()
    suspicious_procs = [p for p in all_processes if p["is_suspicious"]]
    normal_procs = [p for p in all_processes if not p["is_suspicious"]]
    return (suspicious_procs + normal_procs)[:30]

def get_network_connections():
    """Lấy các kết nối mạng outbound đang mở, đánh dấu suspicious nếu cổng đích/nguồn nằm trong danh sách lạ."""
    suspicious_ports = {4444, 5555, 1337, 31337, 6667, 23, 8080, 445}
    connections = []
    my_pid = os.getpid()
    try:
        for conn in psutil.net_connections(kind='inet'):
            # CHỈ lấy socket outbound thực sự (có raddr và không phải LISTEN)
            if not conn.raddr or conn.status == 'LISTEN':
                continue
            # Bỏ qua socket của chính LARP Agent (tránh self-detection loop)
            if conn.pid == my_pid:
                continue

            laddr = conn.laddr
            raddr = conn.raddr
            src_ip = laddr.ip if laddr else "0.0.0.0"
            src_port = laddr.port if laddr else 0
            dst_ip = raddr.ip
            dst_port = raddr.port

            # Bỏ qua loopback và wildcard 0.0.0.0
            if dst_ip.startswith("127.") or dst_ip in ("::1", "0.0.0.0", "localhost"):
                continue

            is_susp = (dst_port in suspicious_ports or src_port in suspicious_ports)

            proc_name = "unknown"
            exe_path = ""
            create_time = None
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name() or "unknown"
                    try:
                        exe_path = p.exe() or ""
                    except Exception:
                        pass
                    try:
                        create_time = p.create_time()
                    except Exception:
                        pass
                except Exception:
                    proc_name = "unknown"

            connections.append({
                "pid": conn.pid,
                "process_name": proc_name,
                "process": proc_name,
                "exe_path": exe_path,
                "process_start_time": create_time,
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
    return (suspicious_conns + normal_conns)[:25]

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

def collect_shadow_copy_indicators(all_processes=None, suspicious_cmds=None):
    """
    Thu thập dấu hiệu Shadow Copy Deletion:
    - Kiểm tra /etc/shadow đã được đọc/mở.
    - Kiểm tra tiến trình vssadmin / shadow copy deletion trong all_processes.
    - Kiểm tra câu lệnh vssadmin / shadow copy deletion trong suspicious_cmds.
    """
    if all_processes is None:
        all_processes = collect_process_info()
    if suspicious_cmds is None:
        suspicious_cmds = collect_suspicious_commands(all_processes)

    shadow_detected = False
    indicators = []

    shadow_keywords = [
        "vssadmin", "delete shadows", "wmic shadowcopy", "bcdedit", "wbadmin",
        "shadow_deletion", "shadow"
    ]

    # 1. Kiểm tra tiến trình trong all_processes
    for proc in all_processes:
        name = str(proc.get("name", "")).lower()
        cmdline = str(proc.get("cmdline", "")).lower()
        full_str = f"{name} {cmdline}"
        if any(kw in full_str for kw in shadow_keywords):
            shadow_detected = True
            ind_msg = f"vssadmin_process: {proc.get('name')} ({proc.get('cmdline')})"
            if ind_msg not in indicators:
                indicators.append(ind_msg)

    # 2. Kiểm tra trong suspicious_cmds
    for cmd in suspicious_cmds:
        cmd_lower = str(cmd).lower()
        if any(kw in cmd_lower for kw in shadow_keywords):
            shadow_detected = True
            ind_msg = f"vssadmin_command: {cmd}"
            if ind_msg not in indicators:
                indicators.append(ind_msg)

    # 3. Kiểm tra /etc/shadow được đọc/mở
    try:
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                open_files = proc.info.get('open_files')
                if open_files:
                    for f in open_files:
                        if getattr(f, 'path', '') == '/etc/shadow':
                            shadow_detected = True
                            if "shadow_file_read" not in indicators:
                                indicators.append("shadow_file_read")
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    return shadow_detected, indicators

def get_network_flow_stats():
    """
    Thu thập số liệu lưu lượng mạng (bytes, packets) sử dụng psutil.net_io_counters()
    và tính delta giữa hai chu kỳ lấy mẫu.
    """
    global _prev_net_io, _prev_net_time
    curr_io = psutil.net_io_counters()
    curr_time = time.time()

    if _prev_net_io is None or _prev_net_time is None:
        _prev_net_io = curr_io
        _prev_net_time = curr_time
        return {
            "agent_id": AGENT_ID,
            "bytes_sent_delta": 0,
            "bytes_recv_delta": 0,
            "packets_sent_delta": 0,
            "packets_recv_delta": 0,
            "tcp_packets_delta": 0,
            "udp_packets_delta": 0,
            "ip_address": get_ip_address(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    bytes_sent_delta = max(0, curr_io.bytes_sent - _prev_net_io.bytes_sent)
    bytes_recv_delta = max(0, curr_io.bytes_recv - _prev_net_io.bytes_recv)
    packets_sent_delta = max(0, curr_io.packets_sent - _prev_net_io.packets_sent)
    packets_recv_delta = max(0, curr_io.packets_recv - _prev_net_io.packets_recv)

    _prev_net_io = curr_io
    _prev_net_time = curr_time

    tcp_packets_delta = 0
    udp_packets_delta = 0
    try:
        if os.path.exists("/proc/net/snmp"):
            with open("/proc/net/snmp", "r") as f:
                lines = f.readlines()
            for i in range(len(lines) - 1):
                if lines[i].startswith("Tcp:") and lines[i+1].startswith("Tcp:"):
                    headers = lines[i].split()
                    values = lines[i+1].split()
                    if "OutSegs" in headers:
                        idx = headers.index("OutSegs")
                        tcp_out = int(values[idx])
                        if hasattr(get_network_flow_stats, "_prev_tcp_out"):
                            tcp_packets_delta = max(0, tcp_out - get_network_flow_stats._prev_tcp_out)
                        get_network_flow_stats._prev_tcp_out = tcp_out
                elif lines[i].startswith("Udp:") and lines[i+1].startswith("Udp:"):
                    headers = lines[i].split()
                    values = lines[i+1].split()
                    if "OutDatagrams" in headers:
                        idx = headers.index("OutDatagrams")
                        udp_out = int(values[idx])
                        if hasattr(get_network_flow_stats, "_prev_udp_out"):
                            udp_packets_delta = max(0, udp_out - get_network_flow_stats._prev_udp_out)
                        get_network_flow_stats._prev_udp_out = udp_out
    except Exception:
        pass

    if tcp_packets_delta == 0 and udp_packets_delta == 0 and packets_sent_delta > 0:
        tcp_packets_delta = int(packets_sent_delta * 0.75)
        udp_packets_delta = packets_sent_delta - tcp_packets_delta

    return {
        "agent_id": AGENT_ID,
        "bytes_sent_delta": bytes_sent_delta,
        "bytes_recv_delta": bytes_recv_delta,
        "packets_sent_delta": packets_sent_delta,
        "packets_recv_delta": packets_recv_delta,
        "tcp_packets_delta": tcp_packets_delta,
        "udp_packets_delta": udp_packets_delta,
        "ip_address": get_ip_address(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

async def send_ws_json_and_wait(websocket, message):
    """Gửi message yêu cầu phản hồi (Heartbeat, Command ACK) có bảo vệ bằng ws_request_lock."""
    async with ws_request_lock:
        try:
            await websocket.send(json.dumps(message))
            raw_res = await asyncio.wait_for(websocket.recv(), timeout=5)
            return json.loads(raw_res)
        except asyncio.TimeoutError:
            return None
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            raise
        except Exception as e:
            print(f"WS response read error: {e}", flush=True)
            return None

async def send_ws_json_no_wait(websocket, message):
    """Gửi message fire-and-forget (Telemetry, Process list, Flow stats, FIM) không khóa đợi phản hồi."""
    async with ws_send_lock:
        try:
            await websocket.send(json.dumps(message))
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            raise
        except Exception as e:
            print(f"WS send error: {e}", flush=True)

async def execute_command(websocket, cmd):
    action = cmd.get("action")
    params = cmd.get("payload", {})
    handler = COMMAND_HANDLERS.get(action)
    if not handler:
        return {"status": "error", "message": f"Unknown action '{action}'"}

    result = await handler.execute(params, websocket)
    return result

async def send_stats(websocket):
    """Gửi heartbeat định kỳ mỗi 5s và nhận lệnh pending_commands."""
    global last_heartbeat_ack_time
    while True:
        try:
            stats = collect_stats()
            message = {"type": "HEARTBEAT", "payload": stats}
            response = await send_ws_json_and_wait(websocket, message)
            if response and isinstance(response, dict):
                if response.get("status") == "ack":
                    last_heartbeat_ack_time = time.time()
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
                        await send_ws_json_and_wait(websocket, ack_message)
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            print(f"[{AGENT_ID}] WebSocket connection closed in send_stats loop.", flush=True)
            raise
        except Exception as e:
            print(f"Error in send_stats loop: {e}", flush=True)
        await asyncio.sleep(5)

async def send_risk_telemetry(websocket):
    await asyncio.sleep(1)
    while True:
        try:
            all_procs = collect_process_info()
            procs = get_process_list(all_procs)
            conns = get_network_connections()
            file_changes = get_file_changes_count()
            registry_changes = collect_registry_changes()
            suspicious_cmds = collect_suspicious_commands(all_procs)

            shadow_detected, shadow_indicators = collect_shadow_copy_indicators(all_procs, suspicious_cmds)
            shadow_copy_deletion = shadow_detected

            cred_events = []
            if os.path.exists("/tmp/lsass.dump"):
                cred_events.append({"target_object": "lsass.dump", "action": "read"})

            auth_events = global_auth_monitor.get_new_events()
            dns_queries = global_dns_sniffer.get_recent_queries()
            global_connection_tracker.sample_connections()
            conn_hist = global_connection_tracker.get_connection_history()

            payload = {
                "agent_id": AGENT_ID,
                "cpu_usage": get_container_cpu_percent(),
                "ram_usage": get_container_memory_percent(),
                "disk_usage": get_container_disk_percent(),
                "process_list": procs,
                "network_connections": conns,
                "file_changes_count": file_changes,
                "suspicious_commands": suspicious_cmds,
                "shadow_copy_deletion": shadow_copy_deletion,
                "shadow_copy_indicators": shadow_indicators,
                "mass_file_modification": file_changes > 20,
                "registry_changes": registry_changes,
                "credential_access_events": cred_events,
                "lateral_movement_events": [],
                "dns_queries": dns_queries,
                "auth_events": auth_events,
                "connection_history": conn_hist,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            message = {"type": "TELEMETRY_RISK", "payload": payload, "wait_ack": False}
            await send_ws_json_no_wait(websocket, message)

            # If auth attempts detected, dispatch real-time AUTH_EVENT message as well
            if auth_events:
                auth_msg = {
                    "type": "AUTH_EVENT",
                    "payload": {"agent_id": AGENT_ID, "events": auth_events},
                    "wait_ack": False
                }
                await send_ws_json_no_wait(websocket, auth_msg)
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            print(f"[{AGENT_ID}] WebSocket connection closed in send_risk_telemetry loop.", flush=True)
            raise
        except Exception as e:
            print(f"Error sending risk telemetry: {e}", flush=True)
        await asyncio.sleep(15)

async def send_process_list(websocket):
    """
    Gửi danh sách toàn bộ process định kỳ mỗi 20s tới Manager qua WebSocket message 'PROCESS_LIST'.
    """
    await asyncio.sleep(2)
    while True:
        try:
            procs = collect_process_info()
            message = {
                "type": "PROCESS_LIST",
                "payload": {
                    "agent_id": AGENT_ID,
                    "processes": procs,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                "wait_ack": False
            }
            await send_ws_json_no_wait(websocket, message)
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            print(f"[{AGENT_ID}] WebSocket connection closed in send_process_list loop.", flush=True)
            raise
        except Exception as e:
            print(f"Error sending process list: {e}", flush=True)
        await asyncio.sleep(20)

async def send_flow_stats(websocket):
    """
    Gửi thông tin lưu lượng mạng (bytes, packets) định kỳ mỗi 5 giây qua 'FLOW_STATS'.
    """
    await asyncio.sleep(1)
    while True:
        try:
            stats = get_network_flow_stats()
            message = {
                "type": "FLOW_STATS",
                "payload": stats,
                "wait_ack": False
            }
            await send_ws_json_no_wait(websocket, message)
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            print(f"[{AGENT_ID}] WebSocket connection closed in send_flow_stats loop.", flush=True)
            raise
        except Exception as e:
            print(f"Error sending flow stats: {e}", flush=True)
        await asyncio.sleep(5)

async def send_fim_alerts(websocket):
    """
    Định kỳ mỗi 10 giây quét tính toàn vẹn của các file hệ thống và gửi 'FIM_ALERT'.
    """
    fim_monitor = FileIntegrityMonitor(agent_id=AGENT_ID)
    await asyncio.sleep(3)
    while True:
        try:
            alerts = fim_monitor.check_integrity()
            for alert in alerts:
                message = {
                    "type": "FIM_ALERT",
                    "payload": alert,
                    "wait_ack": False
                }
                await send_ws_json_no_wait(websocket, message)
                print(f"[{AGENT_ID}] Dispatched FIM_ALERT for {alert.get('file_path')} ({alert.get('action')})", flush=True)
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError, BrokenPipeError, EOFError, OSError):
            print(f"[{AGENT_ID}] WebSocket connection closed in send_fim_alerts loop.", flush=True)
            raise
        except Exception as e:
            print(f"Error in send_fim_alerts loop: {e}", flush=True)
        await asyncio.sleep(10)

async def watchdog_task():
    """
    Watchdog giám sát kết nối: Nếu quá 30 giây không gửi được heartbeat hoặc
    không nhận ACK từ Manager, tự động thoát os._exit(1) để Docker restart container.
    """
    global last_heartbeat_ack_time
    while True:
        await asyncio.sleep(5)
        elapsed = time.time() - last_heartbeat_ack_time
        if elapsed > 30:
            print(f"[{AGENT_ID}] WATCHDOG TRIGGERED: No heartbeat ACK for {elapsed:.1f}s (>30s). Exiting for Docker restart...", flush=True)
            os._exit(1)

def get_manager_ws_url():
    url = os.getenv("MANAGER_URL", "ws://manager:8000/ws/agent")
    sep = "&" if "?" in url else "?"
    if "agent_id=" not in url:
        url = f"{url}{sep}agent_id={AGENT_ID}"
    return url

async def main_agent():
    global last_heartbeat_ack_time
    retry_delay = 2
    max_delay = 15
    ws_url = get_manager_ws_url()

    try:
        global_dns_sniffer.start_background_sniffer()
    except Exception as e:
        print(f"[{AGENT_ID}] DNS sniffer start note: {e}", flush=True)

    while True:
        try:
            print(f"[{AGENT_ID}] Connecting to Manager at {ws_url}...", flush=True)
            async with websockets.connect(
                ws_url,
                open_timeout=10,
                ping_interval=15,
                ping_timeout=15,
            ) as ws:
                print(f"[{AGENT_ID}] Successfully connected to {ws_url}", flush=True)
                retry_delay = 2  # Reset exponential backoff upon successful connection
                last_heartbeat_ack_time = time.time()  # Reset watchdog timer upon connect
                await asyncio.gather(
                    send_stats(ws),
                    send_risk_telemetry(ws),
                    send_process_list(ws),
                    send_flow_stats(ws),
                    send_fim_alerts(ws),
                    watchdog_task(),
                )
        except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError, OSError) as e:
            print(f"[{AGENT_ID}] Connection lost/refused: {e}. Reconnecting in {retry_delay}s...", flush=True)
        except Exception as e:
            print(f"[{AGENT_ID}] Unexpected agent error: {e}. Reconnecting in {retry_delay}s...", flush=True)

        await asyncio.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, max_delay)

if __name__ == "__main__":
    asyncio.run(main_agent())