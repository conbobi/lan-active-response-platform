import asyncio
import json
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable

logger = logging.getLogger("larp_agent.web_log_monitor")

AGENT_ID = os.getenv("AGENT_ID", socket_host := os.uname().nodename if hasattr(os, "uname") else "my-desktop")


class WebLogMonitor:
    """
    Monitors Cloudflare Tunnel (cloudflared) and Web Server access logs.
    Extracts HTTP request telemetry:
      - Cf-Connecting-Ip / Client IP (Real attacker IP)
      - Host, Path, HTTP Method
      - User-Agent (identifying tools like Hydra, sqlmap, nikto)
      - Status code and timestamp
    Forwards structured WEB_ACCESS_LOG events to LARP Manager for NDR detection.
    """

    # Fallback log files if journalctl is not available
    FALLBACK_LOG_PATHS = [
        "/var/log/cloudflared.log",
        "/tmp/cloudflared.log",
        "/var/log/vulnerable_web/access.log",
        "/home/webuser/vulnerable_web/access.log",
        "/tmp/web_access.log",
        "/var/log/nginx/access.log",
    ]

    # Regex patterns for unstructured text log extraction
    RE_IP_HEADER = re.compile(
        r'(?i)(?:cf-connecting-ip|x-forwarded-for)["\s:=]+(?:\[\s*"?)?([0-9a-fA-F.:]+)',
        re.IGNORECASE
    )
    RE_CLIENT_IP = re.compile(
        r'(?i)(?:client_ip|client-ip|remote_addr|src_ip|ip)["\s:=]+"?([0-9a-fA-F.:]+)',
        re.IGNORECASE
    )
    RE_GENERIC_IP = re.compile(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    )
    RE_USER_AGENT = re.compile(
        r'(?i)"?User-Agent"?\s*[:=]\s*(?:\[\s*"([^"]+)"\s*\]|"([^"]+)"|([^\s,}\]]+))',
        re.IGNORECASE
    )
    RE_HTTP_REQUEST_LINE = re.compile(
        r'(?i)\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?:https?://[^/\s]+)?(/[^?\s\n]*(\?[^\s\n]*)?)',
        re.IGNORECASE
    )
    RE_PATH = re.compile(
        r'(?i)\bpath\s*=\s*"?([^\s"]+)',
        re.IGNORECASE
    )
    RE_METHOD = re.compile(
        r'(?i)\bmethod\s*=\s*"?([A-Z]+)',
        re.IGNORECASE
    )
    RE_HOST = re.compile(
        r'(?i)(?:\bhost\s*=\s*"?([^\s"]+)|https?://([^/\s]+))',
        re.IGNORECASE
    )
    RE_STATUS = re.compile(
        r'(?i)\bstatus(?:_code)?\s*=\s*(\d{3})|\s(\d{3})\s',
        re.IGNORECASE
    )

    def __init__(self, agent_id: Optional[str] = None):
        self.agent_id = agent_id or AGENT_ID
        self.is_running = False

    @classmethod
    def parse_raw_log_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single line of log output.
        Supports:
          1. JSON string from `journalctl -o json` containing {"MESSAGE": "..."}
          2. JSON string directly output by cloudflared (--logging-format json)
          3. Key-value unstructured text output by cloudflared / web server
        Returns structured dictionary if HTTP request telemetry is found, else None.
        """
        if not line or not isinstance(line, str):
            return None

        line_str = line.strip()
        if not line_str:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        message_body = line_str

        # 1. Handle journalctl -o json format: {"MESSAGE": "...", "__REALTIME_TIMESTAMP": "..."}
        if line_str.startswith("{") and line_str.endswith("}"):
            try:
                journal_entry = json.loads(line_str)
                if isinstance(journal_entry, dict):
                    if "MESSAGE" in journal_entry:
                        message_body = str(journal_entry["MESSAGE"]).strip()
                    elif "message" in journal_entry:
                        message_body = str(journal_entry["message"]).strip()
            except Exception:
                pass

        # 2. Check if message_body is itself a JSON object from cloudflared / web app
        if message_body.startswith("{") and message_body.endswith("}"):
            try:
                payload = json.loads(message_body)
                if isinstance(payload, dict):
                    # Check for direct or nested fields
                    headers = payload.get("headers") or {}
                    if not isinstance(headers, dict):
                        headers = {}

                    # Extract IP: prioritize Cf-Connecting-Ip
                    src_ip = None
                    cf_ip_hdr = headers.get("Cf-Connecting-Ip") or headers.get("cf-connecting-ip")
                    if isinstance(cf_ip_hdr, list) and cf_ip_hdr:
                        src_ip = str(cf_ip_hdr[0]).strip()
                    elif isinstance(cf_ip_hdr, str) and cf_ip_hdr:
                        src_ip = cf_ip_hdr.strip()

                    if not src_ip:
                        src_ip = (
                            payload.get("client_ip")
                            or payload.get("client-ip")
                            or payload.get("remote_addr")
                            or payload.get("src_ip")
                            or payload.get("ip")
                        )

                    # Extract User-Agent
                    user_agent = ""
                    ua_hdr = headers.get("User-Agent") or headers.get("user-agent")
                    if isinstance(ua_hdr, list) and ua_hdr:
                        user_agent = str(ua_hdr[0]).strip()
                    elif isinstance(ua_hdr, str) and ua_hdr:
                        user_agent = ua_hdr.strip()
                    if not user_agent:
                        user_agent = str(payload.get("user_agent") or payload.get("user-agent") or "")

                    # Extract path and method
                    path = str(payload.get("path") or payload.get("url") or payload.get("uri") or "/")
                    method = str(payload.get("method") or payload.get("http_method") or "GET").upper()
                    host = str(payload.get("host") or payload.get("hostname") or "")
                    status_code = int(payload.get("status") or payload.get("status_code") or 200)

                    # Unquote URL path for SQLi/traversal analysis
                    try:
                        path = urllib.parse.unquote(path)
                    except Exception:
                        pass

                    if src_ip or user_agent or path != "/" or method != "GET":
                        return {
                            "src_ip": str(src_ip or "unknown").strip(),
                            "host": host,
                            "path": path,
                            "http_method": method,
                            "user_agent": user_agent,
                            "status_code": status_code,
                            "timestamp": now_iso,
                            "raw_message": message_body[:1024]
                        }
            except Exception:
                pass

        # 3. Unstructured / Semi-structured text parsing (Regex fallback)
        # Must contain signs of an HTTP request or cloudflared proxy event
        http_hints = ("http", "get", "post", "path=", "method=", "user-agent", "cf-connecting-ip", "client-ip", "/login")
        if not any(h in message_body.lower() for h in http_hints):
            return None

        # Extract HTTP Method & Path
        method = "GET"
        path = "/"
        req_match = cls.RE_HTTP_REQUEST_LINE.search(message_body)
        if req_match:
            method = req_match.group(1).upper()
            path = req_match.group(2)
        else:
            m_match = cls.RE_METHOD.search(message_body)
            if m_match:
                method = m_match.group(1).upper()
            p_match = cls.RE_PATH.search(message_body)
            if p_match:
                path = p_match.group(1)

        # Unquote path
        try:
            path = urllib.parse.unquote(path)
        except Exception:
            pass

        # Extract Client IP (Cf-Connecting-Ip is highest priority)
        src_ip = "unknown"
        cf_match = cls.RE_IP_HEADER.search(message_body)
        if cf_match:
            src_ip = cf_match.group(1)
        else:
            cl_match = cls.RE_CLIENT_IP.search(message_body)
            if cl_match:
                src_ip = cl_match.group(1)
            else:
                # Find any IPv4 not equal to localhost
                all_ips = cls.RE_GENERIC_IP.findall(message_body)
                valid_ips = [ip for ip in all_ips if not ip.startswith("127.") and ip != "0.0.0.0"]
                if valid_ips:
                    src_ip = valid_ips[0]

        # Extract User-Agent
        user_agent = ""
        ua_match = cls.RE_USER_AGENT.search(message_body)
        if ua_match:
            user_agent = ua_match.group(1) or ua_match.group(2) or ua_match.group(3) or ""
            user_agent = user_agent.strip().strip('"').strip("'")

        # Extract Host
        host = ""
        host_match = cls.RE_HOST.search(message_body)
        if host_match:
            host = host_match.group(1) or host_match.group(2) or ""

        # Extract Status Code
        status_code = 200
        st_match = cls.RE_STATUS.search(message_body)
        if st_match:
            try:
                status_code = int(st_match.group(1) or st_match.group(2))
            except Exception:
                status_code = 200

        # Discard irrelevant system noise lines (e.g. cloudflared internal healthcheck pings without client IP or user agent)
        if src_ip == "unknown" and not user_agent and path == "/":
            return None

        return {
            "src_ip": src_ip.strip(),
            "host": host.strip(),
            "path": path.strip(),
            "http_method": method.strip(),
            "user_agent": user_agent.strip(),
            "status_code": status_code,
            "timestamp": now_iso,
            "raw_message": message_body[:1024]
        }


async def send_web_log(ws, log_data: Dict[str, Any], agent_id: Optional[str] = None) -> bool:
    """
    Wraps log_data into a structured WEB_ACCESS_LOG message and sends it via WebSocket.
    """
    if not ws or not log_data:
        return False

    aid = agent_id or AGENT_ID
    message = {
        "type": "WEB_ACCESS_LOG",
        "agent_id": aid,
        "payload": log_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    try:
        await ws.send(json.dumps(message))
        print(
            f"[{aid}] [WebLogMonitor] Dispatched WEB_ACCESS_LOG: "
            f"{log_data.get('src_ip')} {log_data.get('http_method')} {log_data.get('path')} "
            f"(UA: '{log_data.get('user_agent')}')",
            flush=True
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to send WEB_ACCESS_LOG over WebSocket: {e}")
        return False


async def tail_cloudflared_logs(
    ws=None,
    callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    stop_event: Optional[asyncio.Event] = None
):
    """
    Continuously tails cloudflared and web access logs using `journalctl -u cloudflared -u vulnerable_web -f -o json`.
    Falls back to file monitoring if journalctl is unavailable or permission denied.
    Safely catches exceptions and never crashes the agent process.
    """
    print(f"[{AGENT_ID}] [WebLogMonitor] Starting WebLogMonitor for cloudflared & vulnerable_web...", flush=True)
    logger.info("Starting WebLogMonitor background task for cloudflared access logs...")
    retry_delay = 3

    while stop_event is None or not stop_event.is_set():
        proc = None
        try:
            # 1. Attempt to stream journalctl -u cloudflared and -u vulnerable_web
            cmd = ["journalctl", "-u", "cloudflared", "-u", "vulnerable_web", "-f", "-o", "json", "-n", "0"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            print(f"[{AGENT_ID}] [WebLogMonitor] Attached to journalctl -u cloudflared -u vulnerable_web stream.", flush=True)
            retry_delay = 3

            while stop_event is None or not stop_event.is_set():
                if proc.stdout is None:
                    break
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    # Stream ended; inspect return code
                    await proc.wait()
                    if proc.returncode != 0:
                        err_bytes = await proc.stderr.read() if proc.stderr else b""
                        err_msg = err_bytes.decode("utf-8", errors="ignore").strip()
                        print(f"[{AGENT_ID}] [WebLogMonitor] journalctl failed (code {proc.returncode}): {err_msg}", flush=True)
                        if "permission" in err_msg.lower() or "not opened" in err_msg.lower() or proc.returncode == 1:
                            print(
                                f"[{AGENT_ID}] [WebLogMonitor] Permission denied for journalctl. "
                                f"Please run agent with sudo or execute: 'sudo usermod -aG systemd-journal,adm $USER'",
                                flush=True
                            )
                            print(f"[{AGENT_ID}] [WebLogMonitor] Switching to fallback log file monitoring...", flush=True)
                            await _tail_fallback_files(ws, callback, stop_event)
                            return
                    break

                line_str = line_bytes.decode("utf-8", errors="ignore").strip()
                if not line_str:
                    continue

                parsed = WebLogMonitor.parse_raw_log_line(line_str)
                if parsed:
                    if ws is not None:
                        await send_web_log(ws, parsed)
                    if callback is not None:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(parsed)
                        else:
                            callback(parsed)

        except FileNotFoundError:
            # journalctl command not found (e.g. non-systemd container)
            print(f"[{AGENT_ID}] [WebLogMonitor] journalctl not found, switching to fallback log files...", flush=True)
            await _tail_fallback_files(ws, callback, stop_event)
            break
        except Exception as e:
            print(f"[{AGENT_ID}] [WebLogMonitor] Error in log tailer: {e}. Retrying in {retry_delay}s...", flush=True)
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    await proc.wait()
                except Exception:
                    pass

        if stop_event is not None and stop_event.is_set():
            break
        await asyncio.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, 30)


async def _tail_fallback_files(
    ws=None,
    callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    stop_event: Optional[asyncio.Event] = None
):
    """
    Fallback file-based tailing for environments without systemd journalctl.
    """
    positions: Dict[str, int] = {}

    while stop_event is None or not stop_event.is_set():
        try:
            active_files = [p for p in WebLogMonitor.FALLBACK_LOG_PATHS if os.path.isfile(p)]
            for path in active_files:
                curr_size = os.path.getsize(path)
                last_pos = positions.get(path, curr_size)  # Seek to end on first open

                if curr_size < last_pos:
                    last_pos = 0  # Truncated or rotated

                if curr_size > last_pos:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_pos)
                        lines = f.readlines()
                        positions[path] = f.tell()

                    for line in lines:
                        parsed = WebLogMonitor.parse_raw_log_line(line)
                        if parsed:
                            if ws is not None:
                                await send_web_log(ws, parsed)
                            if callback is not None:
                                if asyncio.iscoroutinefunction(callback):
                                    await callback(parsed)
                                else:
                                    callback(parsed)
        except Exception as e:
            logger.debug(f"Fallback log tailing error: {e}")

        await asyncio.sleep(2)


async def web_log_monitor_task(ws):
    """
    Task entrypoint for inclusion in agent.py's asyncio.gather loop.
    """
    try:
        await tail_cloudflared_logs(ws=ws)
    except asyncio.CancelledError:
        logger.info("web_log_monitor_task cancelled.")
    except Exception as e:
        logger.error(f"web_log_monitor_task exited with error: {e}")

