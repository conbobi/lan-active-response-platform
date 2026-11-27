import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable

if __package__:
    from .vulnerable_web.http_evidence import SQL_PATTERNS, safe_http_target
else:
    from vulnerable_web.http_evidence import SQL_PATTERNS, safe_http_target

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
        "/var/log/vulnerable_web/access.log",
        "/tmp/web_access.log",
        "/opt/larp-agent/vulnerable_web/access.log",
        "/home/webuser/vulnerable_web/access.log",
        "/var/log/cloudflared.log",
        "/tmp/cloudflared.log",
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
        journal_timestamp = None

        # 1. Handle journalctl -o json format: {"MESSAGE": "...", "__REALTIME_TIMESTAMP": "..."}
        if line_str.startswith("{") and line_str.endswith("}"):
            try:
                journal_entry = json.loads(line_str)
                if isinstance(journal_entry, dict):
                    stamp = journal_entry.get("__REALTIME_TIMESTAMP")
                    if isinstance(stamp, str) and stamp.isascii() and stamp.isdecimal() and len(stamp) <= 17:
                        journal_timestamp = datetime.fromtimestamp(int(stamp) / 1_000_000, timezone.utc).isoformat()
                    if "MESSAGE" in journal_entry:
                        message_body = str(journal_entry["MESSAGE"]).strip()
                    elif "message" in journal_entry:
                        message_body = str(journal_entry["message"]).strip()
            except (ValueError, OverflowError, OSError):
                logger.debug("Invalid journal envelope for HTTP observation")

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

                    target = str(payload.get("path") or payload.get("url") or payload.get("uri") or "")
                    path, indicators = safe_http_target(target)
                    provided = payload.get("payload_indicators")
                    if isinstance(provided, list):
                        indicators.update(item for item in provided if isinstance(item, str) and item in SQL_PATTERNS)
                    method = str(payload.get("method") or payload.get("http_method") or "").upper()
                    if path and method in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}:
                        stamp = payload.get("timestamp")
                        request_id = payload.get("request_id")
                        if request_id is None and stamp:
                            request_id = hashlib.sha256(message_body.encode()).hexdigest()
                        return {
                            "src_ip": str(src_ip or "unknown").strip(),
                            "host": str(payload.get("host") or payload.get("hostname") or "")[:128],
                            "path": path, "http_method": method, "user_agent": user_agent[:256],
                            "status_code": payload.get("status_code") or payload.get("status"),
                            **({"session_ref": payload["session_ref"]} if isinstance(payload.get("session_ref"), str)
                               and re.fullmatch(r"[0-9a-f]{64}", payload["session_ref"]) else {}),
                            "timestamp": stamp or journal_timestamp or now_iso, "request_id": request_id,
                            "timestamp_source": "log" if stamp or journal_timestamp else "agent_receipt",
                            "service": payload.get("service"), "payload_indicators": sorted(indicators),
                            **app_fields(payload),
                        }
            except (ValueError, TypeError, OverflowError):
                logger.debug("Invalid structured HTTP observation")

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

        path, indicators = safe_http_target(path)
        if not req_match and not m_match:
            return None
        src_ip = "unknown"
        ip_match = cls.RE_IP_HEADER.search(message_body) or cls.RE_CLIENT_IP.search(message_body)
        if ip_match:
            src_ip = ip_match[1]

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
        status_code = None
        st_match = cls.RE_STATUS.search(message_body)
        if st_match:
            try:
                status_code = int(st_match.group(1) or st_match.group(2))
            except (TypeError, ValueError):
                status_code = None

        # Discard irrelevant system noise lines (e.g. cloudflared internal healthcheck pings without client IP or user agent)
        if src_ip == "unknown" and not user_agent and path == "/":
            return None

        return {
            "src_ip": src_ip.strip(),
            "host": host.strip(),
            "path": path,
            "http_method": method.strip(),
            "user_agent": user_agent.strip(),
            "status_code": status_code,
            "timestamp": journal_timestamp or now_iso,
            "timestamp_source": "log" if journal_timestamp else "agent_receipt",
            "payload_indicators": sorted(indicators)
        }


APP_EVENT_KEYS = {
    "file_upload": ("type", "client_filename", "stored", "upload_path", "upload_size", "upload_sha256",
                    "extension", "outside_upload_dir", "script_or_binary", "error"),
    "shell_command": ("type", "parameter", "parameter_length", "parameter_sha256", "shell_indicators",
                      "referenced_upload_files", "execution_result", "child_pid", "child_spawned_at",
                      "exit_code", "duration_s"),
}


def app_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Application-side observation fields forwarded as-is (bounded); the Manager validates them again."""
    out: Dict[str, Any] = {}
    event_id = payload.get("event_id")
    if isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{32}", event_id):
        out["event_id"] = event_id
    for key in ("process_pid", "parent_pid"):
        if type(payload.get(key)) is int and 0 < payload[key] < 2**31:
            out[key] = payload[key]
    event = payload.get("app_event")
    if isinstance(event, dict) and event.get("type") in APP_EVENT_KEYS:
        out["app_event"] = {k: event[k] for k in APP_EVENT_KEYS[event["type"]] if k in event}
    return out


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
        logger.debug("Dispatched WEB_ACCESS_LOG for Agent %s", aid)
        return True
    except Exception as e:
        logger.warning(f"Failed to send WEB_ACCESS_LOG over WebSocket: {e}")
        return False


async def tail_cloudflared_logs(
    ws=None,
    callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    stop_event: Optional[asyncio.Event] = None,
    *, fallback=True,
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
            # The lab unit is vulnerable-web.service; vulnerable_web is kept for older installs.
            cmd = ["journalctl", "-u", "cloudflared", "-u", "vulnerable-web", "-u", "vulnerable_web",
                   "-f", "-o", "json", "-n", "0"]
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
                            if fallback:
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
            if fallback:
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
    Tail access files even when the journal stream is available.
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

                positions[path] = last_pos
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
    tasks = (
        asyncio.create_task(tail_cloudflared_logs(ws=ws, fallback=False)),
        asyncio.create_task(_tail_fallback_files(ws=ws)),
    )
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("web_log_monitor_task cancelled.")
    except Exception as e:
        logger.error(f"web_log_monitor_task exited with error: {e}")
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

