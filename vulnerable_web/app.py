# /opt/larp-agent/vulnerable_web/app.py

from flask import (
    Flask,
    request,
    session,
    redirect,
    render_template_string,
    jsonify,
    abort
)

import os
import json
import ipaddress
import logging
import sqlite3
import subprocess
import hashlib
import time
import threading

from datetime import datetime, timezone

# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "insecure_key_123")

BASE_DIR = os.getenv("VULNERABLE_WEB_DIR", os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = "/tmp/uploads"
DB_PATH = os.getenv("VULNERABLE_DB_PATH", "/tmp/users.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs("/var/log/vulnerable_web", exist_ok=True)

# Log file targets
AUTH_LOG_PATHS = [
    os.path.join(BASE_DIR, "auth.log"),
    "/var/log/vulnerable_web/auth.log",
    "/tmp/web_auth.log",
]

ACCESS_LOG_PATHS = [
    os.path.join(BASE_DIR, "access.log"),
    "/var/log/vulnerable_web/access.log",
    "/tmp/web_access.log",
]

# ============================================================
# LARP WEB AUTHENTICATION & ACCESS LOGGING
# ============================================================

auth_logger = logging.getLogger("larp_web_auth")
auth_logger.setLevel(logging.INFO)
auth_logger.propagate = False

access_logger = logging.getLogger("larp_web_access")
access_logger.setLevel(logging.INFO)
access_logger.propagate = False

formatter = logging.Formatter("%(message)s")

if not auth_logger.handlers:
    for log_p in AUTH_LOG_PATHS:
        try:
            os.makedirs(os.path.dirname(log_p), exist_ok=True)
            h = logging.FileHandler(log_p, encoding="utf-8")
            h.setFormatter(formatter)
            auth_logger.addHandler(h)
            try: os.chmod(log_p, 0o666)
            except: pass
        except: pass

if not access_logger.handlers:
    for log_p in ACCESS_LOG_PATHS:
        try:
            os.makedirs(os.path.dirname(log_p), exist_ok=True)
            h = logging.FileHandler(log_p, encoding="utf-8")
            h.setFormatter(formatter)
            access_logger.addHandler(h)
            try: os.chmod(log_p, 0o666)
            except: pass
        except: pass

def get_client_ip():
    cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
    if cf_ip:
        try: return (str(ipaddress.ip_address(cf_ip)), "cloudflare")
        except ValueError: pass

    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        client = xff.split(",")[0].strip()
        try: return (str(ipaddress.ip_address(client)), "x_forwarded_for")
        except ValueError: pass

    remote_ip = request.remote_addr or "unknown"
    return remote_ip, "remote_addr"

@app.after_request
def log_http_access_telemetry(response):
    try:
        client_ip, ip_source = get_client_ip()
        full_path = request.full_path if request.query_string else request.path
        entry = {
            "client_ip": client_ip,
            "ip_source": ip_source,
            "method": request.method,
            "path": full_path,
            "status_code": response.status_code,
            "user_agent": request.headers.get("User-Agent", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": request.host,
        }
        access_logger.info(json.dumps(entry, ensure_ascii=False))
    except: pass
    return response

def write_auth_event(status, username, error_type=None):
    client_ip, ip_source = get_client_ip()
    event = {
        "status": status,
        "event_type": "WEB_AUTH_" + status.upper(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": str(username or "")[:128],
        "source_ip": client_ip,
        "ip_source": ip_source,
        "service": "flask_web",
        "path": request.path,
        "method": request.method
    }
    if error_type: event["error_type"] = error_type
    auth_logger.info(json.dumps(event, ensure_ascii=False))

def write_lab_event(event_type, details=None):
    client_ip, ip_source = get_client_ip()
    event = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": client_ip,
        "ip_source": ip_source,
        "username": session.get("user"),
        "service": "flask_web",
        "details": details or {}
    }
    auth_logger.info(json.dumps(event, ensure_ascii=False))

# ============================================================
# DATABASE
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
        c.execute("DELETE FROM users")
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", hashlib.md5(b"admin123").hexdigest(), "admin"))
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("guest", hashlib.md5(b"guest").hexdigest(), "user"))
        conn.commit()
    finally:
        conn.close()

# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def index():
    if "user" in session: return redirect("/dashboard")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # LỖ HỔNG SQL INJECTION
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(query)
            user = c.fetchone()
            conn.close()
            if user:
                write_auth_event("success", username)
                session["user"] = user[1]
                session["role"] = user[3]
                return redirect("/dashboard")
            else:
                write_auth_event("failed", username)
                error = "Sai tài khoản hoặc mật khẩu"
        except Exception as e:
            write_auth_event("error", username, error_type=type(e).__name__)
            error = f"Lỗi DB: {e}"

    return render_template_string("""
        <html><body style="font-family:Arial;padding:50px;background:#1e293b;color:#fff;">
            <h2>🌐 LARP Corp — Internal Portal</h2>
            {% if error %}<p style="color:#f43f5e;">{{ error }}</p>{% endif %}
            <form method="POST" style="max-width:300px;">
                <input name="username" placeholder="Username" style="width:100%;padding:8px;margin:5px 0;"><br>
                <input name="password" type="password" placeholder="Password" style="width:100%;padding:8px;margin:5px 0;"><br>
                <button type="submit" style="width:100%;padding:10px;background:#7c3aed;color:#fff;border:none;cursor:pointer;">Đăng nhập</button>
            </form>
        </body></html>
    """, error=error)

@app.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect("/login")
    return render_template_string("""
        <html><body style="font-family:Arial;padding:50px;background:#1e293b;color:#fff;">
            <h2>📊 Dashboard — Xin chào {{ user }}!</h2>
            <p>Role: <b>{{ role }}</b></p><hr>
            <h3>📁 Upload tài liệu</h3>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="file">
                <button type="submit">Upload</button>
            </form><hr>
            <h3>🔧 Chức năng kiểm tra mạng</h3>
            <form action="/ping" method="GET">
                <input name="ip" placeholder="IP cần ping" value="8.8.8.8">
                <button type="submit">Ping</button>
            </form><hr>
            <a href="/logout" style="color:#f43f5e;">Đăng xuất</a>
        </body></html>
    """, user=session["user"], role=session["role"])

@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session: return redirect("/login")
    f = request.files.get("file")
    if not f: return "Không có file", 400

    filename = f.filename
    filepath = os.path.join(UPLOAD_DIR, filename)
    f.save(filepath)

    # 🚨 LỖ HỔNG TỰ ĐỘNG THỰC THI FILE PYTHON
    if filename.endswith(".py"):
        try:
            # Tách tiến trình ra khỏi Flask, ghi log để debug
            log_file = open("/tmp/backdoor_output.log", "a")
            subprocess.Popen(
                ["python3", filepath],
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,   # Quan trọng: tách session
                close_fds=True
            )
            return f"<h3>Upload thành công và ĐÃ TỰ ĐỘNG CHẠY: /tmp/uploads/{filename}</h3><a href='/dashboard'>Quay lại</a>"
        except Exception as e:
            return f"<h3>Upload thành công nhưng lỗi chạy: {e}</h3>"
@app.route("/ping")
def ping():
    if "user" not in session: return redirect("/login")
    ip = request.args.get("ip", "127.0.0.1")
    # LỖ HỔNG COMMAND INJECTION (Dùng làm dự phòng nếu upload bị chặn)
    result = subprocess.run(f"ping -c 1 {ip}", shell=True, capture_output=True, text=True, timeout=10)
    return f"<pre style='background:#000;color:#0f0;padding:15px;'>{result.stdout}{result.stderr}</pre><a href='/dashboard'>Quay lại</a>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    init_db()
    flask_host = os.getenv("FLASK_HOST", "0.0.0.0")
    flask_port = int(os.getenv("FLASK_PORT", "5000"))
    print(f"[*] Starting Vulnerable Web App on {flask_host}:{flask_port}...", flush=True)
    app.run(host=flask_host, port=flask_port, debug=False)