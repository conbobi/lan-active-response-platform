
# ~/vulnerable_web/app.py

from flask import (
    g,
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
import uuid

from datetime import datetime, timezone

if __package__:
    from .response_guard import install_guard
    from .http_evidence import ACCOUNT, safe_http_target, sql_indicators
else:
    from response_guard import install_guard
    from http_evidence import ACCOUNT, safe_http_target, sql_indicators


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(__name__)

# Chỉ dùng cho lab demo.
# Khi triển khai thật, cần dùng secret key ngẫu nhiên từ environment.
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "insecure_key_123"
)

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

# Attach file handlers for auth logging
if not auth_logger.handlers:
    for log_p in AUTH_LOG_PATHS:
        try:
            os.makedirs(os.path.dirname(log_p), exist_ok=True)
            h = logging.FileHandler(log_p, encoding="utf-8")
            h.setFormatter(formatter)
            auth_logger.addHandler(h)
            try:
                os.chmod(log_p, 0o666)
            except Exception:
                pass
        except Exception:
            pass

# Attach file handlers for access logging
if not access_logger.handlers:
    for log_p in ACCESS_LOG_PATHS:
        try:
            os.makedirs(os.path.dirname(log_p), exist_ok=True)
            h = logging.FileHandler(log_p, encoding="utf-8")
            h.setFormatter(formatter)
            access_logger.addHandler(h)
            try:
                os.chmod(log_p, 0o666)
            except Exception:
                pass
        except Exception:
            pass


def get_client_ip():
    remote = request.remote_addr or "unknown"
    # Forwarded headers are accepted only from a configured proxy peer.
    try:
        peer = ipaddress.ip_address(remote)
    except ValueError:
        return remote, "remote_addr"
    for configured in os.getenv("LARP_TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128").split(","):
        try:
            if peer not in ipaddress.ip_network(configured.strip(), strict=False):
                continue
        except ValueError:
            app.logger.warning("Invalid LARP trusted proxy CIDR")
            continue
        cf = request.headers.get("CF-Connecting-IP", "").strip()
        forwarded = request.headers.get("X-Forwarded-For", "").rsplit(",", 1)[-1].strip()
        for candidate, source in ((cf, "cf_connecting_ip"), (forwarded, "x_forwarded_for")):
            try:
                return str(ipaddress.ip_address(candidate)), source
            except ValueError:
                continue
        break
    return remote, "remote_addr"


@app.before_request
def assign_observation_id():
    g.observation_id = uuid.uuid4().hex


install_guard(app)


@app.after_request
def log_http_access_telemetry(response):
    client_ip, ip_source = get_client_ip()
    route, indicators = safe_http_target(request.full_path)
    auth = g.get("authentication_observation")
    if auth:
        indicators.update(auth["payload_indicators"])
    if request.url_rule is not None:
        route = request.url_rule.rule
    ua = request.headers.get("User-Agent", "")[:256]
    entry = {
        "client_ip": client_ip, "ip_source": ip_source, "method": request.method,
        "path": route, "status_code": response.status_code,
        "user_agent": ua if ua.isprintable() else "", "request_id": g.observation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(), "host": request.host,
        "service": "flask_web", "payload_indicators": sorted(indicators),
    }
    if g.get("session_ref"):
        entry["session_ref"] = g.session_ref
    access_logger.info(json.dumps(entry, ensure_ascii=False))
    if auth is not None:
        auth_logger.info(json.dumps({
            **entry, **auth, "source_ip": client_ip, "http_status": response.status_code,
            "payload_indicators": entry["payload_indicators"],
        }, ensure_ascii=False))
    return response


def write_auth_event(status, username, error_type=None):
    indicators = sql_indicators(username)
    g.authentication_observation = {
        "status": status, "event_type": "WEB_AUTH_" + status.upper(),
        "username": username if isinstance(username, str) and ACCOUNT.fullmatch(username) and not indicators else None,
        "auth_method": "password", "timestamp_source": "application",
        "payload_indicators": sorted(indicators), "error_type": error_type,
    }


def write_lab_event(event_type, details=None):

    client_ip, ip_source = get_client_ip()

    event = {
        "event_type": event_type,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "source_ip": client_ip,

        "ip_source": ip_source,

        "username": session.get("user"),

        "service": "flask_web",

        "details": details or {}
    }

    auth_logger.info(
        json.dumps(
            event,
            ensure_ascii=False
        )
    )


# ============================================================
# LARP EDR LAB CONFIGURATION
# ============================================================

# Tắt mặc định.
# Chỉ bật khi muốn thực hiện bài kiểm thử EDR.

EDR_LAB_ENABLED = (
    os.getenv("EDR_LAB_ENABLED", "0") == "1"
)

# Danh sách IP được phép gọi endpoint.
# Hỗ trợ IP đơn hoặc CIDR.
#
# Ví dụ:
# EDR_LAB_ALLOWED_IPS="203.0.113.10,192.168.1.0/24"

EDR_LAB_ALLOWED_IPS = os.getenv(
    "EDR_LAB_ALLOWED_IPS",
    ""
)

# Một IP chỉ được tạo process test mỗi 60 giây.

LAB_COOLDOWN_SECONDS = 60

_lab_last_trigger = {}

_lab_lock = threading.Lock()


def is_lab_ip_allowed(client_ip):

    if not EDR_LAB_ALLOWED_IPS.strip():
        return False

    try:
        remote = ipaddress.ip_address(client_ip)

    except ValueError:
        return False

    allowed_entries = (
        EDR_LAB_ALLOWED_IPS.split(",")
    )

    for entry in allowed_entries:

        entry = entry.strip()

        if not entry:
            continue

        try:

            if "/" in entry:

                network = ipaddress.ip_network(
                    entry,
                    strict=False
                )

                if remote in network:
                    return True

            else:

                allowed_ip = ipaddress.ip_address(entry)

                if remote == allowed_ip:
                    return True

        except ValueError:
            continue

    return False


def check_lab_cooldown(client_ip):

    now = time.monotonic()

    with _lab_lock:

        last_trigger = _lab_last_trigger.get(
            client_ip,
            0
        )

        elapsed = now - last_trigger

        if elapsed < LAB_COOLDOWN_SECONDS:

            remaining = int(
                LAB_COOLDOWN_SECONDS - elapsed
            ) + 1

            return False, remaining

        _lab_last_trigger[client_ip] = now

        return True, 0


# ============================================================
# DATABASE
# ============================================================

def init_db():

    """Tạo SQLite DB với user admin mặc định."""

    conn = sqlite3.connect(DB_PATH)

    try:

        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                role TEXT
            )
        """)

        # Demo account.
        # DB bị reset mỗi lần khởi động app.

        c.execute("DELETE FROM users")

        c.execute(
            """
            INSERT INTO users
            (username, password, role)
            VALUES (?, ?, ?)
            """,
            (
                "admin",
                hashlib.md5(
                    b"admin123"
                ).hexdigest(),
                "admin"
            )
        )

        c.execute(
            """
            INSERT INTO users
            (username, password, role)
            VALUES (?, ?, ?)
            """,
            (
                "guest",
                hashlib.md5(
                    b"guest"
                ).hexdigest(),
                "user"
            )
        )

        conn.commit()

    finally:

        conn.close()


# ============================================================
# INDEX
# ============================================================

@app.route("/")
def index():

    if "user" in session:
        return redirect("/dashboard")

    return redirect("/login")


# ============================================================
# LOGIN + AUTHENTICATION LOGGING
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = ""

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        )

        password = request.form.get(
            "password",
            ""
        )

        # LAB ONLY:
        # SQL Injection intentionally retained for demo.

        query = (
            f"SELECT * FROM users "
            f"WHERE username='{username}' "
            f"AND password="
            f"'{hashlib.md5(password.encode()).hexdigest()}'"
        )

        try:

            conn = sqlite3.connect(DB_PATH)

            c = conn.cursor()

            c.execute(query)

            user = c.fetchone()
            if user:
                # Independently evaluate the intended authentication policy without retaining inputs.
                c.execute("SELECT 1 FROM users WHERE id=? AND username=? AND password=?",
                          (user[0], username, hashlib.md5(password.encode()).hexdigest()))
                g.credential_match = c.fetchone() is not None
                session["audit_nonce"] = uuid.uuid4().hex
                g.session_ref = hashlib.sha256(session["audit_nonce"].encode()).hexdigest()

            conn.close()

            if user:

                write_auth_event(
                    "success",
                    username
                )

                session["user"] = user[1]

                session["role"] = user[3]

                return redirect("/dashboard")

            else:

                write_auth_event(
                    "failed",
                    username
                )

                error = "Sai tài khoản hoặc mật khẩu"

        except Exception as e:

            write_auth_event(
                "error",
                username,
                error_type=type(e).__name__
            )

            error = f"Lỗi DB: {e}"

    return render_template_string("""
        <html>
        <body style="
            font-family:Arial;
            padding:50px;
            background:#1e293b;
            color:#fff;
        ">

            <h2>🌐 LARP Corp — Internal Portal</h2>

            {% if error %}
                <p style="color:#f43f5e;">{{ error }}</p>
            {% endif %}

            <form method="POST" style="max-width:300px;">

                <input
                    name="username"
                    placeholder="Username"
                    style="width:100%;padding:8px;margin:5px 0;"
                >

                <br>

                <input
                    name="password"
                    type="password"
                    placeholder="Password"
                    style="width:100%;padding:8px;margin:5px 0;"
                >

                <br>

                <button
                    type="submit"
                    style="
                        width:100%;
                        padding:10px;
                        background:#7c3aed;
                        color:#fff;
                        border:none;
                        cursor:pointer;
                    "
                >
                    Đăng nhập
                </button>

            </form>

            <p style="font-size:12px;color:#94a3b8;">
                Hệ thống quản trị nội bộ v1.0
            </p>

        </body>
        </html>
    """, error=error)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template_string("""
        <html>
        <body style="
            font-family:Arial;
            padding:50px;
            background:#1e293b;
            color:#fff;
        ">

            <h2>📊 Dashboard — Xin chào {{ user }}!</h2>

            <p>Role: <b>{{ role }}</b></p>

            <hr>

            <h3>📁 Upload tài liệu</h3>

            <form
                action="/upload"
                method="POST"
                enctype="multipart/form-data"
            >

                <input type="file" name="file">

                <button type="submit">
                    Upload
                </button>

            </form>

            <hr>

            <h3>🔧 Chức năng kiểm tra mạng</h3>

            <form action="/ping" method="GET">

                <input
                    name="ip"
                    placeholder="IP cần ping"
                    value="8.8.8.8"
                >

                <button type="submit">
                    Ping
                </button>

            </form>

            <hr>

            <a href="/logout" style="color:#f43f5e;">
                Đăng xuất
            </a>

        </body>
        </html>
    """,
        user=session["user"],
        role=session["role"]
    )


# ============================================================
# UPLOAD
# ============================================================

@app.route("/upload", methods=["POST"])
def upload():

    if "user" not in session:
        return redirect("/login")

    f = request.files.get("file")

    if not f:
        return "Không có file", 400

    # LAB ONLY:
    # Giữ nguyên hành vi upload chưa kiểm tra định dạng.

    filename = f.filename

    filepath = os.path.join(
        UPLOAD_DIR,
        filename
    )

    f.save(filepath)

    return (
        f"<h3>Upload thành công: "
        f"/tmp/uploads/{filename}</h3>"
        "<a href='/dashboard'>Quay lại</a>"
    )


# ============================================================
# PING
# ============================================================

@app.route("/ping")
def ping():

    if "user" not in session:
        return redirect("/login")

    ip = request.args.get(
        "ip",
        "127.0.0.1"
    )

    # LAB ONLY:
    # Command Injection intentionally retained.

    result = subprocess.run(
        f"ping -c 1 {ip}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )

    return (
        "<pre style='background:#000;color:#0f0;padding:15px;'>"
        f"{result.stdout}{result.stderr}"
        "</pre>"
        "<a href='/dashboard'>Quay lại</a>"
    )


# ============================================================
# LARP EDR PROCESS TEST
# ============================================================

@app.route("/api/system-check", methods=["POST"])
def system_check():

    # 1. Kiểm tra chế độ Lab

    if not EDR_LAB_ENABLED:
        abort(404)

    # 2. Bắt buộc đăng nhập

    if "user" not in session:
        abort(401)

    # 3. Chỉ Admin được chạy

    if session.get("role") != "admin":
        abort(403)

    # 4. Kiểm tra IP allowlist

    client_ip, ip_source = get_client_ip()

    if not is_lab_ip_allowed(client_ip):

        write_lab_event(
            "WEB_EDR_PROCESS_TEST_DENIED",
            {
                "reason": "IP_NOT_ALLOWED"
            }
        )

        abort(403)

    # 5. Giới hạn tần suất

    allowed, remaining = check_lab_cooldown(client_ip)

    if not allowed:

        return jsonify({
            "status": "rate_limited",
            "retry_after": remaining
        }), 429

    # 6. Tạo process tree cố định.
    # Không nhận command từ request.
    # Flask Python -> sh -> sleep

    try:

        proc = subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                "/usr/bin/id >/dev/null 2>&1; /bin/sleep 45"
            ],

            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,

            close_fds=True
        )

        write_lab_event(
            "WEB_EDR_PROCESS_TEST_STARTED",
            {
                "parent_pid": os.getpid(),
                "child_pid": proc.pid,
                "duration_seconds": 45
            }
        )

        return jsonify({

            "status": "started",

            "message": "EDR process test started",

            "parent_pid": os.getpid(),

            "shell_pid": proc.pid,

            "duration_seconds": 45

        }), 202

    except OSError as e:

        write_lab_event(
            "WEB_EDR_PROCESS_TEST_ERROR",
            {
                "error": type(e).__name__
            }
        )

        return jsonify({
            "status": "error",
            "message": "Cannot start test process"
        }), 500


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    init_db()

    flask_host = os.getenv("FLASK_HOST", "0.0.0.0")
    flask_port = int(os.getenv("FLASK_PORT", "5000"))

    print(f"[*] Starting Vulnerable Web App on {flask_host}:{flask_port}...", flush=True)
    app.run(
        host=flask_host,
        port=flask_port,
        debug=False
    )
