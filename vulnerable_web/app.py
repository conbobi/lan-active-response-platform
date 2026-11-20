
# ~/vulnerable_web/app.py

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

# Chỉ dùng cho lab demo.
# Khi triển khai thật, cần dùng secret key ngẫu nhiên từ environment.
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "insecure_key_123"
)

BASE_DIR = "/home/webuser/vulnerable_web"

UPLOAD_DIR = "/tmp/uploads"
AUTH_LOG = os.path.join(BASE_DIR, "auth.log")
FALLBACK_AUTH_LOG = "/tmp/web_auth.log"

DB_PATH = "/tmp/users.db"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)


# ============================================================
# LARP WEB AUTHENTICATION LOGGING
# ============================================================

auth_logger = logging.getLogger("larp_web_auth")
auth_logger.setLevel(logging.INFO)
auth_logger.propagate = False

if not auth_logger.handlers:

    try:
        handler = logging.FileHandler(
            AUTH_LOG,
            encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(message)s")
        )
        auth_logger.addHandler(handler)
        os.chmod(AUTH_LOG, 0o644)
    except Exception:
        pass

    try:
        fallback_handler = logging.FileHandler(
            FALLBACK_AUTH_LOG,
            encoding="utf-8"
        )
        fallback_handler.setFormatter(
            logging.Formatter("%(message)s")
        )
        auth_logger.addHandler(fallback_handler)
        os.chmod(FALLBACK_AUTH_LOG, 0o666)
    except Exception:
        pass


def get_client_ip():
    """
    Lấy IP Client từ Cloudflare Tunnel.

    Chỉ tin CF-Connecting-IP khi origin được giới hạn
    để chỉ nhận traffic từ Cloudflare Tunnel.

    Không tin tưởng X-Forwarded-For do client có thể giả mạo.
    """

    cf_ip = request.headers.get(
        "CF-Connecting-IP",
        ""
    ).strip()

    if cf_ip:

        try:
            return (
                str(ipaddress.ip_address(cf_ip)),
                "cloudflare"
            )

        except ValueError:
            pass

    remote_ip = request.remote_addr or "unknown"

    return remote_ip, "remote_addr"


def write_auth_event(status, username, error_type=None):

    client_ip, ip_source = get_client_ip()

    event = {
        "status": status,

        "event_type": "WEB_AUTH_" + status.upper(),

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "username": str(username or "")[:128],

        "source_ip": client_ip,

        "ip_source": ip_source,

        "service": "flask_web",

        "path": request.path,

        "method": request.method
    }

    if error_type:
        event["error_type"] = error_type

    auth_logger.info(
        json.dumps(
            event,
            ensure_ascii=False
        )
    )


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

    # Nếu cloudflared chạy trực tiếp trên cùng máy:
    # nên bind Flask vào 127.0.0.1.
    #
    # Nếu cloudflared chạy trong container riêng:
    # cần cấu hình địa chỉ origin phù hợp.

    flask_host = os.getenv(
        "FLASK_HOST",
        "127.0.0.1"
    )

    app.run(
        host=flask_host,
        port=5000,
        debug=False
    )
