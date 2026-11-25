"""Opt-in application enforcement for a disposable, direct-peer Flask lab."""
import hashlib
import ipaddress
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path


def install_guard(app):
    from flask import g, request, session

    directory = os.getenv("LARP_HTTP_LAB_STATE")
    if not directory:
        return
    root = Path(directory).resolve(strict=True)
    observations = root / "observations.db"
    with closing(sqlite3.connect(observations)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS observation
            (request_id TEXT PRIMARY KEY, peer TEXT NOT NULL, at REAL NOT NULL,
             forwarded INTEGER NOT NULL, action_id TEXT, status INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS grant_observation
            (request_id TEXT PRIMARY KEY, peer TEXT NOT NULL, at REAL NOT NULL, session_ref TEXT NOT NULL,
             credential_match INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS revocation_receipt
            (action_id TEXT PRIMARY KEY, session_ref TEXT NOT NULL, request_id TEXT NOT NULL, at REAL NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS rate_window
            (action_id TEXT PRIMARY KEY, starts_at REAL NOT NULL, attempts INTEGER NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS observation_time ON observation(at)")
        db.execute("CREATE INDEX IF NOT EXISTS observation_action ON observation(action_id, at)")

    @app.before_request
    def enforce_lease():
        nonce = session.get("audit_nonce")
        if isinstance(nonce, str) and len(nonce) == 32 and (root / "leases.db").exists():
            ref = hashlib.sha256(nonce.encode()).hexdigest()
            try:
                with closing(sqlite3.connect((root / "leases.db").as_uri() + "?mode=ro", uri=True, timeout=0.1)) as db:
                    configured = db.execute("SELECT 1 FROM sqlite_master WHERE name='revoked_session'").fetchone()
                    revoked = db.execute("SELECT action_id FROM revoked_session WHERE session_ref=?", (ref,)).fetchone() if configured else None
                if revoked:
                    session.clear()
                    g.revocation = (revoked[0], ref)
                    return "Session revoked", 401
            except sqlite3.Error:
                app.logger.warning("Lab session verification unavailable")
                return "Session verification unavailable", 503
        if request.path != "/login" or request.method != "POST":
            return
        try:
            peer = ipaddress.ip_address(request.environ.get("REMOTE_ADDR", ""))
        except ValueError:
            return
        if not any(peer in subnet for subnet in TEST_NETWORKS):
            return
        g.response_peer = str(peer)
        try:
            with closing(sqlite3.connect((root / "leases.db").as_uri() + "?mode=ro", uri=True, timeout=0.1)) as db:
                row = db.execute("SELECT action_id,kind FROM lease WHERE peer=? AND expires_at>?",
                                 (str(peer), time.time())).fetchone()
        except sqlite3.OperationalError:
            app.logger.warning("Lab response lease store unavailable")
            return
        if row:
            if row[1] == "temporary_ip_block":
                g.response_action = row[0]
                return "Temporary application block", 403
            if row[1] == "apply_rate_limit":
                try:
                    with closing(sqlite3.connect(observations, timeout=0.2)) as db, db:
                        stamp = time.time()
                        db.execute("DELETE FROM rate_window WHERE starts_at<=?", (stamp - 10,))
                        db.execute("""INSERT INTO rate_window VALUES (?,?,1) ON CONFLICT(action_id)
                            DO UPDATE SET attempts=MIN(attempts+1,4)""", (row[0], stamp))
                        attempts = db.execute("SELECT attempts FROM rate_window WHERE action_id=?", (row[0],)).fetchone()[0]
                    if attempts > 3:
                        g.response_action = row[0]
                        return "Temporary login rate limit", 429
                except sqlite3.Error:
                    app.logger.warning("Lab response counter unavailable")

    @app.after_request
    def record_decision(response):
        if g.get("revocation") and g.get("observation_id") and response.status_code == 401:
            try:
                with closing(sqlite3.connect(observations, timeout=0.2)) as db, db:
                    db.execute("INSERT OR IGNORE INTO revocation_receipt VALUES (?,?,?,?)",
                               (*g.revocation, g.observation_id, time.time()))
            except sqlite3.Error:
                app.logger.warning("Lab session revocation receipt unavailable")
        if not g.get("response_peer") or not g.get("observation_id"):
            return response
        forwarded = any(h in request.headers for h in ("Forwarded", "X-Forwarded-For", "CF-Connecting-IP"))
        try:
            with closing(sqlite3.connect(observations, timeout=0.2)) as db, db:
                stamp = time.time()
                db.execute("DELETE FROM observation WHERE at < ?", (stamp - 3600,))
                db.execute("DELETE FROM grant_observation WHERE at < ?", (stamp - 3600,))
                if g.get("session_ref") and type(g.get("credential_match")) is bool and response.status_code == 302:
                    db.execute("INSERT INTO grant_observation VALUES (?,?,?,?,?)", (
                        g.observation_id, g.response_peer, stamp, g.session_ref, int(g.credential_match)))
                db.execute("INSERT INTO observation VALUES (?,?,?,?,?,?)",
                           (g.observation_id, g.response_peer, stamp, forwarded, g.get("response_action"), response.status_code))
        except sqlite3.Error:
            app.logger.warning("Lab response receipt unavailable")
        return response


TEST_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
