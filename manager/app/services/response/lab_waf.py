"""Local lab WAF adapter. Each configured Agent has its own private state directory."""
import ipaddress
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from fastapi import HTTPException

from app.core.config import settings

NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
TAILNET = ipaddress.ip_network("100.64.0.0/10")
TTL = 300


def eligible(agent, peer):
    config = settings.HTTP_RESPONSE_LAB_WAFS.get(agent)
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return bool(config and peer in config.disposable_peers and peer not in config.protected_peers
                and any(ip in network and ip not in (network.network_address, network.broadcast_address) for network in (*NETWORKS, TAILNET)))


def store(agent, database, mode):
    config = settings.HTTP_RESPONSE_LAB_WAFS.get(agent)
    if not config:
        raise HTTPException(409, "Lab adapter unavailable")
    root = Path(config.directory)
    if not root.is_absolute() or not root.is_dir():
        raise HTTPException(409, "Lab adapter directory unavailable")
    return sqlite3.connect((root / database).as_uri() + "?mode=" + mode, uri=True, timeout=0.4)


def direct_observation(agent, peer, request_id, observed_at):
    if not eligible(agent, peer) or not request_id:
        return False
    try:
        with closing(store(agent, "observations.db", "ro")) as db:
            row = db.execute("SELECT at FROM observation WHERE request_id=? AND peer=? AND forwarded=0 AND action_id IS NULL",
                             (request_id, peer)).fetchone()
            return bool(row and 0 <= time.time() - row[0] <= TTL and abs(row[0] - observed_at) <= 5)
    except (HTTPException, sqlite3.Error, OSError):
        return False


def activate(agent, peer, key, deadline, kind):
    if kind not in {"temporary_ip_block", "apply_rate_limit"} or not eligible(agent, peer) or deadline <= time.time():
        raise HTTPException(409, "Target protection or lease deadline prevents application")
    with closing(store(agent, "leases.db", "rwc")) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS lease (peer TEXT PRIMARY KEY, action_id TEXT NOT NULL, expires_at REAL NOT NULL, kind TEXT NOT NULL)")
        db.execute("""INSERT INTO lease VALUES (?,?,?,?) ON CONFLICT(peer) DO UPDATE SET
            action_id=excluded.action_id, expires_at=excluded.expires_at, kind=excluded.kind
            WHERE lease.expires_at<=? OR lease.action_id=excluded.action_id""", (peer, key, deadline, kind, time.time()))
        if db.execute("SELECT action_id,expires_at,kind FROM lease WHERE peer=?", (peer,)).fetchone() != (key, deadline, kind):
            raise HTTPException(409, "An active lease already owns this target")


def verify(agent, peer, key, start, deadline, kind):
    with closing(store(agent, "leases.db", "ro")) as db:
        lease = db.execute("SELECT action_id,expires_at,kind FROM lease WHERE peer=?", (peer,)).fetchone()
    if time.time() >= deadline:
        return "expired", []
    if lease != (key, deadline, kind):
        return "failed", []
    with closing(store(agent, "observations.db", "ro")) as db:
        receipt = db.execute("""SELECT request_id FROM observation WHERE action_id=? AND peer=? AND status=?
            AND at BETWEEN ? AND ? ORDER BY at DESC LIMIT 1""", (key, peer, 429 if kind == "apply_rate_limit" else 403, start, min(time.time(), deadline))).fetchone()
    return ("succeeded", [receipt[0]]) if receipt else ("verifying", [])


def rollback(agent, peer, key):
    with closing(store(agent, "leases.db", "rw")) as db, db:
        db.execute("DELETE FROM lease WHERE peer=? AND action_id=?", (peer, key))
        if db.execute("SELECT 1 FROM lease WHERE peer=? AND action_id=?", (peer, key)).fetchone():
            raise HTTPException(409, "Lease rollback could not be verified")


def credential_mismatch(agent, peer, request_id, session_ref, observed_at):
    if not eligible(agent, peer):
        return False
    try:
        with closing(store(agent, "observations.db", "ro")) as db:
            result = db.execute("""SELECT at FROM grant_observation WHERE peer=? AND request_id=?
                AND session_ref=? AND credential_match=0""", (peer, request_id, session_ref)).fetchone()
        return bool(result and abs(result[0] - observed_at) <= 5)
    except (HTTPException, sqlite3.Error, OSError):
        return False


def revoke(agent, ref, action_id):
    with closing(store(agent, "leases.db", "rwc")) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS revoked_session (session_ref TEXT PRIMARY KEY, action_id TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO revoked_session VALUES (?,?)", (ref, action_id))
        if db.execute("SELECT action_id FROM revoked_session WHERE session_ref=?", (ref,)).fetchone() != (action_id,):
            raise HTTPException(409, "Session already revoked by another action")


def revocation_receipt(agent, ref, key):
    with closing(store(agent, "observations.db", "ro")) as db:
        return db.execute("SELECT request_id FROM revocation_receipt WHERE action_id=? AND session_ref=?", (key, ref)).fetchone()
