"""Collect firewall log records with persistent journal and file positions."""
from datetime import datetime, timedelta, timezone
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

from network_sources import CollectionError, run


def state_directory():
    return Path(os.environ.get("STATE_DIRECTORY", "/var/lib/larp-agent").split(":")[0])


def atomic_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_firewall_event(message, stamp, reference):
    fields = dict(re.findall(r"\b(IN|OUT|SRC|DST|PROTO|SPT|DPT)=([^\s]*)", message))
    if not {"IN", "OUT", "SRC", "DST", "PROTO"} <= fields.keys():
        return None
    try:
        source, destination = str(ipaddress.ip_address(fields["SRC"])), str(ipaddress.ip_address(fields["DST"]))
    except ValueError:
        return None
    prefix = message.partition("IN=")[0].strip()
    keyword = re.search(r"\b(BLOCK|DROP|DENY|REJECT|ALLOW|ACCEPT)\b", prefix, re.I)
    action = {"BLOCK": "DROP", "DENY": "DROP", "ALLOW": "ACCEPT"}.get(keyword[0].upper(), keyword[0].upper()) if keyword else "UNKNOWN"
    def port(key):
        item = fields.get(key, "")
        return int(item) if item.isdecimal() and 0 < int(item) <= 65535 else None
    packet = message[message.index("IN="):].strip()
    fingerprint = hashlib.sha256(f"{stamp[:19]} {prefix[-120:]} {packet}".encode()).hexdigest()[:24]
    event_id = hashlib.sha256(reference.encode()).hexdigest()[:24]
    return {"id": event_id, "fingerprint": fingerprint, "timestamp": stamp, "source": source, "destination": destination,
            "source_port": port("SPT"), "destination_port": port("DPT"), "protocol": fields["PROTO"][:20],
            "in_interface": fields["IN"][:40], "out_interface": fields["OUT"][:40], "action": action,
            "prefix": prefix[-120:], "reference": reference[:512]}


def journal_events(cursor):
    args = ["--no-pager", "_TRANSPORT=kernel", "--output=json", "--output-fields=MESSAGE"]
    if cursor:
        args += ["--after-cursor", cursor, "--lines=+500"]
    else:
        args += ["--since=-24h", "--lines=500"]
    rows = []
    for line in run("journalctl", *args, limit=1_500_000).splitlines():
        entry = json.loads(line)
        cursor = entry.get("__CURSOR", cursor)
        message = entry.get("MESSAGE")
        if isinstance(message, str) and cursor and "__REALTIME_TIMESTAMP" in entry:
            stamp = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1e6, timezone.utc).isoformat()
            if event := parse_firewall_event(message, stamp, f"journal:{cursor}"):
                rows.append(event)
    return cursor, rows


def file_events(path, position):
    rows = []
    if not path.exists():
        return position, rows
    current = path.stat()
    identity, offset = position or (None, 0)
    if identity and identity != current.st_ino:
        candidates = [entry for entry in path.parent.glob(path.name + ".*") if entry.is_file()]
        rotated = next((entry for entry in candidates if entry.stat().st_ino == identity), None)
        if rotated and rotated.suffix != ".gz":
            rotated_position, rows = file_events(rotated, position)
            if rotated_position[1] < rotated.stat().st_size and rotated_position != tuple(position):
                return rotated_position, rows
        offset = 0
    if offset > current.st_size:
        offset = 0
    with path.open("rb") as handle:
        handle.seek(offset if identity else max(0, current.st_size - 256_000))
        if not identity and handle.tell():
            handle.readline(8192)
        for _ in range(500):
            start = handle.tell()
            line = handle.readline(8192)
            if not line:
                break
            if not line.endswith(b"\n") and handle.tell() == current.st_size:
                handle.seek(start)
                break
            message = line.decode("utf-8", "replace")
            match = re.search(r"\[[^]]+\]\s+IN=", message)
            if not match:
                continue
            try:
                stamp = datetime.fromisoformat(message.split()[0]).astimezone(timezone.utc)
            except ValueError:
                try:
                    local = datetime.now().astimezone()
                    stamp = datetime.strptime(message[:15], "%b %d %H:%M:%S").replace(year=local.year).astimezone(timezone.utc)
                    if stamp > local + timedelta(days=1):
                        stamp = stamp.replace(year=stamp.year - 1)
                except ValueError:
                    continue
            if event := parse_firewall_event(message[match.start():], stamp.isoformat(), f"{path.name}:{current.st_ino}:{start}"):
                rows.append(event)
        return (current.st_ino, handle.tell()), rows


def collect_events():
    path = state_directory() / "network-events.json"
    errors = {}
    try:
        state = json.loads(path.read_text()) if path.exists() else {}
    except (OSError, ValueError) as error:
        state = {}
        errors["cursor"] = str(error)
    cursor, position = state.get("journal"), state.get("file")
    journal_rows, file_rows = [], []
    try:
        cursor, journal_rows = journal_events(cursor)
    except (CollectionError, OSError, ValueError) as error:
        errors["journal"] = str(error)
        if cursor:
            try:
                cursor, journal_rows = journal_events(None)
            except (CollectionError, OSError, ValueError) as reset_error:
                errors["journal"] = str(reset_error)
    log_path = Path("/var/log/ufw.log")
    try:
        position, file_rows = file_events(log_path, position)
    except OSError as error:
        errors["ufw.log"] = str(error)
    source = "journal + ufw.log" if log_path.exists() else "journal"
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=24)).isoformat()
    merged = {row["id"]: row for row in [*state.get("events", []), *journal_rows, *file_rows] if row["timestamp"] >= cutoff}
    recent = sorted(merged.values(), key=lambda row: row["timestamp"], reverse=True)
    journal_counts = Counter(row.get("fingerprint") for row in recent if row["reference"].startswith("journal:"))
    events = []
    for row in recent:
        fingerprint = row.get("fingerprint")
        if not row["reference"].startswith("journal:") and fingerprint and journal_counts[fingerprint]:
            journal_counts[fingerprint] -= 1
            continue
        events.append(row)
        if len(events) == 500:
            break
    try:
        atomic_json(path, {"journal": cursor, "file": position, "events": events})
    except OSError as error:
        errors["cursor"] = str(error)
    blocked = [row for row in events if row["action"] in {"DROP", "REJECT"}]
    return {"rows": events, "source": source, "errors": errors, "blocked": len(blocked),
            "retention_hours": 24, "limit": 500,
            "by_hour": sorted(Counter(row["timestamp"][:13] + ":00 UTC" for row in blocked).items()),
            "by_source": Counter(row["source"] for row in blocked).most_common(10),
            "by_port": Counter(row["destination_port"] for row in blocked if row["destination_port"]).most_common(10),
            "by_protocol": Counter(row["protocol"] for row in blocked).most_common(10)}
