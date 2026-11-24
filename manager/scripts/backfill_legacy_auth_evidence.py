"""Preview, or apply with a compare-and-set guard, a legacy auth evidence backfill."""
import argparse
import json
import re
import subprocess
from datetime import timedelta

from app.services.detection.behavior_evidence import SQLI, TOKEN, address, observed_time, signature_indicators, stable_id

READ_INCIDENT = """
BEGIN READ ONLY;
SELECT json_build_object('id', id, 'agent_id', agent_id, 'created_at', created_at, 'snapshot', detection_evidence)
FROM incidents WHERE id = :'incident';
COMMIT;
"""

READ_ATTEMPTS = """
BEGIN READ ONLY;
SELECT json_build_object('id', id, 'username', username, 'timestamp', timestamp, 'status', status, 'count', count)
FROM auth_events
WHERE agent_id = :'agent' AND service = :'service' AND source_ip = :'source'
  AND timestamp BETWEEN :'start'::timestamptz AND :'end'::timestamptz
ORDER BY timestamp, id;
COMMIT;
"""

APPLY = """
BEGIN;
UPDATE incidents
SET detection_evidence = detection_evidence::jsonb || jsonb_build_object('behavior', :'behavior'::jsonb)
WHERE id = :'incident' AND agent_id = :'agent' AND detection_evidence::jsonb = :'snapshot'::jsonb
AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(:'references'::jsonb) AS ref(event_id)
    WHERE NOT EXISTS (
        SELECT 1 FROM auth_events a
        WHERE a.id = ref.event_id AND a.agent_id = :'agent' AND a.service = :'service'
          AND a.source_ip = :'source' AND a.timestamp BETWEEN :'start'::timestamptz AND :'end'::timestamptz
    )
)
RETURNING id;
COMMIT;
"""


def sql(args, statement, **variables):
    flags = [f"-v{key}={value}" for key, value in variables.items()]
    return subprocess.run(
        ["docker", "exec", "-i", args.container, "psql", "-X", "-w", "-qAt",
         "-U", args.user, "-d", args.database, "-v", "ON_ERROR_STOP=1", *flags],
        input=statement, text=True, capture_output=True, check=True,
    ).stdout.strip()


def review(args):
    value = sql(args, READ_INCIDENT, incident=args.incident)
    if not value:
        raise ValueError("Incident unavailable")
    incident = json.loads(value)
    snapshot = incident["snapshot"] or {}
    if snapshot.get("rule_id") != "brute_force" or snapshot.get("behavior"):
        raise ValueError("Only unbackfilled legacy brute_force incidents are eligible")
    factors = snapshot.get("factors") or []
    auth_factor = next((factor for factor in factors if factor.get("rule") == "brute_force"), {})
    match = re.fullmatch(r"Brute force on ([\w-]+) from (\S+): (\d+) failed logins", auth_factor.get("reason", ""))
    if not match or not address(match[2]):
        raise ValueError("Legacy factor cannot identify an auth cohort")
    end = observed_time(snapshot.get("risk_calculated_at"))
    created = observed_time(incident["created_at"])
    if end is None or created is None or abs(created - end) > timedelta(seconds=5):
        raise ValueError("Incident clock does not identify its original risk assessment")
    scope = {
        "agent": incident["agent_id"], "service": match[1], "source": address(match[2]),
        "start": (end - timedelta(seconds=60)).isoformat(), "end": end.isoformat(),
    }
    rows = [json.loads(line) for line in sql(args, READ_ATTEMPTS, **scope).splitlines()]
    if not rows:
        raise ValueError("No raw authentication records remain in the original window")
    indicators = {row["id"]: signature_indicators(row["username"]) for row in rows}
    indicator_ids = [key for key, hits in indicators.items() if hits]
    if not indicator_ids:
        raise ValueError("No SQL syntax indicators in the observed authentication records")
    ids = [row["id"] for row in rows]
    users = {row["username"] for row in rows if TOKEN.fullmatch(row["username"] or "")
             and row["username"] != "unknown"}
    scope_start, scope_end = rows[0]["timestamp"], rows[-1]["timestamp"]
    evidence = {
        "evidence_id": stable_id("auth_group_", incident["id"], *ids),
        "evidence_type": "authentication", "source": "auth_events", "source_event_ids": ids,
        "indicator_source_event_ids": indicator_ids, "indicator_event_count": len(indicator_ids),
        "agent_id": scope["agent"], "classification": SQLI,
        "service": scope["service"], "source_ip": scope["source"],
        "username": next(iter(users)) if len(users) == 1 else None,
        "authentication_status": sorted({row["status"] for row in rows}),
        "failed_attempts": sum(row["count"] for row in rows if row["status"] == "failed"),
        "successful_attempts": sum(row["count"] for row in rows if row["status"] == "success"),
        "error_attempts": sum(row["count"] for row in rows if row["status"] == "error"),
        "first_attempt_at": scope_start, "last_attempt_at": scope_end,
        "detection_window_seconds": 60, "time_basis": ["legacy_receipt"],
        "timestamp_resolution": "manager_batch_receipt",
        "legacy_duplicate_status": "unresolved_mirrors",
        "legacy_reported_failed_attempts": int(match[3]),
        "payload_indicators": sorted(set().union(*indicators.values())),
        "exploitation_outcome": "undetermined",
    }
    return incident, scope, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incident", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--user", default="larp")
    parser.add_argument("--database", default="larpdb")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        incident, scope, evidence = review(args)
        print(json.dumps({"incident": args.incident, "scope": scope, "behavior": evidence}, indent=2))
        if args.apply:
            result = sql(
                args, APPLY, incident=args.incident, snapshot=json.dumps(incident["snapshot"]),
                behavior=json.dumps(evidence), references=json.dumps(evidence["source_event_ids"]), **scope,
            )
            if result != args.incident:
                raise ValueError("Backfill guard failed or incident changed")
            print(f"Applied evidence backfill to {result}")
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error) if isinstance(error, ValueError) else "PostgreSQL backfill command failed") from error


if __name__ == "__main__":
    main()
