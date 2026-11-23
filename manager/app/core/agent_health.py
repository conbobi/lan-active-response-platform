from datetime import datetime, timedelta, timezone

STALE_AFTER = timedelta(seconds=30)
OFFLINE_AFTER = timedelta(seconds=120)
ACTIVITY_FRESHNESS = timedelta(seconds=45)


def as_utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def agent_health(agent, now=None):
    if agent is None:
        return "unknown"
    if agent.decommissioned_at is not None:
        return "decommissioned"
    last_seen = as_utc(agent.last_seen)
    if last_seen is None:
        return "unknown"
    age = (now or datetime.now(timezone.utc)) - last_seen
    if age >= OFFLINE_AFTER:
        return "offline"
    return "stale" if age >= STALE_AFTER else "online"
