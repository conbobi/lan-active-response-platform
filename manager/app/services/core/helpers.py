import uuid
from datetime import datetime, timezone


def generate_id(prefix: str = "id") -> str:
    """Generate a prefixed unique identifier."""
    uid = uuid.uuid4().hex[:12]
    return f"{prefix}_{uid}" if prefix else uid


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)
