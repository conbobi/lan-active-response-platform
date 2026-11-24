"""Emit bounded HTTP indicators without copying request inputs into telemetry."""
import re
from urllib.parse import unquote, urlsplit

SQL_PATTERNS = {
    "sql_boolean_expression": re.compile(r"""['"]\s*\)?\s*(?:and|or)\s+[\s('"\d]+[^\s]{0,40}\s*=""", re.I),
    "sql_query_operator": re.compile(r"\bunion\s+(?:all\s+)?select\b|\bselect\s+(?:case|concat|char)\b|\border\s+by\s+\d+\s*--", re.I),
    "sql_delay_function": re.compile(r"\b(?:pg_sleep|sleep|benchmark|dbms_pipe\.receive_message)\s*\(|\bwaitfor\s+delay\b", re.I),
    "sql_error_expression": re.compile(r"\b(?:extractvalue|updatexml)\s*\(", re.I),
}
ACCOUNT = re.compile(r"[A-Za-z0-9_.:@+\\-]{1,64}\Z")


def sql_indicators(value):
    return {name for name, pattern in SQL_PATTERNS.items() if pattern.search(value[:4096])} if isinstance(value, str) else set()


def safe_http_target(value):
    try:
        parts = urlsplit(value[:4096])
    except ValueError:
        return None, set()
    route = parts.path if parts.path.startswith("/") else None
    indicators = sql_indicators(unquote(parts.query)) | sql_indicators(unquote(route or ""))
    if route and len(route) <= 256 and not any(ord(char) < 32 for char in route):
        route = "/".join("[redacted]" if len(segment) > 48 else segment for segment in route.split("/"))
    else:
        route = None
    return route, indicators
