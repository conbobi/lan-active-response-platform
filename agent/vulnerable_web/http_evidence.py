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


# Shell metacharacters in a value the application passes to /bin/sh (route-specific: only /ping).
SHELL_PATTERNS = {
    "shell_command_separator": re.compile(r";|\n|\r"),
    "shell_pipe": re.compile(r"(?<!\|)\|(?!\|)"),
    "shell_and_or": re.compile(r"&&|\|\|"),
    "shell_background": re.compile(r"(?<!&)&(?!&)"),
    "shell_substitution": re.compile(r"\$\(|`"),
    "shell_redirection": re.compile(r"[<>]"),
}
FILENAME = re.compile(r"[^A-Za-z0-9._-]")


def shell_indicators(value):
    return {name for name, pattern in SHELL_PATTERNS.items() if pattern.search(value[:4096])} if isinstance(value, str) else set()


def referenced_files(value, directory):
    """Basenames of files under ``directory`` named in ``value`` (bounded, sanitised)."""
    if not isinstance(value, str):
        return []
    prefix = directory.rstrip("/") + "/"
    names = []
    for match in re.finditer(re.escape(prefix) + r"([^\s;|&`$()<>'\"]{1,255})", value[:4096]):
        name = FILENAME.sub("_", match.group(1).split("/")[-1])[:128]
        if name and name not in names:
            names.append(name)
    return names[:8]


def safe_filename(value):
    """Printable, bounded form of a client-supplied filename for telemetry (not for storage)."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch if ch.isprintable() and ch not in "\\" else "_" for ch in value)[:255]
    return cleaned or None
