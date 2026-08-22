from enum import Enum


class AgentStatus(str, Enum):
    ACTIVE = "active"
    ISOLATED = "isolated"
    QUARANTINE = "quarantine"
    INACTIVE = "inactive"
    DEAD = "dead"

class ActionType(str, Enum):
    LOG = "log"
    ALERT = "alert"
    ALERT_WITH_BUTTONS = "alert_with_buttons"
    AUTO_ISOLATE = "auto_isolate"

class CommandStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"