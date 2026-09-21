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


class ResponseActionType(str, Enum):
    ISOLATE = "isolate"
    KILL = "kill"
    BLOCK_IP = "block_ip"
    QUARANTINE = "quarantine"


class ResponseActionStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    REVERTING = "reverting"
    REVERTED = "reverted"
    FAILED = "failed"


class ActionAuditEvent(str, Enum):
    CREATED = "created"
    APPLIED = "applied"
    UNDO_REQUESTED = "undo_requested"
    UNDONE = "undone"
    AUTO_UNDONE = "auto_undone"
    FAILED = "failed"