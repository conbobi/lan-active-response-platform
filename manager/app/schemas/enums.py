from enum import Enum


class AgentStatus(str, Enum):
    ACTIVE = "active"
    ISOLATED = "isolated"
    QUARANTINE = "quarantine"
    INACTIVE = "inactive"
    DEAD = "dead"


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