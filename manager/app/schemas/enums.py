from enum import Enum


class AgentStatus(str, Enum):
    ACTIVE = "active"
    ISOLATED = "isolated"
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
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"