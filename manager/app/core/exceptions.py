class AppException(Exception):
    """Base exception class for application exceptions.

    ``outcome`` is an optional response outcome code (see app.core.response_outcome) and ``extra``
    carries additional machine-readable fields for the client, e.g. ``{"use": "response_assist"}``.
    """
    def __init__(self, message: str = "An unexpected error occurred.", status_code: int = 500,
                 outcome: str | None = None, extra: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.outcome = outcome
        self.extra = extra or {}


class NotFoundError(AppException):
    def __init__(self, message: str = "Resource not found."):
        super().__init__(message=message, status_code=404)


class AgentNotFoundError(NotFoundError):
    def __init__(self, agent_id: str):
        super().__init__(message=f"Agent with ID '{agent_id}' was not found.")


class ConflictError(AppException):
    def __init__(self, message: str = "Resource conflict occurred."):
        super().__init__(message=message, status_code=409)


class BandwidthExceededError(AppException):
    def __init__(self, message: str = "Requested bandwidth exceeds available network capacity."):
        super().__init__(message=message, status_code=400)


class PathNotFoundError(AppException):
    def __init__(self, source_id: str, dest_id: str):
        super().__init__(message=f"No valid routing path found from '{source_id}' to '{dest_id}'.", status_code=404)


class CommandExecutionError(AppException):
    def __init__(self, command_id: str, details: str):
        super().__init__(message=f"Command '{command_id}' execution failed: {details}", status_code=500)


class LockAcquisitionError(AppException):
    def __init__(self, lock_key: str):
        super().__init__(message=f"Failed to acquire lock for key '{lock_key}'.", status_code=503)
class BadRequestError(AppException):
    def __init__(self, message: str = "Bad request.", outcome: str | None = None):
        super().__init__(message=message, status_code=400, outcome=outcome)


class PolicyDeniedError(AppException):
    """The request is well formed and authorized but response policy refuses it on this path."""
    def __init__(self, message: str, extra: dict | None = None):
        super().__init__(message=message, status_code=409, outcome="POLICY_DENIED", extra=extra)


class InsufficientEvidenceError(AppException):
    def __init__(self, message: str, extra: dict | None = None):
        super().__init__(message=message, status_code=409, outcome="INSUFFICIENT_EVIDENCE", extra=extra)


class FlappingCooldownError(AppException):
    def __init__(self, message: str = "Action rejected due to anti-flapping cooldown."):
        super().__init__(message=message, status_code=429)

