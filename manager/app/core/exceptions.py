class AppException(Exception):
    """Base exception class for application exceptions."""
    def __init__(self, message: str = "An unexpected error occurred.", status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


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
    def __init__(self, message: str = "Requested bandwidth exceeds available topology link capacity."):
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
