"""Machine-readable outcome codes for response endpoints.

Every error body carries ``outcome_code`` so the dashboard can tell an authorization problem from a
policy refusal, missing evidence or an offline Agent instead of showing one generic failure.
"""
from fastapi import HTTPException

SUCCESS = "SUCCESS"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
POLICY_DENIED = "POLICY_DENIED"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
EXECUTOR_UNAVAILABLE = "EXECUTOR_UNAVAILABLE"
AGENT_OFFLINE = "AGENT_OFFLINE"
VALIDATION_ERROR = "VALIDATION_ERROR"
CONFLICT = "CONFLICT"
NOT_FOUND = "NOT_FOUND"
INTERNAL_ERROR = "INTERNAL_ERROR"


class OutcomeHTTPException(HTTPException):
    """HTTPException with an explicit outcome code and optional extra body fields."""

    def __init__(self, status_code: int, detail: str, outcome: str, extra: dict | None = None, headers=None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.outcome = outcome
        self.extra = extra or {}


def default_outcome(status_code: int) -> str:
    if status_code in (401, 403):
        return AUTHORIZATION_FAILED
    if status_code in (400, 422):
        return VALIDATION_ERROR
    if status_code == 404:
        return NOT_FOUND
    if status_code == 409:
        return CONFLICT
    if status_code == 503:
        return EXECUTOR_UNAVAILABLE
    if status_code >= 500:
        return INTERNAL_ERROR
    return VALIDATION_ERROR


def error_body(status_code: int, detail, request_id=None, outcome: str | None = None, extra: dict | None = None):
    return {**(extra or {}), "error": detail, "detail": detail, "status_code": status_code, "request_id": request_id,
            "outcome_code": outcome or default_outcome(status_code)}
