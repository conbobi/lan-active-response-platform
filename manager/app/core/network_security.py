"""Authentication for the network module and enrolled Linux Agents."""
import hashlib
from hmac import compare_digest
from typing import Any
from fastapi import Header, HTTPException

from app.core.config import settings


def token_matches(token, expected):
    return bool(token and expected and 32 <= len(token) <= 256 and compare_digest(
        hashlib.sha256(token.encode()).hexdigest(), expected
    ))


def is_enrolled(agent_id):
    return agent_id in settings.NETWORK_AGENT_TOKENS


def authenticate_agent(agent_id, token):
    return token_matches(token, settings.NETWORK_AGENT_TOKENS.get(agent_id))


def authorize_agent(agent_id, authorization, *, write=False):
    return verify_operator_or_admin(authorization, agent_id=agent_id, write=write)


def verify_operator_or_admin(
    authorization: str | None,
    agent_id: str | None = None,
    *,
    write: bool = False
) -> tuple[str, Any]:
    """
    Unified authorization for operators and administrators.
    Accepts:
    1. Operator tokens in settings.NETWORK_OPERATORS (soc-admin with admin role, soc-reader with analyst role).
    2. Legacy administrator token in settings.NETWORK_LEGACY_ADMIN_TOKEN (superuser privileges).
    Enforces role permissions (write requires admin) and agent scoping.
    """
    has_auth_configured = bool(settings.NETWORK_OPERATORS or settings.NETWORK_LEGACY_ADMIN_TOKEN)
    if not has_auth_configured:
        # Development mode when no credentials are configured
        return "anonymous_dev", None

    kind, _, token = (authorization or "").partition(" ")
    clean_token = token.strip()
    if kind.lower() != "bearer" or not clean_token:
        raise HTTPException(
            status_code=401,
            detail="A valid administrator or operator access token is required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # 1. Legacy administrator token (superuser privilege, exempt from agent scope)
    if settings.NETWORK_LEGACY_ADMIN_TOKEN and token_matches(clean_token, settings.NETWORK_LEGACY_ADMIN_TOKEN):
        return "legacy_admin", None

    # 2. Operator tokens
    if settings.NETWORK_OPERATORS:
        for identity, config in settings.NETWORK_OPERATORS.items():
            if token_matches(clean_token, config.token_sha256):
                if agent_id and config.agents and agent_id not in config.agents:
                    raise HTTPException(status_code=403, detail="Permission denied for this Agent")
                if write and config.role != "admin":
                    raise HTTPException(status_code=403, detail="Admin role required for write actions")
                return identity, config

    raise HTTPException(
        status_code=401,
        detail="Invalid access token or insufficient permissions",
        headers={"WWW-Authenticate": "Bearer"}
    )


def require_network_read(agent_id: str, authorization: str | None = Header(None)):
    return authorize_agent(agent_id, authorization)


def require_network_admin(agent_id: str, authorization: str | None = Header(None)):
    return authorize_agent(agent_id, authorization, write=True)


def is_reserved_action(action):
    return isinstance(action, str) and action.startswith("network_")
