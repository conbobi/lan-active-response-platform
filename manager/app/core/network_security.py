"""Authentication for the network module and enrolled Linux Agents."""
import hashlib
from hmac import compare_digest

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
    if not settings.NETWORK_OPERATORS:
        raise HTTPException(503, "Network access has not been configured")
    kind, _, token = (authorization or "").partition(" ")
    operators = settings.NETWORK_OPERATORS.items()
    for identity, config in operators:
        if kind.lower() == "bearer" and token_matches(token, config.token_sha256):
            if agent_id not in config.agents or (write and config.role != "admin"):
                raise HTTPException(403, "Permission denied for this Agent")
            return identity, config
    raise HTTPException(401, "A valid network access token is required", headers={"WWW-Authenticate": "Bearer"})


def require_network_read(agent_id: str, authorization: str | None = Header(None)):
    return authorize_agent(agent_id, authorization)


def require_network_admin(agent_id: str, authorization: str | None = Header(None)):
    return authorize_agent(agent_id, authorization, write=True)


def is_reserved_action(action):
    return isinstance(action, str) and action.startswith("network_")
