"""Authentication for SOC operators (JWT + deprecated static tokens) and enrolled Linux Agents."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from hmac import compare_digest
import secrets
import time
from typing import Any

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_session
from app.core.response_outcome import AUTHORIZATION_FAILED, OutcomeHTTPException
from app.models.soc_auth import SocUser


def is_reserved_action(action):
    return isinstance(action, str) and action.startswith("network_")


@dataclass(frozen=True)
class OperatorContext:
    role: str
    agents: set[str] = field(default_factory=set)
    user_id: str | None = None
    username: str | None = None
    auth_method: str = "jwt"


def token_matches(token, expected):
    return bool(
        token
        and expected
        and 32 <= len(token) <= 256
        and compare_digest(hashlib.sha256(token.encode()).hexdigest(), expected)
    )


# Without a deployment key, restarting the Manager invalidates legacy sessions.
_SESSION_KEY = (settings.OPERATOR_SESSION_KEY or secrets.token_urlsafe(48)).encode()


def issue_session(digest):
    expires = int(time.time()) + 3600
    payload = f"ls1.{expires}.{secrets.token_hex(16)}"
    return f"{payload}.{session_mac(payload, digest)}", expires


def session_mac(payload, digest):
    return hmac.new(_SESSION_KEY, f"{payload}:{digest}".encode(), hashlib.sha256).hexdigest()


def matches_operator_token(token, digest):
    if not digest or len(token) > 256:
        return False
    if token_matches(token, digest):
        return True
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "ls1" or not parts[1].isascii() or not parts[1].isdigit():
        return False
    if not parts[3].isascii() or not compare_digest(session_mac(".".join(parts[:3]), digest), parts[3]):
        return False
    if int(parts[1]) <= time.time():
        raise OutcomeHTTPException(
            401,
            "Operator session expired",
            "SESSION_EXPIRED",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


def is_enrolled(agent_id):
    return agent_id in settings.NETWORK_AGENT_TOKENS


def authenticate_agent(agent_id, token):
    return token_matches(token, settings.NETWORK_AGENT_TOKENS.get(agent_id))


def _is_agent_credential(token: str) -> bool:
    return any(token_matches(token, digest) for digest in settings.NETWORK_AGENT_TOKENS.values())


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _enforce_role_and_scope(
    *,
    role: str,
    agents: set[str],
    agent_id: str | None,
    write: bool,
    allowed_write_roles: set[str] | None,
) -> None:
    if role == "operator":
        if not agents or (agent_id and agent_id not in agents):
            raise OutcomeHTTPException(403, "Permission denied for this Agent", AUTHORIZATION_FAILED)
    elif agent_id and agents and agent_id not in agents:
        raise OutcomeHTTPException(403, "Permission denied for this Agent", AUTHORIZATION_FAILED)

    if write:
        allowed = allowed_write_roles if allowed_write_roles is not None else {"admin"}
        if role not in allowed:
            msg = "Admin role required for write actions" if allowed == {"admin"} else "Admin or operator role required for write actions"
            raise OutcomeHTTPException(403, msg, AUTHORIZATION_FAILED)


def _verify_legacy_operator(
    clean_token: str,
    agent_id: str | None = None,
    *,
    write: bool = False,
    allowed_write_roles: set[str] | None = None,
) -> tuple[str, OperatorContext]:
    if not settings.ALLOW_LEGACY_OPERATOR_TOKENS:
        raise OutcomeHTTPException(
            401,
            "Invalid access token or insufficient permissions",
            AUTHORIZATION_FAILED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    has_legacy = bool(settings.NETWORK_OPERATORS or settings.NETWORK_LEGACY_ADMIN_TOKEN)
    if not has_legacy:
        raise OutcomeHTTPException(
            401,
            "Configured operator credentials required",
            AUTHORIZATION_FAILED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if settings.NETWORK_LEGACY_ADMIN_TOKEN and matches_operator_token(
        clean_token, settings.NETWORK_LEGACY_ADMIN_TOKEN
    ):
        return "legacy_admin", OperatorContext(
            role="admin", agents=set(), username="legacy_admin", auth_method="legacy_admin"
        )

    if settings.NETWORK_OPERATORS:
        for identity, config in settings.NETWORK_OPERATORS.items():
            if matches_operator_token(clean_token, config.token_sha256):
                _enforce_role_and_scope(
                    role=config.role,
                    agents=set(config.agents),
                    agent_id=agent_id,
                    write=write,
                    allowed_write_roles=allowed_write_roles,
                )
                return identity, OperatorContext(
                    role=config.role,
                    agents=set(config.agents),
                    username=identity,
                    auth_method="legacy_operator",
                )

    raise OutcomeHTTPException(
        401,
        "Invalid access token or insufficient permissions",
        AUTHORIZATION_FAILED,
        headers={"WWW-Authenticate": "Bearer"},
    )


def verify_operator_or_admin(
    authorization: str | None,
    agent_id: str | None = None,
    *,
    write: bool = False,
    allowed_write_roles: set[str] | None = None,
) -> tuple[str, Any]:
    """Legacy synchronous verifier for static operator tokens only (use async helper for JWT)."""
    from app.services.auth.jwt_service import looks_like_jwt

    kind, _, token = (authorization or "").partition(" ")
    clean_token = token.strip()
    if kind.lower() != "bearer" or not clean_token:
        raise HTTPException(
            status_code=401,
            detail="A valid administrator or operator access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if _is_agent_credential(clean_token) or looks_like_jwt(clean_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid access token or insufficient permissions",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _verify_legacy_operator(
        clean_token, agent_id=agent_id, write=write, allowed_write_roles=allowed_write_roles
    )


async def authenticate_operator_request(
    authorization: str | None,
    db: AsyncSession,
    agent_id: str | None = None,
    *,
    write: bool = False,
    allowed_write_roles: set[str] | None = None,
) -> tuple[str, OperatorContext]:
    """Unified async authenticator: validates JWT access tokens against live DB state, or legacy tokens."""
    from app.services.auth.jwt_service import decode_access_token, looks_like_jwt

    kind, _, token = (authorization or "").partition(" ")
    clean_token = token.strip()
    if kind.lower() != "bearer" or not clean_token:
        raise HTTPException(
            status_code=401,
            detail="A valid administrator or operator access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if _is_agent_credential(clean_token):
        raise OutcomeHTTPException(
            401,
            "Agent credentials cannot be used for operator access",
            AUTHORIZATION_FAILED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if looks_like_jwt(clean_token):
        claims = decode_access_token(clean_token)
        user = await db.get(SocUser, claims["sub"])
        if user is None or not user.is_active:
            raise OutcomeHTTPException(
                401,
                "Operator account is inactive or unavailable",
                AUTHORIZATION_FAILED,
                headers={"WWW-Authenticate": "Bearer"},
            )
        locked_until = _as_utc(user.locked_until)
        if locked_until and locked_until > datetime.now(timezone.utc):
            raise OutcomeHTTPException(
                401,
                "Operator account is temporarily locked",
                AUTHORIZATION_FAILED,
                headers={"WWW-Authenticate": "Bearer"},
            )
        if claims.get("tv") != user.token_version:
            raise OutcomeHTTPException(
                401,
                "Operator session has been revoked",
                "SESSION_EXPIRED",
                headers={"WWW-Authenticate": "Bearer"},
            )
        scopes = {scope.agent_id for scope in (user.agent_scopes or [])}
        _enforce_role_and_scope(
            role=user.role,
            agents=scopes,
            agent_id=agent_id,
            write=write,
            allowed_write_roles=allowed_write_roles,
        )
        return user.username, OperatorContext(
            role=user.role,
            agents=scopes,
            user_id=user.id,
            username=user.username,
            auth_method="jwt",
        )

    return _verify_legacy_operator(
        clean_token,
        agent_id=agent_id,
        write=write,
        allowed_write_roles=allowed_write_roles,
    )


async def authorize_agent(
    agent_id: str,
    authorization: str | None,
    db: AsyncSession,
    *,
    write: bool = False,
) -> tuple[str, OperatorContext]:
    return await authenticate_operator_request(authorization, db, agent_id=agent_id, write=write)


async def require_network_read(
    agent_id: str,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_session),
):
    return await authorize_agent(agent_id, authorization, db)


async def require_network_admin(
    agent_id: str,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_session),
):
    return await authorize_agent(agent_id, authorization, db, write=True)
