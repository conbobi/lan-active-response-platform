"""Short-lived HS256 JWT access tokens with key rotation (kid) and strict claim validation."""
import secrets
import time
import uuid

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.config import settings
from app.core.response_outcome import AUTHORIZATION_FAILED, OutcomeHTTPException

# Generated once per process when no deployment key is configured.
_EPHEMERAL_JWT_KEY = secrets.token_urlsafe(48)
ALLOWED_ALGORITHMS = ("HS256",)


def active_signing_key() -> tuple[str, str]:
    key = settings.JWT_SECRET_KEY or settings.OPERATOR_SESSION_KEY or _EPHEMERAL_JWT_KEY
    return settings.JWT_KEY_ID, key


def key_for_kid(kid: str | None) -> str | None:
    active_kid, active_key = active_signing_key()
    if kid is None or kid == active_kid:
        return active_key
    candidate = settings.JWT_PREVIOUS_KEYS.get(kid)
    if isinstance(candidate, str) and len(candidate) >= 32:
        return candidate
    return None


def uses_ephemeral_key() -> bool:
    return not (settings.JWT_SECRET_KEY or settings.OPERATOR_SESSION_KEY)


def looks_like_jwt(token: str) -> bool:
    return isinstance(token, str) and token.count(".") == 2 and not token.startswith("ls1.")


def create_access_token(
    *,
    user_id: str,
    username: str,
    role: str,
    token_version: int = 1,
    ttl_seconds: int | None = None,
) -> tuple[str, int, str]:
    now = int(time.time())
    ttl = ttl_seconds if ttl_seconds is not None else settings.JWT_ACCESS_TTL_SECONDS
    jti = uuid.uuid4().hex
    kid, secret = active_signing_key()
    payload = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": user_id,
        "username": username,
        "role": role,
        "tv": token_version,
        "jti": jti,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "token_type": "access",
    }
    token = jwt.encode(payload, secret, algorithm="HS256", headers={"kid": kid})
    return token, ttl, jti


def decode_access_token(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError:
        raise OutcomeHTTPException(
            401, "Invalid access token", AUTHORIZATION_FAILED, headers={"WWW-Authenticate": "Bearer"}
        ) from None

    alg = header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise OutcomeHTTPException(
            401, "Invalid access token algorithm", AUTHORIZATION_FAILED, headers={"WWW-Authenticate": "Bearer"}
        )

    secret = key_for_kid(header.get("kid"))
    if not secret:
        raise OutcomeHTTPException(
            401, "Unknown signing key", AUTHORIZATION_FAILED, headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=list(ALLOWED_ALGORITHMS),
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={"require": ["iss", "aud", "sub", "jti", "iat", "nbf", "exp", "token_type"]},
        )
    except ExpiredSignatureError:
        raise OutcomeHTTPException(
            401, "Access token expired", "SESSION_EXPIRED", headers={"WWW-Authenticate": "Bearer"}
        ) from None
    except InvalidTokenError:
        raise OutcomeHTTPException(
            401, "Invalid access token", AUTHORIZATION_FAILED, headers={"WWW-Authenticate": "Bearer"}
        ) from None

    if payload.get("token_type") != "access" or not isinstance(payload.get("sub"), str):
        raise OutcomeHTTPException(
            401, "Invalid access token type", AUTHORIZATION_FAILED, headers={"WWW-Authenticate": "Bearer"}
        )
    return payload

