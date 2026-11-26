"""SOC Dashboard username/password login, JWT issuance, HttpOnly refresh cookie rotation, and logout."""
from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_db
from app.core.network_security import authenticate_operator_request
from app.core.response_outcome import AUTHORIZATION_FAILED, OutcomeHTTPException
from app.services.auth.auth_service import (
    authenticate_user,
    refresh_auth_session,
    revoke_all_user_sessions,
    revoke_refresh_cookie_session,
    user_summary,
)

router = APIRouter(prefix="/auth", tags=["SOC Authentication"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded:
        return forwarded[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _is_secure_request(request: Request) -> bool:
    if settings.REFRESH_COOKIE_SECURE is not None:
        return settings.REFRESH_COOKIE_SECURE
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return proto == "https" or request.url.scheme == "https"


def _set_refresh_cookie(response: Response, request: Request, raw_refresh: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw_refresh,
        max_age=settings.REFRESH_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=_is_secure_request(request),
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        domain=settings.REFRESH_COOKIE_DOMAIN,
        path="/api/v1/auth",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _clear_refresh_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
        domain=settings.REFRESH_COOKIE_DOMAIN,
        secure=_is_secure_request(request),
        httponly=True,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _enforce_csrf(request: Request) -> None:
    csrf = request.headers.get("x-larp-csrf") or request.headers.get("x-requested-with")
    if csrf not in {"1", "XMLHttpRequest"}:
        raise OutcomeHTTPException(403, "CSRF header required for session mutation", AUTHORIZATION_FAILED)
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host")
        same_origin = {f"http://{host}", f"https://{host}"} if host else set()
        if origin not in set(settings.CORS_ALLOWED_ORIGINS) | same_origin:
            raise OutcomeHTTPException(403, "Origin not allowed", AUTHORIZATION_FAILED)


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    access_token, expires_in, raw_refresh, user = await authenticate_user(
        db,
        username=body.username,
        password=body.password,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _set_refresh_cookie(response, request, raw_refresh)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_summary(user),
    }


@router.post("/refresh")
async def refresh(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    _enforce_csrf(request)
    raw_cookie = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    try:
        access_token, expires_in, next_refresh, user = await refresh_auth_session(
            db,
            raw_refresh_token=raw_cookie,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except OutcomeHTTPException:
        _clear_refresh_cookie(response, request)
        raise
    _set_refresh_cookie(response, request, next_refresh)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_summary(user),
    }


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    _enforce_csrf(request)
    raw_cookie = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    await revoke_refresh_cookie_session(db, raw_refresh_token=raw_cookie, ip_address=_client_ip(request))
    _clear_refresh_cookie(response, request)
    return {"status": "logged_out"}


@router.post("/logout-all")
async def logout_all(
    request: Request,
    response: Response,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    _enforce_csrf(request)
    _, ctx = await authenticate_operator_request(authorization, db)
    if not ctx.user_id:
        raise OutcomeHTTPException(401, "Authenticated SOC user account required", AUTHORIZATION_FAILED)
    revoked = await revoke_all_user_sessions(db, user_id=ctx.user_id, ip_address=_client_ip(request))
    _clear_refresh_cookie(response, request)
    return {"status": "logged_out_all", "revoked_sessions": revoked}


@router.get("/me")
async def me(
    response: Response,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    identity, ctx = await authenticate_operator_request(authorization, db)
    response.headers["Cache-Control"] = "no-store"
    return {
        "id": ctx.user_id,
        "username": ctx.username or identity,
        "role": ctx.role,
        "agent_scopes": sorted(ctx.agents),
        "is_active": True,
        "auth_method": ctx.auth_method,
    }

