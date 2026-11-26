"""Authentication service: login rate limits, lockout, Argon2id verification, JWT + refresh rotation."""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import threading
import time
import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.response_outcome import AUTHORIZATION_FAILED, OutcomeHTTPException
from app.models.soc_auth import SocAuthAuditLog, SocRefreshSession, SocUser, SocUserAgentScope
from app.services.auth.jwt_service import create_access_token
from app.services.auth.password_service import dummy_verify, hash_password, needs_rehash, verify_password

VALID_ROLES = frozenset({"analyst", "operator", "admin"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class LoginRateLimiter:
    """Sliding-window rate limiter keyed by client IP and username."""

    def __init__(self):
        self._lock = threading.Lock()
        self._attempts: dict[str, deque[float]] = defaultdict(deque)

    def reset(self) -> None:
        with self._lock:
            self._attempts.clear()

    def check_and_record(self, ip: str, username: str) -> bool:
        window = settings.AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS
        limit = settings.AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS
        now = time.monotonic()
        keys = (f"ip:{ip or 'unknown'}", f"user:{ip or 'unknown'}:{username.lower()}")
        with self._lock:
            for key in keys:
                bucket = self._attempts[key]
                while bucket and now - bucket[0] > window:
                    bucket.popleft()
                if len(bucket) >= limit:
                    return False
            for key in keys:
                self._attempts[key].append(now)
            return True


login_rate_limiter = LoginRateLimiter()


async def record_auth_audit(
    db: AsyncSession,
    *,
    event: str,
    user_id: str | None = None,
    username: str | None = None,
    ip_address: str | None = None,
    detail: dict | None = None,
) -> None:
    db.add(
        SocAuthAuditLog(
            id=uuid.uuid4().hex,
            user_id=user_id,
            username=username,
            event=event,
            ip_address=ip_address,
            detail=detail or {},
            created_at=_utcnow(),
        )
    )
    await db.flush()


def user_summary(user: SocUser) -> dict:
    scopes = sorted(scope.agent_id for scope in (user.agent_scopes or []))
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "agent_scopes": scopes,
        "is_active": bool(user.is_active),
    }


async def issue_tokens_for_user(
    db: AsyncSession,
    user: SocUser,
    *,
    family_id: str | None = None,
    device_metadata: dict | None = None,
) -> tuple[str, int, str, SocRefreshSession]:
    now = _utcnow()
    raw_refresh = secrets.token_urlsafe(48)
    refresh_row = SocRefreshSession(
        id=uuid.uuid4().hex,
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(raw_refresh),
        token_family_id=family_id or uuid.uuid4().hex,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_TTL_SECONDS),
        last_used_at=now,
        device_metadata=device_metadata or {},
    )
    db.add(refresh_row)
    await db.flush()
    access_token, expires_in, _ = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        token_version=user.token_version,
    )
    return access_token, expires_in, raw_refresh, refresh_row


async def authenticate_user(
    db: AsyncSession,
    *,
    username: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, int, str, SocUser]:
    clean_username = (username or "").strip()
    if not login_rate_limiter.check_and_record(ip_address or "unknown", clean_username):
        await record_auth_audit(
            db, event="login_rate_limited", username=clean_username or None, ip_address=ip_address
        )
        await db.commit()
        raise OutcomeHTTPException(429, "Too many login attempts. Please try again later.", AUTHORIZATION_FAILED)

    user = await db.scalar(select(SocUser).where(SocUser.username == clean_username))
    now = _utcnow()
    if user is None:
        dummy_verify(password)
        await record_auth_audit(
            db, event="login_failed", username=clean_username or None, ip_address=ip_address,
            detail={"reason": "invalid_credentials"},
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Invalid username or password", AUTHORIZATION_FAILED)

    locked_until = _as_utc(user.locked_until)
    if locked_until and locked_until > now:
        await record_auth_audit(
            db, event="login_locked", user_id=user.id, username=user.username, ip_address=ip_address
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Too many failed login attempts. Please try again later.", AUTHORIZATION_FAILED)

    password_ok = verify_password(user.password_hash, password)
    if not password_ok or not user.is_active:
        if not password_ok:
            user.failed_login_count = int(user.failed_login_count or 0) + 1
            if user.failed_login_count >= settings.AUTH_LOCKOUT_THRESHOLD:
                user.locked_until = now + timedelta(seconds=settings.AUTH_LOCKOUT_SECONDS)
        user.updated_at = now
        await record_auth_audit(
            db,
            event="login_failed",
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            detail={"reason": "disabled" if password_ok and not user.is_active else "invalid_credentials"},
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Invalid username or password", AUTHORIZATION_FAILED)

    user.failed_login_count = 0
    user.locked_until = None
    user.updated_at = now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    meta = {"ip": ip_address or "", "user_agent": (user_agent or "")[:200]}
    access_token, expires_in, raw_refresh, session_row = await issue_tokens_for_user(
        db, user, device_metadata=meta
    )
    await record_auth_audit(
        db,
        event="login_success",
        user_id=user.id,
        username=user.username,
        ip_address=ip_address,
        detail={"session_id": session_row.id, "family_id": session_row.token_family_id},
    )
    await db.commit()
    return access_token, expires_in, raw_refresh, user


async def refresh_auth_session(
    db: AsyncSession,
    *,
    raw_refresh_token: str | None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, int, str, SocUser]:
    if not raw_refresh_token or len(raw_refresh_token) < 20 or len(raw_refresh_token) > 512:
        raise OutcomeHTTPException(401, "Refresh session required", "SESSION_EXPIRED")

    token_hash = hash_refresh_token(raw_refresh_token)
    row = await db.scalar(select(SocRefreshSession).where(SocRefreshSession.refresh_token_hash == token_hash))
    if row is None:
        raise OutcomeHTTPException(401, "Invalid refresh session", "SESSION_EXPIRED")

    now = _utcnow()
    if row.revoked_at is not None or row.replaced_by_id is not None:
        await db.execute(
            update(SocRefreshSession)
            .where(SocRefreshSession.token_family_id == row.token_family_id, SocRefreshSession.revoked_at.is_(None))
            .values(revoked_at=now, reuse_detected_at=now)
        )
        await db.execute(
            update(SocRefreshSession).where(SocRefreshSession.id == row.id).values(reuse_detected_at=now)
        )
        await record_auth_audit(
            db,
            event="refresh_reuse_detected",
            user_id=row.user_id,
            ip_address=ip_address,
            detail={"session_id": row.id, "family_id": row.token_family_id},
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Refresh session revoked due to reuse", "SESSION_EXPIRED")

    expires_at = _as_utc(row.expires_at)
    if expires_at is None or expires_at <= now:
        await db.execute(
            update(SocRefreshSession)
            .where(SocRefreshSession.id == row.id, SocRefreshSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Refresh session expired", "SESSION_EXPIRED")

    user = await db.get(SocUser, row.user_id)
    locked_until = _as_utc(user.locked_until) if user else None
    if not user or not user.is_active or (locked_until and locked_until > now):
        await db.execute(
            update(SocRefreshSession)
            .where(SocRefreshSession.token_family_id == row.token_family_id, SocRefreshSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Account inactive or locked", AUTHORIZATION_FAILED)

    new_session_id = uuid.uuid4().hex
    claim = await db.execute(
        update(SocRefreshSession)
        .where(
            SocRefreshSession.id == row.id,
            SocRefreshSession.revoked_at.is_(None),
            SocRefreshSession.replaced_by_id.is_(None),
        )
        .values(revoked_at=now, last_used_at=now, replaced_by_id=new_session_id)
    )
    if claim.rowcount != 1:
        await db.execute(
            update(SocRefreshSession)
            .where(SocRefreshSession.token_family_id == row.token_family_id, SocRefreshSession.revoked_at.is_(None))
            .values(revoked_at=now, reuse_detected_at=now)
        )
        await record_auth_audit(
            db,
            event="refresh_reuse_detected",
            user_id=row.user_id,
            ip_address=ip_address,
            detail={"session_id": row.id, "family_id": row.token_family_id, "concurrent": True},
        )
        await db.commit()
        raise OutcomeHTTPException(401, "Refresh session rotated concurrently", "SESSION_EXPIRED")

    raw_next = secrets.token_urlsafe(48)
    next_row = SocRefreshSession(
        id=new_session_id,
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(raw_next),
        token_family_id=row.token_family_id,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.REFRESH_TOKEN_TTL_SECONDS),
        last_used_at=now,
        device_metadata={"ip": ip_address or "", "user_agent": (user_agent or "")[:200]},
    )
    db.add(next_row)
    access_token, expires_in, _ = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        token_version=user.token_version,
    )
    await record_auth_audit(
        db,
        event="refresh_rotated",
        user_id=user.id,
        username=user.username,
        ip_address=ip_address,
        detail={"old_session_id": row.id, "new_session_id": new_session_id, "family_id": row.token_family_id},
    )
    await db.commit()
    return access_token, expires_in, raw_next, user


async def revoke_refresh_cookie_session(
    db: AsyncSession, *, raw_refresh_token: str | None, ip_address: str | None = None
) -> bool:
    if not raw_refresh_token:
        return False
    token_hash = hash_refresh_token(raw_refresh_token)
    row = await db.scalar(select(SocRefreshSession).where(SocRefreshSession.refresh_token_hash == token_hash))
    if row is None:
        return False
    now = _utcnow()
    if row.revoked_at is None:
        await db.execute(
            update(SocRefreshSession)
            .where(SocRefreshSession.id == row.id, SocRefreshSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
    await record_auth_audit(
        db,
        event="logout",
        user_id=row.user_id,
        ip_address=ip_address,
        detail={"session_id": row.id, "family_id": row.token_family_id},
    )
    await db.commit()
    return True


async def revoke_all_user_sessions(
    db: AsyncSession, *, user_id: str, ip_address: str | None = None, event: str = "logout_all"
) -> int:
    now = _utcnow()
    res = await db.execute(
        update(SocRefreshSession)
        .where(SocRefreshSession.user_id == user_id, SocRefreshSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await db.execute(
        update(SocUser)
        .where(SocUser.id == user_id)
        .values(token_version=SocUser.token_version + 1, updated_at=now)
    )
    await record_auth_audit(
        db, event=event, user_id=user_id, ip_address=ip_address, detail={"revoked_sessions": res.rowcount or 0}
    )
    await db.commit()
    return res.rowcount or 0


async def create_soc_user(
    db: AsyncSession,
    *,
    username: str,
    password: str,
    role: str,
    agent_scopes: set[str] | list[str] | None = None,
) -> SocUser:
    clean_username = (username or "").strip()
    if not clean_username or len(clean_username) > 64:
        raise ValueError("Username must be between 1 and 64 characters")
    if role not in VALID_ROLES:
        raise ValueError(f"Role must be one of {sorted(VALID_ROLES)}")
    scopes = sorted({s.strip() for s in (agent_scopes or []) if isinstance(s, str) and s.strip()})
    if role == "operator" and not scopes:
        raise ValueError("Operator role requires at least one explicit Agent scope")
    existing = await db.scalar(select(SocUser.id).where(SocUser.username == clean_username))
    if existing:
        raise ValueError(f"Username '{clean_username}' already exists")
    now = _utcnow()
    user = SocUser(
        id=uuid.uuid4().hex,
        username=clean_username,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        failed_login_count=0,
        token_version=1,
        created_at=now,
        updated_at=now,
        password_changed_at=now,
    )
    db.add(user)
    await db.flush()
    for agent_id in scopes:
        db.add(SocUserAgentScope(user_id=user.id, agent_id=agent_id))
    await record_auth_audit(
        db,
        event="user_created",
        user_id=user.id,
        username=user.username,
        detail={"role": role, "agent_scopes": scopes},
    )
    await db.commit()
    await db.refresh(user)
    return user

