"""Administrative CLI for LARP SOC user and session management (run inside manager environment)."""
import asyncio
from datetime import datetime, timezone
import sys

import click
from sqlalchemy import select

from app.core.database import AsyncSessionLocal, async_engine
import app.models  # noqa: F401
from app.models.base import Base
from app.models.soc_auth import SocUser, SocUserAgentScope
from app.services.auth.auth_service import (
    create_soc_user,
    record_auth_audit,
    revoke_all_user_sessions,
)
from app.services.auth.password_service import hash_password, verify_password


def _parse_agents(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


async def _ensure_auth_tables() -> None:
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@click.group(help="LARP Manager administrative CLI.")
def main():
    pass


@main.group(help="Manage SOC Dashboard users and refresh sessions.")
def auth():
    pass


@auth.command("create-admin")
@click.option("--username", prompt=True, help="Admin username")
@click.option("--agents", default="", help="Optional comma-separated Agent IDs (empty = all agents)")
def create_admin(username: str, agents: str):
    """Interactively create a SOC administrator account."""
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            user = await create_soc_user(
                db,
                username=username,
                password=password,
                role="admin",
                agent_scopes=_parse_agents(agents),
            )
            click.echo(f"Created admin user '{user.username}' (id={user.id}).")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("create-user")
@click.option("--username", prompt=True, help="Username")
@click.option(
    "--role",
    type=click.Choice(["analyst", "operator", "admin"], case_sensitive=False),
    prompt=True,
    help="User role",
)
@click.option("--agents", default="", help="Comma-separated Agent IDs (required for operator)")
def create_user(username: str, role: str, agents: str):
    """Interactively create a SOC user (analyst, operator, or admin)."""
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            user = await create_soc_user(
                db,
                username=username,
                password=password,
                role=role.lower(),
                agent_scopes=_parse_agents(agents),
            )
            scopes = sorted(s.agent_id for s in user.agent_scopes)
            click.echo(f"Created {user.role} user '{user.username}' (id={user.id}, scopes={scopes}).")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("disable-user")
@click.argument("username")
def disable_user(username: str):
    """Disable a SOC user and revoke all active sessions."""

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            user = await db.scalar(select(SocUser).where(SocUser.username == username.strip()))
            if not user:
                raise ValueError(f"User '{username}' not found")
            now = datetime.now(timezone.utc)
            user.is_active = False
            user.updated_at = now
            revoked = await revoke_all_user_sessions(db, user_id=user.id, event="user_disabled")
            click.echo(f"Disabled user '{user.username}' and revoked {revoked} session(s).")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("change-password")
@click.argument("username")
def change_password(username: str):
    """Change a user's password after verifying the current password."""
    current = click.prompt("Current password", hide_input=True)
    new_pw = click.prompt("New password", hide_input=True, confirmation_prompt=True)

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            user = await db.scalar(select(SocUser).where(SocUser.username == username.strip()))
            if not user:
                raise ValueError(f"User '{username}' not found")
            if not verify_password(user.password_hash, current):
                raise ValueError("Current password is incorrect")
            now = datetime.now(timezone.utc)
            user.password_hash = hash_password(new_pw)
            user.password_changed_at = now
            user.updated_at = now
            user.failed_login_count = 0
            user.locked_until = None
            revoked = await revoke_all_user_sessions(db, user_id=user.id, event="password_changed")
            click.echo(f"Updated password for '{user.username}' and revoked {revoked} session(s).")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("reset-password")
@click.argument("username")
def reset_password(username: str):
    """Administratively reset a user's password, clear lockouts, and revoke active sessions."""
    new_pw = click.prompt("New password", hide_input=True, confirmation_prompt=True)

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            user = await db.scalar(select(SocUser).where(SocUser.username == username.strip()))
            if not user:
                raise ValueError(f"User '{username}' not found")
            now = datetime.now(timezone.utc)
            user.password_hash = hash_password(new_pw)
            user.password_changed_at = now
            user.updated_at = now
            user.failed_login_count = 0
            user.locked_until = None
            revoked = await revoke_all_user_sessions(db, user_id=user.id, event="password_reset")
            click.echo(f"Reset password for '{user.username}' and revoked {revoked} session(s).")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("revoke-sessions")
@click.argument("username")
def revoke_sessions(username: str):
    """Revoke all refresh sessions and invalidate existing JWTs for USERNAME."""

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            user = await db.scalar(select(SocUser).where(SocUser.username == username.strip()))
            if not user:
                raise ValueError(f"User '{username}' not found")
            revoked = await revoke_all_user_sessions(db, user_id=user.id, event="sessions_revoked")
            click.echo(f"Revoked {revoked} session(s) for '{user.username}'.")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("set-scopes")
@click.argument("username")
@click.option("--agents", required=True, help="Comma-separated Agent IDs (empty string clears scopes)")
def set_scopes(username: str, agents: str):
    """Replace Agent scopes for USERNAME."""

    async def _run():
        await _ensure_auth_tables()
        scopes = sorted(set(_parse_agents(agents)))
        async with AsyncSessionLocal() as db:
            user = await db.scalar(select(SocUser).where(SocUser.username == username.strip()))
            if not user:
                raise ValueError(f"User '{username}' not found")
            if user.role == "operator" and not scopes:
                raise ValueError("Operator role requires at least one Agent scope")
            user.agent_scopes.clear()
            await db.flush()
            for agent_id in scopes:
                user.agent_scopes.append(SocUserAgentScope(user_id=user.id, agent_id=agent_id))
            await record_auth_audit(
                db, event="scopes_updated", user_id=user.id, username=user.username, detail={"agent_scopes": scopes}
            )
            await db.commit()
            click.echo(f"Updated scopes for '{user.username}' -> {scopes}")

    try:
        asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


@auth.command("list-users")
def list_users():
    """List SOC users without exposing credential hashes."""

    async def _run():
        await _ensure_auth_tables()
        async with AsyncSessionLocal() as db:
            users = (await db.scalars(select(SocUser).order_by(SocUser.username))).all()
            if not users:
                click.echo("No SOC users found.")
                return
            for u in users:
                scopes = ",".join(sorted(s.agent_id for s in (u.agent_scopes or []))) or "*"
                status = "active" if u.is_active else "disabled"
                click.echo(f"{u.username}\trole={u.role}\tstatus={status}\tfailed={u.failed_login_count}\tscopes={scopes}")

    asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())

