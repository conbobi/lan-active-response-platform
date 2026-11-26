"""Phase 11 & 12: Security and E2E integration tests for username/password + Argon2id + JWT + refresh rotation."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from click.testing import CliRunner
from fastapi.testclient import TestClient
import httpx
import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.websockets import WebSocketDisconnect

from app import cli as larp_cli
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_session
from app.main import app
from app.models.agent import Agent, AgentStatus
from app.models.base import Base
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.soc_auth import SocAuthAuditLog, SocRefreshSession, SocUser
from app.models.web_access_log import WebAccessLog
from app.services.auth.auth_service import create_soc_user, login_rate_limiter
from app.services.auth.jwt_service import create_access_token
from app.services.response import assist_policy
from app.websocket import agent_ws
from test_network_module import AGENT, AGENT_TOKEN, OTHER, digest, heartbeat, snapshot

CSRF = {"X-LARP-CSRF": "1"}
JWT_KEY = "unit-test-jwt-signing-key-32-chars-minimum!!"


@pytest.fixture
async def jwt_lab(tmp_path, monkeypatch):
    login_rate_limiter.reset()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'jwt_auth.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as db:
        db.add(Agent(id=AGENT, hostname=AGENT, ip_address="192.0.2.10", mac_address="00:00:00:00:00:01", status=AgentStatus.ACTIVE))
        db.add(Agent(id=OTHER, hostname=OTHER, ip_address="192.0.2.11", mac_address="00:00:00:00:00:02", status=AgentStatus.ACTIVE))
        db.add(ProcessInfo(
            id="proc_jwt_1", agent_id=AGENT, pid=4321, parent_pid=1, name="evil",
            exe_path="/tmp/evil", process_start_time=1000.0, cmdline="/tmp/evil", is_suspicious=True,
        ))
        db.add(WebAccessLog(
            id="wlog_jwt", agent_id=AGENT, method="POST", path="/login", status_code=200,
            src_ip="192.0.2.50", user_agent="sqlmap/1.9", timestamp=datetime.now(timezone.utc),
        ))
        db.add(Incident(
            id="inc_jwt", title="HTTP Incident", risk_score=65, agent_id=AGENT,
            detection_evidence={"behavior": {
                "agent_id": AGENT, "source": "web_access_logs", "evidence_type": "http",
                "evidence_id": "grp_jwt", "source_event_ids": ["wlog_jwt"],
            }},
        ))
        await db.commit()
        await create_soc_user(db, username="soc-admin", password="AdminPassword!123", role="admin")
        await create_soc_user(
            db, username="soc-operator", password="OperatorPass!123", role="operator", agent_scopes=[AGENT]
        )
        await create_soc_user(
            db, username="soc-analyst", password="AnalystPass!123", role="analyst", agent_scopes=[AGENT]
        )

    async def dependency():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def model(*args, **kwargs):
        return {"answer": json.dumps({"action_type": "collect_additional_evidence", "evidence_ids": ["grp_jwt", "wlog_jwt"]})}

    monkeypatch.setattr(assist_policy.ai_client, "generate", model)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", JWT_KEY)
    monkeypatch.setattr(settings, "JWT_KEY_ID", "v1")
    monkeypatch.setattr(settings, "JWT_PREVIOUS_KEYS", {})
    monkeypatch.setattr(settings, "NETWORK_AGENT_TOKENS", {AGENT: digest(AGENT_TOKEN)})
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", {})
    monkeypatch.setattr(settings, "NETWORK_LEGACY_ADMIN_TOKEN", None)
    monkeypatch.setattr(settings, "ALLOW_LEGACY_OPERATOR_TOKENS", False)
    monkeypatch.setattr(agent_ws, "AsyncSessionLocal", factory)
    app.dependency_overrides[get_db] = dependency
    app.dependency_overrides[get_session] = dependency
    try:
        yield TestClient(app), factory
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_session, None)
        await engine.dispose()


def _login(client: TestClient, username: str, password: str):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_login_argon2id_wrong_password_lockout_and_audit(jwt_lab):
    client, factory = jwt_lab
    ok = _login(client, "soc-admin", "AdminPassword!123")
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900
    assert body["user"]["username"] == "soc-admin"
    assert body["user"]["role"] == "admin"
    assert "refresh_token" not in body
    assert ok.headers["cache-control"] == "no-store"
    cookie_header = ok.headers.get("set-cookie", "")
    assert "larp_refresh_token=" in cookie_header and "HttpOnly" in cookie_header

    async with factory() as db:
        user = await db.scalar(select(SocUser).where(SocUser.username == "soc-admin"))
        assert user.password_hash.startswith("$argon2id$")
        assert "AdminPassword!123" not in user.password_hash
        # Refresh token is hashed in DB, never plaintext.
        sess = await db.scalar(select(SocRefreshSession).where(SocRefreshSession.user_id == user.id))
        assert sess is not None and len(sess.refresh_token_hash) == 64
        assert sess.refresh_token_hash != ok.cookies["larp_refresh_token"]

    # Wrong password returns generic 401 and locks after threshold.
    for _ in range(settings.AUTH_LOCKOUT_THRESHOLD):
        bad = _login(client, "soc-operator", "WrongPass!999")
        assert bad.status_code == 401
        assert bad.json()["detail"] == "Invalid username or password"

    locked = _login(client, "soc-operator", "OperatorPass!123")
    assert locked.status_code == 401
    assert "too many failed login attempts" in locked.json()["detail"].lower()

    # Rate limit after burst.
    for _ in range(settings.AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        _login(client, "unknown-user", "WrongPass!999")
    throttled = _login(client, "unknown-user", "WrongPass!999")
    assert throttled.status_code == 429

    async with factory() as db:
        events = set(await db.scalars(select(SocAuthAuditLog.event)))
        assert {"login_success", "login_failed", "login_locked", "login_rate_limited"} <= events


@pytest.mark.asyncio
async def test_jwt_validation_edge_cases_and_disabled_user(jwt_lab, monkeypatch):
    client, factory = jwt_lab
    ok = _login(client, "soc-admin", "AdminPassword!123")
    token = ok.json()["access_token"]
    assert client.get("/api/v1/auth/me", headers=_bearer(token)).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401

    # Invalid signature
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}.{'A' * len(parts[2])}"
    assert client.get("/api/v1/auth/me", headers=_bearer(tampered)).status_code == 401

    # Wrong issuer / wrong audience / wrong token_type / alg=none
    now = int(datetime.now(timezone.utc).timestamp())
    base_claims = {"iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": "x", "jti": "j", "iat": now, "nbf": now, "exp": now + 60, "token_type": "access"}
    wrong_iss = jwt.encode({**base_claims, "iss": "evil"}, JWT_KEY, algorithm="HS256")
    wrong_aud = jwt.encode({**base_claims, "aud": "other"}, JWT_KEY, algorithm="HS256")
    wrong_type = jwt.encode({**base_claims, "token_type": "refresh"}, JWT_KEY, algorithm="HS256")
    alg_none = jwt.encode(base_claims, "", algorithm="none")
    for bad_jwt in (wrong_iss, wrong_aud, wrong_type, alg_none):
        assert client.get("/api/v1/auth/me", headers=_bearer(bad_jwt)).status_code == 401

    # Expired JWT
    expired = jwt.encode({**base_claims, "exp": now - 10}, JWT_KEY, algorithm="HS256")
    exp_res = client.get("/api/v1/auth/me", headers=_bearer(expired))
    assert exp_res.status_code == 401 and exp_res.json()["outcome_code"] == "SESSION_EXPIRED"

    # Key rotation: v1 token still verifies under v2 when JWT_PREVIOUS_KEYS includes v1.
    from app.services.auth.jwt_service import uses_ephemeral_key
    assert not uses_ephemeral_key()
    monkeypatch.setattr(settings, "JWT_KEY_ID", "v2")
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "rotated-new-signing-key-32-chars-min!!")
    monkeypatch.setattr(settings, "JWT_PREVIOUS_KEYS", {"v1": JWT_KEY})
    assert client.get("/api/v1/auth/me", headers=_bearer(token)).status_code == 200

    # Disabled user immediately fails even with an unexpired JWT.
    async with factory.begin() as db:
        user = await db.scalar(select(SocUser).where(SocUser.username == "soc-admin"))
        user.is_active = False
    assert client.get("/api/v1/auth/me", headers=_bearer(token)).status_code == 401
    assert _login(client, "soc-admin", "AdminPassword!123").status_code == 401


@pytest.mark.asyncio
async def test_refresh_rotation_reuse_detection_concurrent_and_logout(jwt_lab):
    client, factory = jwt_lab
    login_res = _login(client, "soc-admin", "AdminPassword!123")
    rt1 = login_res.cookies[settings.REFRESH_COOKIE_NAME]

    # CSRF protection blocks cookie refresh without X-LARP-CSRF header or disallowed Origin.
    assert client.post("/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: rt1}).status_code == 403
    assert client.post(
        "/api/v1/auth/refresh",
        headers={**CSRF, "Origin": "https://evil.example"},
        cookies={settings.REFRESH_COOKIE_NAME: rt1},
    ).status_code == 403

    # Valid refresh rotates rt1 -> rt2.
    r1 = client.post("/api/v1/auth/refresh", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt1})
    assert r1.status_code == 200
    rt2 = r1.cookies[settings.REFRESH_COOKIE_NAME]
    assert rt2 != rt1

    # Replaying rt1 detects reuse and revokes the entire token family (including rt2!).
    replay = client.post("/api/v1/auth/refresh", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt1})
    assert replay.status_code == 401
    rt2_after_reuse = client.post("/api/v1/auth/refresh", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt2})
    assert rt2_after_reuse.status_code == 401

    async with factory() as db:
        reuse_audit = await db.scalar(select(SocAuthAuditLog).where(SocAuthAuditLog.event == "refresh_reuse_detected"))
        assert reuse_audit is not None

    # Concurrent refresh race: at most 1 request may succeed.
    login_res2 = _login(client, "soc-operator", "OperatorPass!123")
    rt_concurrent = login_res2.cookies[settings.REFRESH_COOKIE_NAME]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
        cookies={settings.REFRESH_COOKIE_NAME: rt_concurrent},
    ) as async_api:
        r_a, r_b = await asyncio.gather(
            async_api.post("/api/v1/auth/refresh", headers=CSRF),
            async_api.post("/api/v1/auth/refresh", headers=CSRF),
        )
    statuses = sorted([r_a.status_code, r_b.status_code])
    assert statuses in ([200, 401], [401, 401]), statuses

    # Logout revokes session and blocks subsequent refresh.
    login_res3 = _login(client, "soc-analyst", "AnalystPass!123")
    rt_logout = login_res3.cookies[settings.REFRESH_COOKIE_NAME]
    out = client.post("/api/v1/auth/logout", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt_logout})
    assert out.status_code == 200
    assert client.post("/api/v1/auth/refresh", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt_logout}).status_code == 401


def test_cors_and_trust_boundary_isolation(jwt_lab):
    client, _ = jwt_lab
    # CORS allows configured origin with credentials, rejects untrusted origin (no wildcard).
    allowed = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert allowed.headers.get("access-control-allow-credentials") == "true"

    disallowed = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://attacker.invalid", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in disallowed.headers

    # Agent token cannot access SOC endpoints or legacy session endpoint when disabled.
    assert client.get("/api/v1/auth/me", headers=_bearer(AGENT_TOKEN)).status_code == 401
    assert client.post("/api/v1/auth/session", headers=_bearer(AGENT_TOKEN)).status_code == 401
    assert client.get("/api/v1/incidents/inc_jwt/response-proposals", headers=_bearer(AGENT_TOKEN)).status_code == 401

    # User JWT cannot authenticate as an Agent over WebSocket or probe endpoint.
    user_jwt = _login(client, "soc-admin", "AdminPassword!123").json()["access_token"]
    assert client.get(f"/api/v1/network/agents/{AGENT}/probe", headers={"x-larp-agent-token": user_jwt}).status_code == 401
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": user_jwt}):
            pass


def test_rbac_scopes_legacy_routes_and_phase12_e2e(jwt_lab, monkeypatch):
    client, _ = jwt_lab
    analyst_jwt = _login(client, "soc-analyst", "AnalystPass!123").json()["access_token"]
    operator_jwt = _login(client, "soc-operator", "OperatorPass!123").json()["access_token"]
    admin_jwt = _login(client, "soc-admin", "AdminPassword!123").json()["access_token"]

    # Analyst can propose, cannot approve/execute or hit admin routes.
    prop_res = client.post("/api/v1/incidents/inc_jwt/response-proposals", headers=_bearer(analyst_jwt), json={})
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]
    action_url = f"/api/v1/response-actions/{action_id}"
    assert client.post(f"{action_url}/approve", headers=_bearer(analyst_jwt), json={}).status_code == 403
    assert client.post("/api/v1/policies", headers=_bearer(analyst_jwt), json={}).status_code == 403
    assert client.post("/api/v1/policies", headers=_bearer(operator_jwt), json={}).status_code == 403

    # Operator scoped to AGENT cannot read OTHER agent.
    assert client.get(f"/api/v1/network/agents/{OTHER}/overview", headers=_bearer(operator_jwt)).status_code == 403

    # Legacy mutating APIs enforce JWT + role + scope.
    assert client.post("/api/v1/actions", json={"agent_id": AGENT, "action_type": "isolate"}).status_code == 401
    assert client.post("/api/v1/actions", headers=_bearer(operator_jwt), json={"agent_id": AGENT, "action_type": "isolate"}).status_code == 403
    legacy_act = client.post(
        "/api/v1/actions",
        headers=_bearer(admin_jwt),
        json={"agent_id": AGENT, "action_type": "isolate", "action_params": {"confirmed": True}},
    )
    assert legacy_act.status_code == 201
    kill_res = client.post(
        f"/api/v1/process/{AGENT}/process/4321/kill",
        headers=_bearer(admin_jwt),
        json={"process_start_time": 1000.0, "exe_path": "/tmp/evil", "confirmed": True},
    )
    assert kill_res.status_code == 200

    # Phase 12 E2E (steps 5-15): GET /me, incident, approve with operator JWT, execute via mock Agent, audit actor, expire JWT, refresh, retry, logout.
    me_res = client.get("/api/v1/auth/me", headers=_bearer(operator_jwt))
    assert me_res.status_code == 200 and me_res.json()["username"] == "soc-operator"
    assert client.get("/api/v1/incidents/inc_jwt").status_code == 200

    assert client.post(f"{action_url}/approve", headers=_bearer(operator_jwt), json={}).json()["status"] == "approved"
    with client.websocket_connect(f"/ws/agent?agent_id={AGENT}", headers={"x-larp-agent-token": AGENT_TOKEN}) as ws:
        heartbeat(ws)
        exec_res = client.post(f"{action_url}/execute", headers=_bearer(operator_jwt), json={})
        assert exec_res.status_code == 200 and exec_res.json()["status"] == "dispatched"
        command = heartbeat(ws)["network_command"]
        frame = snapshot(command_id=command["command_id"], status="ok")
        ws.send_json({"type": "NETWORK_SNAPSHOT", "payload": frame})
        ws.send_json({"type": "NETWORK_ACK", "payload": {
            "agent_id": AGENT, "schema_version": 1, "command_id": command["command_id"],
            "snapshot_id": frame["snapshot_id"], "timestamp": datetime.now(timezone.utc).isoformat(), "status": "success",
        }})
        heartbeat(ws)

    detail = client.get(action_url, headers=_bearer(operator_jwt)).json()
    assert detail["status"] == "succeeded"
    assert detail["audit"][2]["actor"] == "soc-operator"
    assert detail["audit"][3]["actor"] == "soc-operator"

    # Simulate JWT expiry -> 401 -> refresh -> retry succeeds -> logout -> cannot refresh.
    expired_jwt, _, _ = create_access_token(user_id="x", username="soc-operator", role="operator", ttl_seconds=-5)
    assert client.get("/api/v1/auth/me", headers=_bearer(expired_jwt)).status_code == 401

    login_fresh = _login(client, "soc-operator", "OperatorPass!123")
    rt_fresh = login_fresh.cookies[settings.REFRESH_COOKIE_NAME]
    refreshed = client.post("/api/v1/auth/refresh", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt_fresh})
    assert refreshed.status_code == 200
    rt_rotated = refreshed.cookies[settings.REFRESH_COOKIE_NAME]
    assert client.get("/api/v1/auth/me", headers=_bearer(refreshed.json()["access_token"])).status_code == 200

    assert client.post("/api/v1/auth/logout", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt_rotated}).status_code == 200
    assert client.post("/api/v1/auth/refresh", headers=CSRF, cookies={settings.REFRESH_COOKIE_NAME: rt_rotated}).status_code == 401


def test_cli_admin_bootstrap_password_reset_and_alembic_migration(tmp_path, monkeypatch):
    db_file = tmp_path / "cli_alembic.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")

    async def _init():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init())
    factory = async_sessionmaker(engine, expire_on_commit=False)

    monkeypatch.setattr(larp_cli, "async_engine", engine)
    monkeypatch.setattr(larp_cli, "AsyncSessionLocal", factory)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", JWT_KEY)
    monkeypatch.setattr(settings, "ALLOW_LEGACY_OPERATOR_TOKENS", False)

    runner = CliRunner()
    res_admin = runner.invoke(
        larp_cli.main,
        ["auth", "create-admin", "--username", "cli-admin"],
        input="CliStrongPass!1\nCliStrongPass!1\n",
    )
    assert res_admin.exit_code == 0, res_admin.output
    assert "CliStrongPass!1" not in res_admin.output

    # Duplicate username rejected.
    dup = runner.invoke(
        larp_cli.main,
        ["auth", "create-admin", "--username", "cli-admin"],
        input="CliStrongPass!1\nCliStrongPass!1\n",
    )
    assert dup.exit_code != 0

    # Reset password revokes existing sessions and invalidates old JWT.
    async def _get_old_jwt():
        async with factory() as db:
            user = await db.scalar(select(SocUser).where(SocUser.username == "cli-admin"))
            return create_access_token(
                user_id=user.id, username=user.username, role=user.role, token_version=user.token_version
            )[0]

    old_jwt = asyncio.run(_get_old_jwt())

    reset_res = runner.invoke(
        larp_cli.main,
        ["auth", "reset-password", "cli-admin"],
        input="NewCliPass!999\nNewCliPass!999\n",
    )
    assert reset_res.exit_code == 0, reset_res.output

    # Old JWT fails token_version check after password reset.
    async def dep():
        async with factory() as s:
            yield s

    app.dependency_overrides[get_db] = dep
    app.dependency_overrides[get_session] = dep
    try:
        client = TestClient(app)
        assert client.get("/api/v1/auth/me", headers=_bearer(old_jwt)).status_code == 401
        assert _login(client, "cli-admin", "CliStrongPass!1").status_code == 401
        assert _login(client, "cli-admin", "NewCliPass!999").status_code == 200
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_session, None)

    asyncio.run(engine.dispose())

    # Verify Alembic upgrade/downgrade on a clean SQLite database.
    import importlib.util
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    mig_path = Path(__file__).resolve().parents[2] / "alembic/versions/c8d9e0f1a2b3_add_soc_users_and_refresh_sessions.py"
    spec = importlib.util.spec_from_file_location("auth_mig", mig_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    mig_engine = sa.create_engine(f"sqlite:///{tmp_path / 'mig_test.db'}")
    with mig_engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
            insp = sa.inspect(conn)
            for tbl in ("soc_users", "soc_user_agent_scopes", "soc_refresh_sessions", "soc_auth_audit_logs"):
                assert insp.has_table(tbl)
            mod.downgrade()
            insp2 = sa.inspect(conn)
            for tbl in ("soc_users", "soc_user_agent_scopes", "soc_refresh_sessions", "soc_auth_audit_logs"):
                assert not insp2.has_table(tbl)
    mig_engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["/api/v1/rules", "/api/rules"])
async def test_ai_rules_jwt_permissions(jwt_lab, monkeypatch, prefix):
    from app.services.ai import harvest_service as harvest_module
    from test_ai_soc_studio import SUPPORTED

    client, factory = jwt_lab

    async def model(cti_text):
        return SUPPORTED

    monkeypatch.setattr(harvest_module, "AsyncSessionLocal", factory)
    monkeypatch.setattr(harvest_module.harvest_service, "_call_llm_for_sigma", model)
    admin = _bearer(_login(client, "soc-admin", "AdminPassword!123").json()["access_token"])
    operator = _bearer(_login(client, "soc-operator", "OperatorPass!123").json()["access_token"])
    analyst = _bearer(_login(client, "soc-analyst", "AnalystPass!123").json()["access_token"])
    body = {"cti_text": "Synthetic report for rule generation"}
    for headers in (admin, operator):
        created = client.post(f"{prefix}/harvest", headers=headers, json=body)
        assert created.status_code == 200 and created.json()["status"] == "pending"
    path = f"{prefix}/{created.json()['rule_id']}"
    assert client.get(path, headers=analyst).json()["rule_yaml"]
    assert client.post(f"{prefix}/harvest", json=body).status_code == 401
    assert client.post(f"{prefix}/harvest", headers=analyst, json=body).status_code == 403
    for method, url, payload, expected_status in [
        ("PUT", path, {"notes": "reviewed"}, "pending"),
        ("POST", f"{path}/validate", {}, "validated"),
        ("POST", f"{path}/activate", {}, "active"),
        ("POST", f"{path}/reject", {}, "rejected"),
        ("POST", f"{path}/disable", {}, "disabled"),
    ]:
        assert client.request(method, url, json=payload).status_code == 401
        assert client.request(method, url, headers=analyst, json=payload).status_code == 403
        result = client.request(method, url, headers=operator, json=payload)
        assert result.status_code == 200 and result.json().get("status") == expected_status, result.text
