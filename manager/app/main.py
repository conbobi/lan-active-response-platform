import logging
import re
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException, RequestValidationError
from app.core.config import settings
from app.core.network_security import token_matches, verify_operator_or_admin
from app.core.database import get_pool_status
from app.initializers.init_db import ensure_activity_schema, ensure_network_evidence_columns, ensure_process_instance_column, init_db
from app.routers.v1 import api_router
from app.websocket.agent_ws import agent_websocket_endpoint
from app.websocket.dashboard_ws import router as dashboard_ws_router
from app.services.core.scheduler import start_background_tasks
from app.core.exceptions import AppException
from app.core.response_outcome import AUTHORIZATION_FAILED, VALIDATION_ERROR, error_body

# ⚠️ QUAN TRỌNG: Import Base từ nơi models THỰC SỰ kế thừa
# Nếu project dùng app/core/database.py:
from app.core.database import async_engine as engine
from app.models.base import Base

# Nếu project dùng app/database.py (như file hiện tại):
# from app.database import engine, Base

# Import tất cả models để Base.metadata biết hết các bảng
import app.models  # noqa: F401 — quan trọng!


# ===== Logging =====
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("larp_manager")


# ===== Lifespan DUY NHẤT =====
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup order:
      1. Tạo tất cả bảng (idempotent — không xóa dữ liệu cũ)
      2. Seed data (rules, policies, groups — idempotent)
      3. Khởi động background tasks
    """
    # ── STEP 1: Tạo bảng ─────────────────────────────────────
    logger.info("[STARTUP] Creating database tables (if not exist)...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(ensure_process_instance_column)
            await conn.run_sync(ensure_network_evidence_columns)
            await conn.run_sync(ensure_activity_schema)
        logger.info(f"[STARTUP] ✓ Tables ready: {len(Base.metadata.tables)} tables")
    except Exception as e:
        logger.error(f"[STARTUP] ✗ Failed to create tables: {e}")
        raise  # Không start app nếu không tạo được bảng

    # ── STEP 2: Seed data ────────────────────────────────────
    logger.info("[STARTUP] Seeding initial data (rules, policies, groups)...")
    try:
        await init_db()
        logger.info("[STARTUP] ✓ Seed data ready")
    except Exception as e:
        # Seed fail không nên block app (có thể rules đã tồn tại)
        logger.warning(f"[STARTUP] Seed warning: {e}")

    # ── STEP 3: Background tasks ─────────────────────────────
    logger.info("[STARTUP] Starting background tasks...")
    scheduler = await start_background_tasks()

    logger.info("🚀 LAN Active Response Manager startup complete.")
    yield

    # ── SHUTDOWN ─────────────────────────────────────────────
    logger.info("🛑 Shutting down LAN Active Response Manager...")
    try:
        scheduler.stop_all()
    except Exception as e:
        logger.warning(f"[SHUTDOWN] {e}")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    redirect_slashes=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Attach unique request ID for distributed tracing and structured logs."""
    request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


_V1 = re.escape(settings.API_V1_STR)
_ID = r"[^/]+"
# Routes that authenticate and scope the operator themselves (Agent scope, read/write role).
OWN_AUTHORIZATION = [re.compile(p) for p in (
    rf"{_V1}/network/agents/.*",
    rf"{_V1}/incidents/{_ID}/response-proposals/?",
    rf"{_V1}/response-actions/{_ID}/(approve|reject|execute|rollback)/?",
)]
# Incident workflow calls any configured operator (analyst or admin) may make. They change incident
# bookkeeping or request read-only analysis; none dispatches a command to an endpoint.
ANALYST_WRITE = [(frozenset(methods), re.compile(p)) for methods, p in (
    ({"POST"}, rf"{_V1}/incidents/{_ID}/(assign|close|contain|false-positive|resolve|notes)/?"),
    ({"POST"}, rf"{_V1}/incidents/{_ID}/ai-analysis/(rate|regenerate|suggest-response|dismiss-suggestion)/?"),
    ({"POST"}, rf"{_V1}/incidents/bulk-resolve/?"),
    ({"PUT", "PATCH"}, rf"{_V1}/incidents/{_ID}/?"),
    ({"POST"}, rf"{_V1}/threat-intel/check/?"),
    ({"POST"}, rf"{_V1}/reports/generate/?"),
)]


def analyst_write(method, path):
    return any(method in methods and rule.fullmatch(path) for methods, rule in ANALYST_WRITE)


@app.middleware("http")
async def protect_sensitive_legacy_apis(request: Request, call_next):
    """Authorize every state-changing API call once credentials are configured.

    Default deny: a mutating request needs an admin operator (or the legacy admin token) unless it is
    an analyst-level incident workflow call (ANALYST_WRITE) or a route with its own scoped checks
    (OWN_AUTHORIZATION). The authenticated identity is exposed as ``request.state.operator`` so
    routes record it as the actor instead of trusting a client-supplied name.
    """
    path = request.url.path
    network = path.startswith(f"{settings.API_V1_STR}/network/agents/")
    request.state.operator = None
    has_auth_configured = bool(settings.NETWORK_LEGACY_ADMIN_TOKEN or settings.NETWORK_OPERATORS)
    if has_auth_configured and path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
        auth_header = request.headers.get("authorization", "")
        if path.startswith(f"{settings.API_V1_STR}/commands"):
            # Legacy raw command endpoints stay restricted to the legacy administrator token.
            kind, _, token = auth_header.partition(" ")
            if kind.lower() != "bearer" or not token_matches(token.strip(), settings.NETWORK_LEGACY_ADMIN_TOKEN):
                return JSONResponse({"detail": "Legacy administration requires its administrator token",
                                     "outcome_code": AUTHORIZATION_FAILED}, status_code=401)
            request.state.operator = "legacy_admin"
        elif not any(rule.fullmatch(path) for rule in OWN_AUTHORIZATION):
            try:
                identity, _ = verify_operator_or_admin(
                    auth_header, write=not analyst_write(request.method, path))
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail, "outcome_code": AUTHORIZATION_FAILED},
                                    status_code=exc.status_code, headers=exc.headers or {})
            request.state.operator = identity

    response = await call_next(request)
    if network:
        response.headers["Cache-Control"] = "private, no-store"
    return response


@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    req_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(exc.status_code, exc.message, req_id, exc.outcome, exc.extra),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    req_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(exc.status_code, exc.detail, req_id, getattr(exc, "outcome", None), getattr(exc, "extra", None)),
        headers=exc.headers or {}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", None)
    return JSONResponse(status_code=422, content={
        "detail": jsonable_encoder(exc.errors()), "status_code": 422, "request_id": req_id,
        "outcome_code": VALIDATION_ERROR})

# Routers
from app.api.routes.rules import router as ai_rules_router
from app.api.routes.dashboard import router as ai_dashboard_router

app.include_router(ai_rules_router, prefix="/api/rules", tags=["AI Rules"])
app.include_router(ai_rules_router, prefix="/api/v1/rules", tags=["AI Rules"])
app.include_router(ai_dashboard_router, prefix="/api/dashboard", tags=["AI Dashboard"])
app.include_router(ai_dashboard_router, prefix="/api/v1/dashboard", tags=["AI Dashboard"])
app.include_router(api_router, prefix=settings.API_V1_STR)

app.add_api_websocket_route("/ws/agent", agent_websocket_endpoint)
app.include_router(dashboard_ws_router)

@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database_pool": get_pool_status(),
    }


@app.get(f"{settings.API_V1_STR}/system/db-pool", tags=["System"])
async def system_db_pool_status():
    return get_pool_status()