import logging
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import HTTPException
from app.core.config import settings
from app.core.network_security import token_matches, verify_operator_or_admin
from app.core.database import get_pool_status
from app.initializers.init_db import ensure_process_instance_column, init_db, ensure_network_evidence_columns
from app.routers.v1 import api_router
from app.websocket.agent_ws import agent_websocket_endpoint
from app.websocket.dashboard_ws import router as dashboard_ws_router
from app.services.core.scheduler import start_background_tasks
from app.core.exceptions import AppException

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


@app.middleware("http")
async def protect_sensitive_legacy_apis(request: Request, call_next):
    """Keep unauthenticated legacy control routes outside enrolled deployments."""
    network = request.url.path.startswith(f"{settings.API_V1_STR}/network/agents/")
    has_auth_configured = bool(settings.NETWORK_LEGACY_ADMIN_TOKEN or settings.NETWORK_OPERATORS)
    if has_auth_configured and request.url.path.startswith("/api/"):
        read = request.method in {"GET", "HEAD", "OPTIONS"}
        is_legacy_commands = request.url.path.startswith(f"{settings.API_V1_STR}/commands")
        action_path = any(part in request.url.path.split("/") for part in {"actions", "kill", "kill_tree"})

        # 1. Legacy raw command injection endpoint (/commands) strictly requires legacy admin token if configured
        if is_legacy_commands and not read:
            kind, _, token = request.headers.get("authorization", "").partition(" ")
            is_valid_legacy = token_matches(token.strip(), settings.NETWORK_LEGACY_ADMIN_TOKEN)
            if kind.lower() != "bearer" or not is_valid_legacy:
                return JSONResponse({"detail": "Legacy administration requires its administrator token"}, status_code=401)

        # 2. Modern actions and process kill endpoints use unified authorization (operators and legacy admin)
        elif not network and (action_path or not read):
            auth_header = request.headers.get("authorization", "")
            try:
                verify_operator_or_admin(auth_header, write=True)
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    response = await call_next(request)
    if network:
        response.headers["Cache-Control"] = "private, no-store"
    return response


@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    req_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "detail": exc.message, "status_code": exc.status_code, "request_id": req_id}
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    req_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "detail": exc.detail, "status_code": exc.status_code, "request_id": req_id},
        headers=exc.headers or {}
    )

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