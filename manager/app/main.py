import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.initializers.init_db import init_db
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
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code}
    )

# Routers
app.include_router(api_router, prefix=settings.API_V1_STR)
app.add_api_websocket_route("/ws/agent", agent_websocket_endpoint)
app.include_router(dashboard_ws_router)

@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION
    }