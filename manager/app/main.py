import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.initializers.init_db import init_db
from app.routers.v1 import api_router
from app.websocket.agent_ws import agent_websocket_endpoint
from app.websocket.dashboard_ws import router as dashboard_ws_router
from app.services.topology_service import topology_facade
from app.core.exceptions import AppException
from fastapi.middleware.cors import CORSMiddleware
# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("larp_manager")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing database tables...")
    await init_db()

    logger.info("Starting background scheduler and dead agent sweep...")
    scheduler = topology_facade.schedule_background_tasks()

    # Schedule periodic Threat Feed sync (every 6 hours)
    async def periodic_feed_sync():
        try:
            from app.core.database import AsyncSessionLocal
            from app.services.threat_intelligence_service import ThreatIntelligenceService
            async with AsyncSessionLocal() as session:
                ti_svc = ThreatIntelligenceService(session)
                await ti_svc.sync_all_feeds()
        except Exception as e:
            logger.error(f"Error in periodic threat feed sync: {e}")

    scheduler.schedule_task(21600, periodic_feed_sync)

    # Schedule periodic ML baseline retrain (every 24 hours)
    async def periodic_ml_retrain():
        try:
            from app.core.database import AsyncSessionLocal
            from app.repositories.agent_repository import AgentRepository
            from app.services.ml_anomaly_service import MLAnomalyService
            async with AsyncSessionLocal() as session:
                agent_repo = AgentRepository(session)
                ml_svc = MLAnomalyService(session)
                agents = await agent_repo.list()
                for ag in agents:
                    await ml_svc.train_agent_baseline(ag.id)
        except Exception as e:
            logger.error(f"Error in periodic ML baseline retrain: {e}")

    scheduler.schedule_task(86400, periodic_ml_retrain)

    logger.info("🚀 LAN Active Response Manager startup complete.")
    yield

    # Shutdown
    logger.info("🛑 Shutting down LAN Active Response Manager...")
    scheduler.stop_all()


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
# Exception handler for custom AppException
@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code}
    )


# API Routers
app.include_router(api_router, prefix=settings.API_V1_STR)

# WebSocket Endpoint
app.add_api_websocket_route("/ws/agent", agent_websocket_endpoint)

app.include_router(dashboard_ws_router)

# Health check endpoint
@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION
    }
