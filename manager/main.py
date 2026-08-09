# manager/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.initializers.init_db import init_db
from app.routers import dashboard
from app.websocket.agent_ws import agent_websocket_endpoint

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Tạo bảng khi khởi động
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)

# Router cho Dashboard
app.include_router(dashboard.router)

# WebSocket endpoint cho Agent
app.add_api_websocket_route("/ws/agent", agent_websocket_endpoint)

@app.get("/health")
async def health():
    return {"status": "ok"}