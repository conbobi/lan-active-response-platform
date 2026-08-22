from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.websocket.dashboard_connection_manager import dashboard_manager

router = APIRouter()

@router.websocket("/ws/dashboard")
async def dashboard_websocket_endpoint(websocket: WebSocket):
    await dashboard_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        dashboard_manager.disconnect(websocket)