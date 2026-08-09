# manager/app/websocket/agent_ws.py
import json
from fastapi import WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.deps import get_db
from app.services.agent_service import process_agent_data
from app.websocket.connection_manager import manager as ws_manager

async def agent_websocket_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    # ✅ Phải accept trước khi giao tiếp
    await websocket.accept()

    # Nhận dữ liệu đầu tiên để xác định agent_id
    try:
        data = await websocket.receive_text()
        msg = json.loads(data)
        agent_id = msg.get("agent_id")
        if not agent_id:
            await websocket.close(code=1008)
            return
    except:
        await websocket.close(code=1008)
        return

    await ws_manager.connect(agent_id, websocket)
    try:
        # Xử lý gói tin đầu tiên
        async with db.begin():
            await process_agent_data(db, msg)

        # Vòng lặp nhận dữ liệu tiếp theo
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            async with db.begin():
                await process_agent_data(db, msg)
    except WebSocketDisconnect:
        ws_manager.disconnect(agent_id)