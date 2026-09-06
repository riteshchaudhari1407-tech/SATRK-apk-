"""
WebSocket router for real-time audio chunk processing during live calls.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.container import call_monitoring_service

logger = logging.getLogger("satrk.router.calls")

router = APIRouter(prefix="/calls", tags=["calls"])


@router.websocket("/ws/{call_id}")
async def websocket_call_endpoint(websocket: WebSocket, call_id: str):
    """
    WebSocket endpoint for receiving binary audio chunks for a live call.
    Processes audio chunks in real-time via CallMonitoringService and sends JSON analysis back to client.
    """
    await websocket.accept()
    logger.info(f"WebSocket connection accepted for call_id: {call_id}")

    try:
        while True:
            audio_bytes = await websocket.receive_bytes()
            result = await call_monitoring_service.process_audio_chunk(call_id, audio_bytes)
            await websocket.send_json(result)
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for call_id: {call_id}")
    except Exception as exc:
        logger.error(f"Error during WebSocket session for call_id {call_id}: {exc}")
