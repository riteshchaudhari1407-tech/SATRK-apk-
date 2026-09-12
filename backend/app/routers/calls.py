"""
WebSocket router for real-time audio chunk processing during live calls.

Broadcasts three event types to all connected frontend dashboards:
  - phone_connected   : when an Android device opens a call session
  - call_analysis      : for every processed audio chunk (transcript, risk, etc.)
  - phone_disconnected : when the Android device disconnects
"""

import logging
import time
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, File, UploadFile, HTTPException
import asyncio

from app.container import call_monitoring_service

logger = logging.getLogger("satrk.router.calls")

router = APIRouter(prefix="/calls", tags=["calls"])

# ── state ────────────────────────────────────────────────────────────
frontend_connections: list[WebSocket] = []
active_phone_calls: dict[str, dict] = {}  # call_id → metadata dict


# ── helpers ──────────────────────────────────────────────────────────
async def broadcast_to_frontend(data: dict):
    """Send a JSON payload to every connected frontend dashboard."""
    stale: list[WebSocket] = []
    for ws in frontend_connections:
        try:
            await ws.send_json(data)
        except Exception:
            stale.append(ws)
    for ws in stale:
        if ws in frontend_connections:
            frontend_connections.remove(ws)


# ── frontend dashboard endpoint ─────────────────────────────────────
@router.websocket("/ws-frontend")
async def websocket_frontend_endpoint(websocket: WebSocket):
    """
    Long-lived WS for the React dashboard.  On connect, the dashboard
    immediately receives a snapshot of every active phone call so it can
    render the current state without waiting for the next audio chunk.
    """
    await websocket.accept()
    frontend_connections.append(websocket)
    logger.info("Frontend dashboard connected to live call stream.")

    # Send initial snapshot of all active calls
    try:
        for call_id, meta in active_phone_calls.items():
            await websocket.send_json({
                "event": "phone_connected",
                "call_id": call_id,
                "connected_at": meta.get("connected_at"),
                "phone_status": "ACTIVE",
            })
    except Exception as exc:
        logger.warning(f"Failed to send initial snapshot to frontend: {exc}")

    try:
        while True:
            await websocket.receive_text()  # keep-alive
    except WebSocketDisconnect:
        if websocket in frontend_connections:
            frontend_connections.remove(websocket)
        logger.info("Frontend dashboard disconnected from live call stream.")
    except Exception as exc:
        if websocket in frontend_connections:
            frontend_connections.remove(websocket)
        logger.error(f"Error in frontend websocket: {exc}")


# ── phone (Android) call endpoint ───────────────────────────────────
@router.websocket("/ws/{call_id}")
async def websocket_call_endpoint(websocket: WebSocket, call_id: str):
    """
    Receives binary audio chunks from the Android app, processes them
    through the analysis pipeline, and broadcasts every result to the
    frontend dashboard in real-time.
    """
    await websocket.accept()
    logger.info(f"Phone WebSocket connected — call_id: {call_id}")

    connected_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    active_phone_calls[call_id] = {"connected_at": connected_at}

    # ① Broadcast "phone connected" event
    await broadcast_to_frontend({
        "event": "phone_connected",
        "call_id": call_id,
        "connected_at": connected_at,
        "phone_status": "ACTIVE",
    })

    try:
        while True:
            message = await websocket.receive()
            if "bytes" in message and message["bytes"]:
                audio_bytes = message["bytes"]
                result = await call_monitoring_service.process_audio_chunk(call_id, audio_bytes)
                await websocket.send_json(result)

                # Broadcast analysis result with event tag
                broadcast_payload = {**result, "event": "call_analysis"}
                asyncio.create_task(broadcast_to_frontend(broadcast_payload))
            elif "text" in message and message["text"]:
                try:
                    import json
                    data = json.loads(message["text"])
                    if "frame_base64" in data or "image" in data:
                        frame = data.get("frame_base64") or data.get("image")
                        call_monitoring_service.set_call_frame(call_id, frame)
                        # Process synthetic chunk with frame
                        result = await call_monitoring_service.process_audio_chunk(call_id, b"", video_frame=frame)
                        await websocket.send_json(result)
                        broadcast_payload = {**result, "event": "call_analysis"}
                        asyncio.create_task(broadcast_to_frontend(broadcast_payload))
                except Exception as parse_err:
                    logger.warning(f"WS text parse warning for call {call_id}: {parse_err}")

    except WebSocketDisconnect:
        logger.info(f"Phone WebSocket disconnected — call_id: {call_id}")
    except Exception as exc:
        logger.error(f"Error during phone WebSocket session {call_id}: {exc}")
    finally:
        # ③ Broadcast "phone disconnected" event
        active_phone_calls.pop(call_id, None)
        asyncio.create_task(broadcast_to_frontend({
            "event": "phone_disconnected",
            "call_id": call_id,
            "phone_status": "DISCONNECTED",
        }))


# ── frame / screenshot upload endpoint for live calls ──────────────
@router.post("/frame/{call_id}")
async def upload_call_frame(call_id: str, file: UploadFile = File(...)):
    """
    Accepts a video call frame/screenshot from Android or dashboard,
    runs Vision Service analysis, caches it for the call_id session,
    and broadcasts the updated threat analysis to connected frontends.
    """
    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty frame uploaded.")

    result = await call_monitoring_service.process_audio_chunk(call_id, b"", video_frame=image_bytes)
    broadcast_payload = {**result, "event": "call_analysis"}
    await broadcast_to_frontend(broadcast_payload)
    return result


# ── audio file upload endpoint ──────────────────────────────────────
@router.post("/upload-audio")
async def upload_audio_file(file: UploadFile = File(...)):
    """
    Accepts an uploaded audio file (wav, webm, mp3, ogg, mp4, etc.),
    runs it through the same STT → rule-engine → Groq pipeline used
    for live calls, and broadcasts the result to the frontend dashboard.
    """
    # Check for valid content_type or file extensions
    is_audio_mime = file.content_type and (
        file.content_type.startswith("audio/") 
        or file.content_type.startswith("video/") 
        or file.content_type == "application/octet-stream"
    )
    ext = (file.filename or "").lower().split(".")[-1]
    is_audio_ext = ext in ["wav", "mp3", "webm", "ogg", "m4a", "mp4", "aac", "flac", "raw", "pcm"]

    if not (is_audio_mime or is_audio_ext):
        raise HTTPException(status_code=400, detail="Please upload a valid audio file (.wav, .mp3, .webm, .m4a, .ogg, etc.).")

    audio_bytes = await file.read()
    if not audio_bytes or len(audio_bytes) < 100:
        raise HTTPException(status_code=400, detail="Uploaded audio file is empty or too small.")

    call_id = f"upload_{int(time.time() * 1000)}"
    logger.info(f"Processing uploaded audio file — call_id: {call_id}, size: {len(audio_bytes)} bytes")

    # Broadcast "connected" so dashboard shows activity immediately
    await broadcast_to_frontend({
        "event": "phone_connected",
        "call_id": call_id,
        "connected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phone_status": "ACTIVE",
    })

    try:
        result = await call_monitoring_service.process_audio_chunk(call_id, audio_bytes)

        broadcast_payload = {**result, "event": "call_analysis"}
        await broadcast_to_frontend(broadcast_payload)

        # Mark as done
        await broadcast_to_frontend({
            "event": "phone_disconnected",
            "call_id": call_id,
            "phone_status": "DISCONNECTED",
        })

        return result

    except Exception as exc:
        logger.error(f"Error processing uploaded audio: {exc}")
        await broadcast_to_frontend({
            "event": "phone_disconnected",
            "call_id": call_id,
            "phone_status": "DISCONNECTED",
        })
        raise HTTPException(status_code=500, detail=f"Audio processing failed: {str(exc)}")

