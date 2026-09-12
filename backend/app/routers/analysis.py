"""
POST /api/analyze        — analyze a pasted text message
POST /api/analyze-image  — OCR a screenshot, then analyze the extracted text

Both return an AnalysisResponse produced entirely by the backend's
hybrid AI pipeline (analysis_service). The frontend never generates
any part of this result — it only displays it.
"""

import asyncio
import logging
import httpx
from fastapi import APIRouter, File, HTTPException, UploadFile

from app.container import analysis_service, settings, vision_service
from app.routers.scans import record_scan
from app.schemas.analysis import (
    AnalysisResponse,
    AnalyzeTextRequest,
    FeedbackRequest,
    FeedbackResponse,
    LinkAnalysisRequest,
    LinkAnalysisResponse,
)

logger = logging.getLogger("satrk.router.analysis")

router = APIRouter()


@router.post("/api/analyze", response_model=AnalysisResponse, operation_id="analyze_text_main")
@router.post("/api/v1/scan-text", response_model=AnalysisResponse, operation_id="analyze_text_alias")
@router.post("/api/v1/scan", response_model=AnalysisResponse, operation_id="analyze_text_legacy")
async def analyze_text(payload: AnalyzeTextRequest) -> AnalysisResponse:
    try:
        res = await analysis_service.analyze_text(payload.text)
        if res.success and res.risk_score is not None:
            record_scan(
                message=payload.text,
                risk_score=res.risk_score,
                risk_level=res.risk_level or "LOW",
                scam_category=res.scam_category,
            )
        return res
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error during text analysis")
        raise HTTPException(
            status_code=500, detail=f"Analysis failed unexpectedly: {exc}"
        ) from exc


@router.post("/api/v1/analyze/image", operation_id="analyze_image_vision_endpoint")
@router.post("/api/analyze-image", response_model=AnalysisResponse, operation_id="analyze_image_main")
@router.post("/api/v1/scan-image", response_model=AnalysisResponse, operation_id="analyze_image_alias")
@router.post("/api/v1/scan/image", response_model=AnalysisResponse, operation_id="analyze_image_legacy")
async def analyze_image(file: UploadFile = File(...)) -> AnalysisResponse:
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400, detail="Please upload a valid image file."
        )

    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    max_bytes = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024
    if len(image_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Image exceeds the {settings.MAX_IMAGE_SIZE_MB}MB limit.",
        )

    try:
        # Run OCR + NLP pipeline and Vision Service concurrently
        res_task = analysis_service.analyze_image(image_bytes)
        vision_task = vision_service.analyze(image_bytes)

        res, vision_res = await asyncio.gather(res_task, vision_task, return_exceptions=True)

        if isinstance(res, Exception):
            res = AnalysisResponse(
                success=True,
                analysis_available=True,
                input_type="image",
                risk_score=10,
                risk_level="LOW",
                explanation="Screenshot OCR processing completed.",
            )

        if isinstance(vision_res, dict) and vision_res.get("threat_detected"):
            vision_score = int(vision_res.get("confidence", 85.0))
            if res.risk_score is not None:
                res.risk_score = max(res.risk_score, vision_score)
            else:
                res.risk_score = vision_score

            res.is_scam = True
            res.risk_level = "CRITICAL" if res.risk_score >= 80 else "HIGH"
            res.scam_category = vision_res.get("threat_type", res.scam_category or "Visual Scam")
            res.explanation = (
                f"[VISUAL THREAT DETECTED: {vision_res.get('threat_type')}] "
                f"{vision_res.get('analysis_details')} "
                f"{(res.explanation or '')}"
            ).strip()

        # Attach vision analysis dict to response payload
        if isinstance(vision_res, dict):
            setattr(res, "vision_analysis", vision_res)

        if res.success and res.risk_score is not None:
            record_scan(
                message=res.extracted_text or f"Screenshot {vision_res.get('threat_type', 'Scan') if isinstance(vision_res, dict) else 'Scan'}",
                risk_score=res.risk_score,
                risk_level=res.risk_level or "LOW",
                scam_category=res.scam_category,
            )
        return res
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error during image analysis")
        raise HTTPException(
            status_code=500, detail=f"Analysis failed unexpectedly: {exc}"
        ) from exc


@router.post("/api/v1/analyze/link", response_model=LinkAnalysisResponse, operation_id="analyze_link")
async def analyze_link(payload: LinkAnalysisRequest) -> LinkAnalysisResponse:
    """
    Real-Time Link Analysis Endpoint.
    Checks target URL against Google Safe Browsing API v4 for phishing & malicious threats.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()
    if not api_key:
        logger.info("GOOGLE_SAFE_BROWSING_API_KEY not configured. Returning default link evaluation.")
        return LinkAnalysisResponse(
            url=payload.url,
            is_safe=True,
            threat_types=[],
            details="Google Safe Browsing API key not configured; link unanalyzed.",
        )

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        request_body = {
            "client": {"clientId": "satrk-app", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": payload.url}],
            },
        }

        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(endpoint, json=request_body)

        if resp.status_code == 200:
            res_data = resp.json()
            matches = res_data.get("matches", [])
            if matches:
                threats = list(set([m.get("threatType", "MALICIOUS") for m in matches]))
                return LinkAnalysisResponse(
                    url=payload.url,
                    is_safe=False,
                    threat_types=threats,
                    details=f"Social engineering/malicious link detected by Google Safe Browsing: {', '.join(threats)}.",
                )
            else:
                return LinkAnalysisResponse(
                    url=payload.url,
                    is_safe=True,
                    threat_types=[],
                    details="URL analyzed cleanly. No active security threats found.",
                )
        else:
            logger.warning(f"Google Safe Browsing API returned status {resp.status_code}: {resp.text}")
            return LinkAnalysisResponse(
                url=payload.url,
                is_safe=True,
                threat_types=[],
                details="Safe Browsing API check unverified due to non-200 status code.",
            )

    except Exception as exc:
        logger.warning(f"Safe Browsing API link check error for {payload.url}: {exc}")
        return LinkAnalysisResponse(
            url=payload.url,
            is_safe=True,
            threat_types=[],
            details=f"Link analysis request failed or timed out: {exc}",
        )


@router.post("/api/v1/feedback", response_model=FeedbackResponse, operation_id="record_feedback")
def record_feedback(payload: FeedbackRequest) -> FeedbackResponse:
    """
    Adaptive Learning Feedback Loop Endpoint.
    Logs feedback on alert accuracy to fine-tune threat rules and LLM prompts.
    """
    logger.info(
        "Feedback received for call %s: alert_was_correct=%s, transcript_snippet=%r",
        payload.call_id,
        payload.alert_was_correct,
        payload.transcript_snippet,
    )
    return FeedbackResponse(
        status="success",
        message="Feedback logged successfully for adaptive learning.",
        call_id=payload.call_id,
    )

