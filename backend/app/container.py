"""
Service container.

All services are instantiated exactly once at process startup
(module-level singletons) — the ML/embedding model loads once, the
Groq client is created once, etc. Routers import instances from here
rather than constructing their own.
"""

import logging

from app.config import get_settings
from app.services.analysis_service import AnalysisService
from app.services.groq_service import GroqService
from app.services.health_service import HealthService
from app.services.ocr_service import OCRService
from app.services.semantic_service import SemanticService
from app.services.stt_service import STTService
from app.services.rule_engine_service import RuleEngineService
from app.services.call_monitoring_service import CallMonitoringService
from app.services.voice_authenticity_service import VoiceAuthenticityService
from app.services.vision_service import VisionService
from app.services.financial_scanner import FinancialScanner
from app.services.scam_registry import ScamRegistry

logger = logging.getLogger("satrk.container")

settings = get_settings()

logger.info("Initializing Satrk services...")

groq_service = GroqService(settings)
semantic_service = SemanticService()
ocr_service = OCRService()
rule_engine_service = RuleEngineService()
stt_service = STTService()
voice_authenticity_service = VoiceAuthenticityService(settings.RESEMBLE_API_KEY)
vision_service = VisionService(settings=settings)

financial_scanner = FinancialScanner()
scam_registry = ScamRegistry()

call_monitoring_service = CallMonitoringService(
    stt_service=stt_service,
    rule_engine=rule_engine_service,
    groq_service=groq_service,
    voice_auth_service=voice_authenticity_service,
    vision_service=vision_service,
    financial_scanner=financial_scanner,
    scam_registry=scam_registry,
)

analysis_service = AnalysisService(
    groq_service=groq_service,
    semantic_service=semantic_service,
    ocr_service=ocr_service,
    vision_service=vision_service,
    financial_scanner=financial_scanner,
    scam_registry=scam_registry,
)

health_service = HealthService(
    settings=settings,
    groq_service=groq_service,
    semantic_service=semantic_service,
    ocr_service=ocr_service,
)

logger.info(
    "Services ready — groq_configured=%s semantic_available=%s ocr_available=%s stt_ready=%s",
    groq_service.configured,
    semantic_service.available,
    ocr_service.available,
    stt_service.client is not None,
)
