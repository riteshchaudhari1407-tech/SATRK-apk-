"""
Satrk Backend — FastAPI entrypoint.

Run from the `backend/` directory:

    uvicorn app.main:app --reload --port 8000

Endpoints:
    GET  /api/health         -> real service status (backend, groq, semantic_ai, ocr)
    POST /api/analyze        -> { "text": "..." } -> AnalysisResponse
    POST /api/analyze-image  -> multipart file "file" -> AnalysisResponse
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.container import settings
from app.routers import analysis, calls, health, scans, community

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("satrk.main")

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Hybrid AI backend for detecting India's digital-arrest and "
        "authority-impersonation scams — combining Groq LLM reasoning, "
        "sentence-embedding semantic analysis, and a supporting "
        "technical signal layer."
    ),
    version=settings.APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_origins_list,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["health"])
app.include_router(analysis.router, tags=["analysis"])
app.include_router(scans.router, tags=["scans"])
app.include_router(community.router)
app.include_router(calls.router)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }
