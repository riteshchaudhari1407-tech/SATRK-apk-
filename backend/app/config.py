"""
Central configuration for the Satrk backend.

All values are read from environment variables (via a .env file in
the backend/ directory during local development). Nothing here is
hardcoded as a secret — copy .env.example to .env and fill in real
values.
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Groq LLM ---
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "openai/gpt-oss-20b"
    GROQ_TIMEOUT_SECONDS: float = 20.0
    GROQ_MAX_RETRIES: int = 2

    # --- External Detection APIs ---
    RESEMBLE_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    # --- Semantic AI (sentence-transformers) ---
    SEMANTIC_MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"

    # --- CORS ---
    FRONTEND_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:3000,http://127.0.0.1:3000"

    # --- Input limits ---
    MAX_TEXT_LENGTH: int = 4000
    MAX_IMAGE_SIZE_MB: int = 8

    # --- Health check caching ---
    HEALTH_CACHE_SECONDS: int = 45

    # --- App metadata ---
    APP_NAME: str = "Satrk AI Scam Detection API"
    APP_VERSION: str = "2.0.0"

    @property
    def frontend_origins_list(self) -> List[str]:
        origins = [
            origin.strip()
            for origin in self.FRONTEND_ORIGINS.split(",")
            if origin.strip()
        ]
        defaults = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
        for d in defaults:
            if d not in origins:
                origins.append(d)
        return origins

    @property
    def groq_configured(self) -> bool:
        return bool(self.GROQ_API_KEY.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
