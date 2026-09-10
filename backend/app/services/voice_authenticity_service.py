import logging
import os
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger("satrk.voice_authenticity")

RESEMBLE_DETECT_URL = "https://app.resemble.ai/api/v2/detect"


class VoiceAuthenticityService:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = (api_key or os.getenv("RESEMBLE_API_KEY", "")).strip()
        if not self.api_key:
            logger.info("RESEMBLE_API_KEY not configured. Deepfake detection will return unanalyzed state.")

    async def check_authenticity(
        self, audio_bytes: bytes, filename: str = "audio.wav"
    ) -> Dict[str, Any]:
        """
        Calls Resemble AI detection API (https://app.resemble.ai/api/v2/detect).
        Enforces 8-second timeout.
        Returns {"is_likely_cloned": bool or None, "confidence": float or None}.
        """
        if not self.api_key or not audio_bytes:
            return {"is_likely_cloned": None, "confidence": None}

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
            }
            files = {
                "file": (filename, audio_bytes, "audio/wav"),
            }

            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.post(
                    RESEMBLE_DETECT_URL,
                    headers=headers,
                    files=files,
                )

            if response.status_code == 200:
                data = response.json()
                # Parse fields flexibly supporting standard Resemble API schemas
                is_cloned = data.get("is_likely_cloned")
                if is_cloned is None:
                    is_cloned = data.get("is_cloned")
                if is_cloned is None:
                    is_cloned = data.get("synthetic")

                conf = data.get("confidence")
                if conf is None:
                    conf = data.get("score")
                if conf is None:
                    conf = data.get("confidence_score")

                parsed_cloned = bool(is_cloned) if is_cloned is not None else None
                parsed_conf = float(conf) if conf is not None else None

                return {
                    "is_likely_cloned": parsed_cloned,
                    "confidence": parsed_conf,
                }
            else:
                logger.warning(
                    f"Resemble AI API returned non-200 status code {response.status_code}: {response.text}"
                )
                return {"is_likely_cloned": None, "confidence": None}

        except Exception as e:
            logger.warning(f"Voice authenticity check failed or timed out: {e}")
            return {"is_likely_cloned": None, "confidence": None}
