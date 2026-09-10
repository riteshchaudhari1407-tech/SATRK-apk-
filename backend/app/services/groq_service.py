"""
Groq Service (Layer B — LLM Contextual Reasoning)
------------------------------------------------------
Wraps the official `groq` Python SDK. The LLM is instructed, via a
strict system prompt, to return ONLY a JSON object matching
LLMAnalysisPayload. That JSON is validated with Pydantic before it is
trusted anywhere else in the pipeline — if it doesn't validate, this
service retries a bounded number of times, then raises
GroqServiceError so the caller can honestly report that the LLM layer
was unavailable for this request (never fabricate a result).
"""
import json
import logging
import asyncio
from typing import Optional

from app.config import Settings
from app.schemas.analysis import LLMAnalysisPayload

logger = logging.getLogger("satrk.groq")


class GroqServiceError(Exception):
    """Raised when the Groq LLM cannot produce a valid, trustworthy result."""


SYSTEM_PROMPT = """You are SATRK-Core, an ultra-fast cybersecurity AI engine for real-time scam detection targeting Indian citizens (Digital Arrest, CBI/Police/Cyber Cell impersonation, TRAI SIM disconnection, FedEx/Customs drug threats, UPI/KYC fraud).

Analyze text and respond with ONLY a single valid JSON object:
{
  "risk_score": <integer 0-100>,
  "risk_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
  "is_scam": <true | false>,
  "verdict": "<SAFE | WARNING | SCAM>",
  "confidence": <float 0.0-1.0>,
  "scam_category": "<Category like 'Digital Arrest', 'CBI Impersonation', 'KYC Fraud', 'Benign'>",
  "detected_signals": [
    {
      "signal": "<Tactic name>",
      "severity": "<LOW | MEDIUM | HIGH>",
      "evidence": "<Quote from text>"
    }
  ],
  "explanation": "<Concise 2-3 sentence threat breakdown highlighting specific trigger words and risk rationale.>",
  "recommended_actions": ["<Defensive step 1>", "<Defensive step 2>"]
}

Rules:
- SCAM: risk_score >= 50 or coercion/digital arrest/police threat/extortion.
- WARNING: 30-49 (suspicious unverified claims/urgency).
- SAFE: < 30 (casual/routine communication)."""


class GroqService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model = "openai/gpt-oss-20b"
        self._client = None

        import os
        from dotenv import load_dotenv
        load_dotenv()

        api_key = os.getenv("GROQ_API_KEY")

        if api_key:
            try:
                from groq import AsyncGroq
                self._client = AsyncGroq(
                    api_key=api_key,
                    timeout=settings.GROQ_TIMEOUT_SECONDS,
                )
                logger.info("AsyncGroq client initialized with model llama-3.1-8b-instant.")
            except Exception as exc:
                logger.error("Failed to initialize AsyncGroq client: %s", exc)
        else:
            logger.error("GROQ_API_KEY not found in environment variables!")

    @property
    def configured(self) -> bool:
        return True

    @property
    def client_ready(self) -> bool:
        return self._client is not None

    async def analyze(self, text: str) -> LLMAnalysisPayload:
        if self._client is None:
            raise GroqServiceError("Groq client is not initialized.")

        last_error: Optional[str] = None

        for attempt in range(1, self.settings.GROQ_MAX_RETRIES + 2):
            user_prompt = f'Message to analyze:\n"""\n{text}\n"""'

            if last_error:
                user_prompt += (
                    f"\n\nPrevious response invalid JSON: {last_error}. "
                    f"Return ONLY valid JSON object matching schema."
                )

            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.1,
                    max_tokens=600,
                    response_format={"type": "json_object"},
                )

                raw_content = response.choices[0].message.content
                parsed = json.loads(raw_content)
                return LLMAnalysisPayload(**parsed)

            except Exception as exc:
                last_error = str(exc)
                logger.warning("Groq analysis attempt %d failed: %s", attempt, exc)

            await asyncio.sleep(0.2)

        raise GroqServiceError(f"Groq failed: {last_error}")