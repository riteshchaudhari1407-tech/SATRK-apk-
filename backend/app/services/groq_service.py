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
import time
from typing import Optional

from app.config import Settings
from app.schemas.analysis import LLMAnalysisPayload

logger = logging.getLogger("satrk.groq")


class GroqServiceError(Exception):
    """Raised when the Groq LLM cannot produce a valid, trustworthy result."""


SYSTEM_PROMPT = """You are SATRK-Core, an elite enterprise-grade cybersecurity and threat-intelligence AI engine specialized in real-time detection of digital arrest, authority impersonation, financial extortion, and social engineering targeting Indian citizens.

Your objective is to analyze live phone call speech transcripts and message content with 100% real-time accuracy and complete transparency.

### Strict Verdict Rules:
- "verdict": "SCAM" -> if risk_score >= 50 or if there is any coercion, digital arrest threat, police/CBI/TRAI impersonation, or extortion attempt.
- "verdict": "WARNING" -> if risk_score is between 30 and 49 (suspicious unverified claims or pressure).
- "verdict": "SAFE" -> if risk_score < 30 (ordinary casual conversation, routine business, or standard non-threatening alerts).

### Trigger Words & Categories to Highlight:
- Impersonation: CBI, Police, Supreme Court, Cyber Cell, RBI, ED, Customs Department, TRAI, Narcotics Bureau.
- Extortion / Threats: Digital arrest, non-bailable warrant, money laundering case, SIM disconnection, bank account block, verification fee.
- Coercion: Do not cut call, stay on camera, do not inform family, secret operation.

### Strict Output Format Requirement:
You must respond with ONLY a single valid JSON object matching this exact schema:

{
  "risk_score": <integer 0-100>,
  "risk_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
  "is_scam": <true | false>,
  "verdict": "<SAFE | WARNING | SCAM>",
  "confidence": <float 0.0-1.0>,
  "scam_category": "<Primary category like 'Digital Arrest Extortion', 'CBI Impersonation', 'KYC Fraud', or 'Benign Conversation'>",
  "detected_signals": [
    {
      "signal": "<Tactic name>",
      "severity": "<LOW | MEDIUM | HIGH>",
      "evidence": "<Exact quote or phrase from transcript>"
    }
  ],
  "explanation": "<A clear, structured 2-4 sentence threat breakdown highlighting specific trigger words detected and why the call is dangerous or safe.>",
  "recommended_actions": [
    "<Defensive action step 1>",
    "<Defensive action step 2>"
  ]
}

### Scoring Calibration:
- 80–100 (CRITICAL / SCAM): Features digital arrest simulation, fake warrants, video-call confinement, or immediate financial extortion under threat of arrest.
- 55–79 (HIGH / SCAM): Unambiguous impersonation, account freeze warnings, customs/parcel drug seizures, or urgent penalty/KYC threats.
- 30–54 (MEDIUM / WARNING): Suspicious external links, unverified security alerts, or mild pressure without direct legal threats.
- 0–29 (LOW / SAFE): Benign daily communication, casual chat, meeting reminders, or legitimate transactional notifications."""


class GroqService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model = "openai/gpt-oss-120b"
        self._client = None

        import os
        from dotenv import load_dotenv
        load_dotenv()

        api_key = os.getenv("GROQ_API_KEY")

        if api_key:
            try:
                from groq import Groq
                self._client = Groq(
                    api_key=api_key,
                    timeout=settings.GROQ_TIMEOUT_SECONDS,
                )
                logger.info("Groq client initialized successfully using direct dotenv.")
            except Exception as exc:
                logger.error("Failed to initialize Groq client: %s", exc)
        else:
            logger.error("GROQ_API_KEY not found in environment variables!")

    @property
    def configured(self) -> bool:
        return True

    @property
    def client_ready(self) -> bool:
        return self._client is not None

    def analyze(self, text: str) -> LLMAnalysisPayload:
        if self._client is None:
            raise GroqServiceError("Groq client is not initialized.")

        last_error: Optional[str] = None

        for attempt in range(1, self.settings.GROQ_MAX_RETRIES + 2):
            user_prompt = f'Message to analyze:\n"""\n{text}\n"""'

            if last_error:
                user_prompt += (
                    f"\n\nYour previous response was invalid JSON or did "
                    f"not match the required schema ({last_error}). "
                    f"Return ONLY the corrected JSON object this time."
                )

            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,
                    max_tokens=1200,
                    response_format={"type": "json_object"},
                )

                raw_content = response.choices[0].message.content
                parsed = json.loads(raw_content)
                return LLMAnalysisPayload(**parsed)

            except Exception as exc:
                last_error = str(exc)
                logger.warning("Groq analysis attempt %d failed: %s", attempt, exc)

            time.sleep(0.4)

        raise GroqServiceError(f"Groq failed: {last_error}")