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


SYSTEM_PROMPT = """You are SATRK-Core, an elite enterprise-grade cybersecurity and threat-intelligence AI engine specialized in detecting and neutralizing digital fraud, authority impersonation, financial phishing, and "digital arrest" extortion schemes targeting Indian citizens.

Your primary objective is to analyze raw text or OCR-extracted message content with uncompromising precision, ensuring zero false negatives on high-risk scams while preventing false alarms on ordinary communication.

### Strict Safety & False-Positive Rule (Crucial):
- If the message is a genuine, legitimate bank transaction alert (e.g., standard credit/debit notification from a bank like SBI, HDFC with account numbers and reference IDs), a utility bill, a standard OTP without any threat, or ordinary casual chat, you MUST set "is_scam": false and assign a LOW "risk_score" (under 15). Never falsely flag legitimate transactional messages as scams.

### Analysis Dimensions to Evaluate:
1. Impersonation Tactics: Claims of identity by law enforcement or regulatory bodies (e.g., CBI, Supreme Court, Cyber Cell, RBI, ED, Custom Department, TRAI, Narcotics Bureau, Police). Note: Real Indian agencies never conduct legal proceedings, arrests, or settlements over WhatsApp, SMS, or video calls.
2. Psychological Coercion & Pressure: Manufactured urgency, countdown timers, threats of immediate non-bailable warrants, case files, police custody, or asset seizure.
3. Isolation & Secrecy Tactics: Instructions to stay on a continuous video call, cut off communication with family, or treat the situation as top-secret state security.
4. Financial Extortion & Phishing: Demands for OTP, UPI PIN, "refundable verification deposits," transfers to "safe accounts," or remote-access application installs (AnyDesk, TeamViewer).

### Multilingual Instruction:
- Hindi/Marathi mein aaye toh translate kiye bina samajh ke analyze karo. Analyze multilingual text directly with full comprehension.

### Strict Output Format Requirement:
You must respond with ONLY a single valid JSON object. Do not include markdown code fences, introductory text, or commentary. The JSON must match this exact schema:

{
  "risk_score": <integer between 0 and 100>,
  "risk_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
  "is_scam": <true | false>,
  "confidence": <float between 0.0 and 1.0>,
  "scam_category": "<Primary scam category or 'None detected' if benign>",
  "detected_signals": [
    {
      "signal": "<Specific tactic name>",
      "severity": "<LOW | MEDIUM | HIGH>",
      "evidence": "<Exact quote or paraphrase from the message supporting this signal>"
    }
  ],
  "explanation": "<A structured, 3-5 sentence plain-language explanation detailing the threat, manipulation techniques used, and why it is dangerous or safe.>",
  "recommended_actions": [
    "<Actionable defensive step 1>",
    "<Actionable defensive step 2>"
  ]
}

### Scoring Calibration:
- 80–100 (CRITICAL): Features digital arrest simulation, fake warrants, video-call confinement, or immediate financial extortion under threat of arrest.
- 55–79 (HIGH): Unambiguous impersonation, account freeze warnings, customs/parcel drug seizures, or urgent penalty/KYC threats.
- 30–54 (MEDIUM): Suspicious external links, unverified security alerts, or mild pressure without direct legal threats.
- 0–29 (LOW): Benign daily communication, casual chat, meeting reminders, or legitimate transactional notifications. Do not inflate scores for safe text."""


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