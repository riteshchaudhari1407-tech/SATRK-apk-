import logging
from typing import Dict, Any
from app.services.stt_service import STTService
from app.services.rule_engine_service import RuleEngineService
from app.services.groq_service import GroqService

logger = logging.getLogger("satrk.call_monitoring")

THREAT_THRESHOLD = 50.0  # Risk score threshold jahan alert trigger hoga

class CallMonitoringService:
    def __init__(self, stt_service: STTService, rule_engine: RuleEngineService, groq_service: GroqService):
        self.stt_service = stt_service
        self.rule_engine = rule_engine
        self.groq_service = groq_service
        # Active calls ke liye transcript buffers store karne ke liye dictionary
        self.call_transcripts: Dict[str, str] = {}

    async def process_audio_chunk(self, call_id: str, audio_bytes: bytes) -> Dict[str, Any]:
        """
        Audio chunk leta hai, STT ke through text banata hai, transcript buffer mein 
        append karta hai, aur rule engine + groq pipeline se risk score evaluate karta hai.
        """
        try:
            # Step 1: Transcribe audio chunk using STT Service (Phase 1)
            chunk_text = await self.stt_service.transcribe_audio(audio_bytes)
            
            if not chunk_text:
                return {
                    "call_id": call_id,
                    "latest_chunk": "",
                    "transcript": self.call_transcripts.get(call_id, ""),
                    "risk_score": 0.0,
                    "alert": False,
                    "hits": []
                }

            # Step 2: Maintain transcript buffer for this call
            existing_transcript = self.call_transcripts.get(call_id, "")
            updated_transcript = f"{existing_transcript} {chunk_text}".strip()
            self.call_transcripts[call_id] = updated_transcript

            # Step 3: Run Rule Engine (Deterministic Check)
            rule_result = self.rule_engine.analyze(updated_transcript)
            current_score = rule_result.score

            # Step 4: If rule score crosses threshold, run Groq LLM deep analysis for validation
            llm_analysis = None
            if current_score >= THREAT_THRESHOLD and self.groq_service.client_ready:
                try:
                    llm_analysis = self.groq_service.analyze(updated_transcript)
                    current_score = max(current_score, llm_analysis.risk_score)
                except Exception as e:
                    logger.warning(f"Groq fallback failed during call monitoring: {e}")

            is_alert = current_score >= THREAT_THRESHOLD

            return {
                "call_id": call_id,
                "latest_chunk": chunk_text,
                "transcript": updated_transcript,
                "risk_score": current_score,
                "alert": is_alert,
                "hits": [h.category for h in rule_result.hits]
            }

        except Exception as e:
            logger.error(f"Error in CallMonitoringService for call {call_id}: {e}")
            raise e