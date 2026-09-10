import logging
from typing import Dict, Any, List, Optional
from app.services.stt_service import STTService
from app.services.rule_engine_service import RuleEngineService
from app.services.groq_service import GroqService
from app.services.voice_authenticity_service import VoiceAuthenticityService

logger = logging.getLogger("satrk.call_monitoring")

THREAT_THRESHOLD = 50.0  # Risk score threshold for critical alert


class CallMonitoringService:
    def __init__(
        self,
        stt_service: STTService,
        rule_engine: RuleEngineService,
        groq_service: GroqService,
        voice_auth_service: Optional[VoiceAuthenticityService] = None,
    ):
        self.stt_service = stt_service
        self.rule_engine = rule_engine
        self.groq_service = groq_service
        self.voice_auth_service = voice_auth_service
        self.call_transcripts: Dict[str, str] = {}

    async def process_audio_chunk(self, call_id: str, audio_bytes: bytes) -> Dict[str, Any]:
        """
        Processes audio chunk through STT -> Rule Engine -> Groq LLM pipeline -> Voice Authenticity.
        Generates percentage risk score, definitive verdict (SAFE/WARNING/SCAM),
        AI Threat Explanation breakdown, and deepfake voice detection.
        """
        try:
            # Step 1: Transcribe audio chunk (Whisper temperature=0.0 + noise filter)
            chunk_text = await self.stt_service.transcribe_audio(audio_bytes)
            
            existing_transcript = self.call_transcripts.get(call_id, "")

            if not chunk_text:
                current_score = 0.0
                verdict = "SAFE"
                hits: List[str] = []
                if existing_transcript:
                    rule_res = self.rule_engine.analyze(existing_transcript)
                    current_score = rule_res.score
                    hits = [h.category for h in rule_res.hits]
                    verdict = "SCAM" if current_score >= 50 else ("WARNING" if current_score >= 30 else "SAFE")

                voice_auth_res = {"is_likely_cloned": None, "confidence": None}
                if current_score >= THREAT_THRESHOLD and self.voice_auth_service:
                    try:
                        voice_auth_res = await self.voice_auth_service.check_authenticity(audio_bytes)
                        if voice_auth_res.get("is_likely_cloned") is True:
                            current_score = min(100.0, current_score + 10.0)
                            if "possible_voice_clone" not in hits:
                                hits.append("possible_voice_clone")
                    except Exception as e:
                        logger.warning(f"Voice authenticity check failed for call {call_id}: {e}")

                return {
                    "call_id": call_id,
                    "latest_chunk": "",
                    "transcript": existing_transcript,
                    "risk_score": current_score,
                    "verdict": verdict,
                    "alert": current_score >= THREAT_THRESHOLD or verdict == "SCAM",
                    "explanation": "Listening for incoming audio speech...",
                    "scam_category": "Monitoring",
                    "hits": hits,
                    "detected_signals": [],
                    "voice_authenticity": voice_auth_res,
                }

            # Step 2: Append to call transcript buffer
            updated_transcript = f"{existing_transcript} {chunk_text}".strip()
            self.call_transcripts[call_id] = updated_transcript

            # Step 3: Run Rule Engine Analysis
            rule_result = self.rule_engine.analyze(updated_transcript)
            current_score = rule_result.score
            hits = [h.category for h in rule_result.hits]

            # Step 4: Run Groq LLM Scam Analysis Engine
            llm_analysis = None
            explanation = ""
            scam_category = "None detected"
            detected_signals = []
            verdict = "SAFE"

            if (current_score > 0 or len(updated_transcript) >= 15) and self.groq_service.client_ready:
                try:
                    llm_analysis = self.groq_service.analyze(updated_transcript)
                    current_score = max(current_score, float(llm_analysis.risk_score))
                    verdict = getattr(llm_analysis, 'verdict', None) or ("SCAM" if current_score >= 50 else ("WARNING" if current_score >= 30 else "SAFE"))
                    explanation = llm_analysis.explanation
                    scam_category = llm_analysis.scam_category
                    detected_signals = [
                        {
                            "signal": s.signal,
                            "severity": s.severity,
                            "evidence": s.evidence
                        }
                        for s in llm_analysis.detected_signals
                    ]
                except Exception as e:
                    logger.warning(f"Groq LLM analysis fallback for call {call_id}: {e}")

            # Fallback formatting if Groq LLM was unavailable
            if not llm_analysis:
                verdict = "SCAM" if current_score >= 50 else ("WARNING" if current_score >= 30 else "SAFE")
                if hits:
                    explanation = f"Detected high-risk threat indicators: {', '.join(hits)}. Coercion or authority impersonation language matched."
                    scam_category = hits[0]
                    detected_signals = [
                        {
                            "signal": h.category,
                            "severity": "HIGH" if h.weight >= 40 else "MEDIUM",
                            "evidence": h.matched_keyword
                        }
                        for h in rule_result.hits
                    ]
                else:
                    explanation = "Speech transcript analyzed cleanly. No threat triggers or extortion patterns detected."
                    scam_category = "Benign Conversation"
                    detected_signals = []

            # Step 5: Voice Authenticity Check (Deepfake Detection) for high-risk calls
            voice_auth_res = {"is_likely_cloned": None, "confidence": None}
            if current_score >= THREAT_THRESHOLD and self.voice_auth_service:
                try:
                    voice_auth_res = await self.voice_auth_service.check_authenticity(audio_bytes)
                    if voice_auth_res.get("is_likely_cloned") is True:
                        current_score = min(100.0, current_score + 10.0)
                        if "possible_voice_clone" not in hits:
                            hits.append("possible_voice_clone")
                except Exception as e:
                    logger.warning(f"Voice authenticity check failed for call {call_id}: {e}")

            is_alert = current_score >= THREAT_THRESHOLD or verdict == "SCAM"

            return {
                "call_id": call_id,
                "latest_chunk": chunk_text,
                "transcript": updated_transcript,
                "risk_score": current_score,
                "verdict": verdict,
                "alert": is_alert,
                "explanation": explanation,
                "scam_category": scam_category,
                "hits": hits,
                "detected_signals": detected_signals,
                "voice_authenticity": voice_auth_res,
            }

        except Exception as e:
            logger.error(f"Error in CallMonitoringService for call {call_id}: {e}")
            raise e