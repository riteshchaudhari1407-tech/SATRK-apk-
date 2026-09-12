import asyncio
import logging
from typing import Dict, Any, List, Optional, Union
from app.services.stt_service import STTService
from app.services.rule_engine_service import RuleEngineService
from app.services.groq_service import GroqService
from app.services.voice_authenticity_service import VoiceAuthenticityService

from app.services.vision_service import VisionService

logger = logging.getLogger("satrk.call_monitoring")

THREAT_THRESHOLD = 50.0  # Risk score threshold for critical alert
MAX_AI_TIMEOUT = 3.5     # Strict 3.5s timeout for Groq LLM, Voice Auth & Vision calls


class CallMonitoringService:
    def __init__(
        self,
        stt_service: STTService,
        rule_engine: RuleEngineService,
        groq_service: GroqService,
        voice_auth_service: Optional[VoiceAuthenticityService] = None,
        vision_service: Optional[VisionService] = None,
        **kwargs,
    ):
        self.stt_service = stt_service
        self.rule_engine = rule_engine
        self.groq_service = groq_service
        self.voice_auth_service = voice_auth_service
        self.vision_service = vision_service
        self.financial_scanner = kwargs.get("financial_scanner")
        self.scam_registry = kwargs.get("scam_registry")
        self.call_transcripts: Dict[str, str] = {}
        self.call_frames: Dict[str, Union[bytes, str]] = {}

    def set_call_frame(self, call_id: str, frame: Union[bytes, str]):
        """Cache latest frame screenshot for call session."""
        self.call_frames[call_id] = frame

    async def process_audio_chunk(
        self, call_id: str, audio_bytes: bytes, video_frame: Optional[Union[bytes, str]] = None
    ) -> Dict[str, Any]:
        """
        Processes audio chunk through STT -> Rule Engine -> Groq LLM & Voice Authenticity & Vision Analysis.
        Generates percentage risk score, definitive verdict (SAFE/WARNING/SCAM),
        AI Threat Explanation breakdown, deepfake voice detection, and screen/video scam detection.
        """
        try:
            if video_frame:
                self.call_frames[call_id] = video_frame

            frame_to_analyze = video_frame or self.call_frames.get(call_id)

            # Step 1: Transcribe/Translate audio chunk asynchronously
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
                vision_res = {
                    "threat_detected": False,
                    "confidence": 0.0,
                    "threat_type": "SAFE",
                    "analysis_details": "No active video stream threat detected.",
                }

                if frame_to_analyze and self.vision_service:
                    try:
                        vision_res = await asyncio.wait_for(
                            self.vision_service.analyze(frame_to_analyze, context=existing_transcript),
                            timeout=MAX_AI_TIMEOUT
                        )
                        if vision_res.get("threat_detected"):
                            current_score = max(current_score, 85.0)
                            verdict = "SCAM"
                            hits.append(f"vision_{vision_res.get('threat_type', 'scam').lower()}")
                    except Exception as e:
                        logger.warning(f"Vision analysis timeout/skipped for call {call_id}: {e}")

                if current_score >= THREAT_THRESHOLD and self.voice_auth_service:
                    try:
                        voice_auth_res = await asyncio.wait_for(
                            self.voice_auth_service.check_authenticity(audio_bytes),
                            timeout=MAX_AI_TIMEOUT
                        )
                        if voice_auth_res.get("is_likely_cloned") is True:
                            current_score = min(100.0, current_score + 10.0)
                            if "possible_voice_clone" not in hits:
                                hits.append("possible_voice_clone")
                    except Exception as e:
                        logger.warning(f"Voice authenticity check timeout/skipped for call {call_id}: {e}")

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
                    "vision_analysis": vision_res,
                }

            # Step 2: Append to call transcript buffer
            updated_transcript = f"{existing_transcript} {chunk_text}".strip()
            self.call_transcripts[call_id] = updated_transcript

            # Step 3: Run Rule Engine Analysis
            rule_result = self.rule_engine.analyze(updated_transcript)
            current_score = rule_result.score
            hits = [h.category for h in rule_result.hits]

            # Step 4: Determine concurrency triggers
            should_run_llm = (current_score > 0 or len(updated_transcript) >= 15) and self.groq_service.client_ready
            should_run_voice_auth = (current_score >= THREAT_THRESHOLD) and (self.voice_auth_service is not None)
            should_run_vision = (
                (frame_to_analyze is not None) or (current_score >= 75.0 and frame_to_analyze is not None)
            ) and (self.vision_service is not None)

            llm_coro = asyncio.wait_for(self.groq_service.analyze(updated_transcript), timeout=MAX_AI_TIMEOUT) if should_run_llm else None
            voice_auth_coro = asyncio.wait_for(self.voice_auth_service.check_authenticity(audio_bytes), timeout=MAX_AI_TIMEOUT) if should_run_voice_auth else None
            vision_coro = asyncio.wait_for(self.vision_service.analyze(frame_to_analyze, context=updated_transcript), timeout=MAX_AI_TIMEOUT) if should_run_vision else None

            # Schedule tasks concurrently with asyncio.gather
            llm_result = None
            voice_auth_res = {"is_likely_cloned": None, "confidence": None}
            vision_res = {
                "threat_detected": False,
                "confidence": 0.0,
                "threat_type": "SAFE",
                "analysis_details": "No active visual threat detected.",
            }

            coros = [c for c in [llm_coro, voice_auth_coro, vision_coro] if c is not None]
            if coros:
                results = await asyncio.gather(*coros, return_exceptions=True)
                res_idx = 0
                if llm_coro:
                    res = results[res_idx]
                    res_idx += 1
                    if not isinstance(res, Exception):
                        llm_result = res
                    else:
                        logger.warning(f"Groq LLM analysis error/timeout for call {call_id}: {res}")
                if voice_auth_coro:
                    res = results[res_idx]
                    res_idx += 1
                    if not isinstance(res, Exception) and isinstance(res, dict):
                        voice_auth_res = res
                    else:
                        logger.warning(f"Voice auth check error/timeout for call {call_id}: {res}")
                if vision_coro:
                    res = results[res_idx]
                    res_idx += 1
                    if not isinstance(res, Exception) and isinstance(res, dict):
                        vision_res = res
                    else:
                        logger.warning(f"Vision analysis error/timeout for call {call_id}: {res}")

            # Process LLM & Vision Results
            explanation = ""
            scam_category = "None detected"
            detected_signals = []
            verdict = "SAFE"

            if llm_result:
                current_score = max(current_score, float(llm_result.risk_score))
                verdict = getattr(llm_result, 'verdict', None) or ("SCAM" if current_score >= 50 else ("WARNING" if current_score >= 30 else "SAFE"))
                explanation = llm_result.explanation
                scam_category = llm_result.scam_category
                detected_signals = [
                    {
                        "signal": s.signal,
                        "severity": s.severity,
                        "evidence": s.evidence
                    }
                    for s in llm_result.detected_signals
                ]
            else:
                verdict = "SCAM" if current_score >= 50 else ("WARNING" if current_score >= 30 else "SAFE")
                if hits:
                    explanation = f"Detected threat indicators: {', '.join(hits)}. Coercion or authority impersonation language matched."
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

            # Adjust score if deepfake voice or visual scam detected
            if voice_auth_res.get("is_likely_cloned") is True:
                current_score = min(100.0, current_score + 10.0)
                if "possible_voice_clone" not in hits:
                    hits.append("possible_voice_clone")

            if vision_res.get("threat_detected"):
                current_score = max(current_score, 88.0)
                verdict = "SCAM"
                threat_tag = f"visual_{vision_res.get('threat_type', 'SCAM').lower()}"
                if threat_tag not in hits:
                    hits.append(threat_tag)
                explanation += f" [VISUAL THREAT DETECTED: {vision_res.get('analysis_details', '')}]"

            # --- Financial Scanner & Scam Registry (Zero Fabrication) ---
            fin_risk = 0
            scam_risk = 0
            fin_reasons = []
            if getattr(self, "financial_scanner", None):
                fin_result = self.financial_scanner.scan_text(updated_transcript)
                if fin_result:
                    fin_risk = fin_result.get("risk_contribution", 0)
                    fin_reasons = fin_result.get("reasons", [])
                    
                    if getattr(self, "scam_registry", None):
                        for id_obj in fin_result.get("identifiers", []):
                            reg_check = self.scam_registry.check_identifier(id_obj["value"])
                            if reg_check["reported"]:
                                scam_risk = max(scam_risk, reg_check["risk_boost"])
                                fin_reasons.append(reg_check["reason"])
            
            if fin_risk > 0 or scam_risk > 0:
                current_score = min(100.0, current_score + fin_risk + scam_risk)
                explanation += f" Financial/Registry Indicators: {', '.join(fin_reasons)}."
                for reason in fin_reasons:
                    detected_signals.append({
                        "signal": "financial_or_scam_registry",
                        "severity": "HIGH" if scam_risk > 0 else "MEDIUM",
                        "evidence": reason
                    })

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
                "vision_analysis": vision_res,
            }

        except Exception as e:
            logger.error(f"Error in CallMonitoringService for call {call_id}: {e}")
            raise e