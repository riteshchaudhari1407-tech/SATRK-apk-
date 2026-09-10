"""
Analysis Service (Layer D — Risk Aggregation + Orchestration)
--------------------------------------------------------------
This is the single place where the three analysis layers are
combined into one honest, explainable result:

  Layer A — semantic_service   (embedding-based context understanding)
  Layer B — groq_service       (LLM contextual reasoning)
  Layer C — technical_signals  (regex-based supporting evidence only)

Aggregation strategy (documented, deterministic — NOT a random or
hardcoded fixed score):

  Each of Layer A and Layer B produces a 0-100 score. Layer C produces
  a small, hard-capped 0-20 boost, rescaled to 0-100 for consistent
  weighting. The three are combined with fixed base weights:

      Groq (Layer B):        0.90
      Semantic (Layer A):     0.05
      Technical (Layer C):    0.05

  If one engine is unavailable for this request, its weight is
  dropped and the remaining weights are renormalized to sum to 1.0 —
  so the result is always a fair weighted average of whatever
  actually ran, never a fixed/fake number.

  If NEITHER Groq nor the semantic engine is available, no score is
  fabricated: the service returns success=False /
  analysis_available=False with an honest error message (see
  requirement: never pretend an unavailable engine analyzed the text).
"""

import logging
from typing import List, Optional

from app.schemas.analysis import (
    AnalysisResponse,
    DetectedSignal,
    LLMAnalysisPayload,
    SemanticSignal,
)
from app.services.groq_service import GroqService, GroqServiceError
from app.services.ocr_service import OCRError, OCRService
from app.services.semantic_service import SemanticService
from app.utils.technical_signals import (
    MAX_TECHNICAL_CONTRIBUTION,
    extract_technical_signals,
    technical_score,
)

logger = logging.getLogger("satrk.analysis")

WEIGHT_GROQ = 0.90
WEIGHT_SEMANTIC = 0.05
WEIGHT_TECHNICAL = 0.05


def _risk_level_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _severity_from_similarity(similarity: float) -> str:
    if similarity >= 70:
        return "HIGH"
    if similarity >= 40:
        return "MEDIUM"
    return "LOW"


class AnalysisService:
    def __init__(
        self,
        groq_service: GroqService,
        semantic_service: SemanticService,
        ocr_service: OCRService,
    ):
        self.groq_service = groq_service
        self.semantic_service = semantic_service
        self.ocr_service = ocr_service

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def analyze_text(self, text: str) -> AnalysisResponse:
        return await self._run_pipeline(text, input_type="text")

    async def analyze_image(self, image_bytes: bytes) -> AnalysisResponse:
        try:
            extracted_text = self.ocr_service.extract_text(image_bytes)
        except OCRError as exc:
            return AnalysisResponse(
                success=False,
                analysis_available=False,
                input_type="image",
                analysis_engines_used=[],
                analysis_engines_unavailable=["ocr"],
                error=str(exc),
            )

        response = await self._run_pipeline(extracted_text, input_type="image")
        response.extracted_text = extracted_text
        return response

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def _run_pipeline(self, text: str, input_type: str) -> AnalysisResponse:
        # Layer C — technical signals (always runs, always supporting only)
        tech_signals = extract_technical_signals(text)
        tech_raw = technical_score(tech_signals)
        tech_rescaled = (tech_raw / MAX_TECHNICAL_CONTRIBUTION) * 100

        # Layer A — semantic understanding
        semantic_result = self.semantic_service.analyze(text)
        semantic_available = semantic_result["available"]
        semantic_score = semantic_result["semantic_score"]
        semantic_categories = semantic_result["matched_categories"]

        # Layer B — Groq LLM
        groq_payload: Optional[LLMAnalysisPayload] = None
        groq_error: Optional[str] = None

        try:
            groq_payload = await self.groq_service.analyze(text)
        except GroqServiceError as exc:
            groq_error = str(exc)
            logger.info("Groq unavailable for this request: %s", exc)

        engines_used: List[str] = []
        engines_unavailable: List[str] = []

        if groq_payload is not None:
            engines_used.append("groq")
        else:
            engines_unavailable.append("groq")

        if semantic_available:
            engines_used.append("semantic_ai")
        else:
            engines_unavailable.append("semantic_ai")

        # --- Neither core AI engine available: be honest, don't fake it ---
        if groq_payload is None and not semantic_available:
            return AnalysisResponse(
                success=False,
                analysis_available=False,
                input_type=input_type,
                analysis_engines_used=[],
                analysis_engines_unavailable=["groq", "semantic_ai"],
                error=(
                    "No AI analysis engine is currently available. "
                    f"Groq error: {groq_error or 'not configured'}. "
                    "Semantic AI failed to load on the server."
                ),
            )

        # --- Weighted, renormalized aggregation ---
        weighted_sum = 0.0
        weight_total = 0.0

        if groq_payload is not None:
            weighted_sum += groq_payload.risk_score * WEIGHT_GROQ
            weight_total += WEIGHT_GROQ

        if semantic_available:
            weighted_sum += semantic_score * WEIGHT_SEMANTIC
            weight_total += WEIGHT_SEMANTIC

        # Technical layer always contributes if it detected anything,
        # renormalized alongside whichever core engines are present.
        weighted_sum += tech_rescaled * WEIGHT_TECHNICAL
        weight_total += WEIGHT_TECHNICAL

        final_score = round(weighted_sum / weight_total, 1) if weight_total else 0.0
        final_score = max(0.0, min(100.0, final_score))

        risk_level = _risk_level_from_score(final_score)

        # --- is_scam / confidence / category ---
        if groq_payload is not None:
            is_scam = groq_payload.is_scam
            confidence = groq_payload.confidence
            scam_category = groq_payload.scam_category
        else:
            is_scam = final_score >= 50
            top_similarity = (
                semantic_categories[0]["similarity"] if semantic_categories else 0
            )
            # Confidence derived from actual similarity strength and
            # number of agreeing categories — not a placeholder value.
            confidence = round(
                min(
                    0.9,
                    0.35
                    + (top_similarity / 100) * 0.4
                    + min(len(semantic_categories), 3) * 0.03,
                ),
                2,
            )
            scam_category = (
                semantic_categories[0]["category"]
                if semantic_categories
                else "None detected"
            )

        # --- Combine detected signals from every available layer ---
        detected_signals: List[DetectedSignal] = []
        seen_signal_names = set()

        if groq_payload is not None:
            for sig in groq_payload.detected_signals:
                if sig.signal not in seen_signal_names:
                    detected_signals.append(sig)
                    seen_signal_names.add(sig.signal)

        for category in semantic_categories:
            name = category["category"]
            if name in seen_signal_names:
                continue
            detected_signals.append(
                DetectedSignal(
                    signal=name,
                    severity=_severity_from_similarity(category["similarity"]),
                    evidence=(
                        f"Semantic similarity of {category['similarity']}% to "
                        f"known '{name}' language patterns."
                    ),
                )
            )
            seen_signal_names.add(name)

        for tech_sig in tech_signals:
            if tech_sig["signal"] in seen_signal_names:
                continue
            detected_signals.append(
                DetectedSignal(
                    signal=tech_sig["signal"],
                    severity=tech_sig["severity"],
                    evidence=tech_sig["evidence"],
                )
            )
            seen_signal_names.add(tech_sig["signal"])

        semantic_signals = [
            SemanticSignal(category=c["category"], similarity=c["similarity"])
            for c in semantic_categories
        ]

        # --- Explanation ---
        if groq_payload is not None:
            explanation = groq_payload.explanation
            if not semantic_available:
                explanation += (
                    " (Note: the semantic understanding layer was "
                    "unavailable for this request, so this assessment "
                    "relies on the LLM and technical signal layers only.)"
                )
        else:
            explanation = self._build_fallback_explanation(
                final_score, risk_level, semantic_categories, tech_signals
            )

        # --- Recommended actions ---
        if groq_payload is not None:
            recommended_actions = groq_payload.recommended_actions
        else:
            recommended_actions = self._default_recommended_actions(risk_level)

        return AnalysisResponse(
            success=True,
            analysis_available=True,
            input_type=input_type,
            analysis_engines_used=engines_used,
            analysis_engines_unavailable=engines_unavailable,
            risk_score=round(final_score),
            risk_level=risk_level,
            is_scam=is_scam,
            confidence=confidence,
            scam_category=scam_category,
            detected_signals=detected_signals,
            semantic_signals=semantic_signals,
            explanation=explanation,
            recommended_actions=recommended_actions,
        )

    # ------------------------------------------------------------------
    # Fallback text generation (used only when Groq is unavailable)
    # ------------------------------------------------------------------

    def _build_fallback_explanation(
        self, score: float, risk_level: str, semantic_categories, tech_signals
    ) -> str:
        if not semantic_categories and not tech_signals:
            return (
                f"No significant scam patterns were detected by the semantic "
                f"understanding or technical signal layers. Risk score: "
                f"{round(score)}% ({risk_level}). Note: the Groq LLM layer "
                f"was unavailable for this request, so this assessment "
                f"relies on semantic pattern matching only."
            )

        parts = [
            f"Risk score {round(score)}% ({risk_level}), based on semantic "
            f"pattern matching and technical signal detection. The Groq LLM "
            f"layer was unavailable for this request."
        ]

        if semantic_categories:
            cat_list = ", ".join(
                f"{c['category']} ({c['similarity']}% similarity)"
                for c in semantic_categories[:3]
            )
            parts.append(f"Semantic layer matched: {cat_list}.")

        if tech_signals:
            tech_list = ", ".join(sig["signal"] for sig in tech_signals)
            parts.append(f"Technical layer flagged: {tech_list}.")

        return " ".join(parts)

    def _default_recommended_actions(self, risk_level: str) -> List[str]:
        if risk_level in ("HIGH", "CRITICAL"):
            return [
                "Do not share OTPs, passwords, or banking details.",
                "Do not make any payment or transfer money.",
                "Do not stay on a video call under pressure or isolation.",
                "Verify the sender independently through official channels.",
                "Report to India's National Cyber Crime Helpline: 1930 or cybercrime.gov.in.",
            ]
        if risk_level == "MEDIUM":
            return [
                "Verify the sender independently before taking any action.",
                "Do not click any links or share sensitive information yet.",
            ]
        return [
            "No immediate action needed, but stay cautious with unexpected requests for money or personal details.",
        ]
