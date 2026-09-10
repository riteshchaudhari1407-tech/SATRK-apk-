"""
Pydantic schemas for the /api/analyze and /api/analyze-image endpoints.

`LLMAnalysisPayload` is the strict schema the Groq LLM's JSON output is
validated against before anything from it is trusted. `AnalysisResponse`
is the final, honest response shape returned to the frontend — it always
states which engines actually ran.
"""

from typing import List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Severity = Literal["LOW", "MEDIUM", "HIGH"]
InputType = Literal["text", "image"]


class AnalyzeTextRequest(BaseModel):
    text: Optional[str] = None
    message: Optional[str] = None

    @model_validator(mode="after")
    def validate_text_or_message(self) -> "AnalyzeTextRequest":
        raw = (self.text or self.message or "").strip()
        if not raw:
            raise ValueError("text or message cannot be empty or whitespace only.")
        if len(raw) > 4000:
            raise ValueError("Text exceeds maximum allowed length of 4000 characters.")
        self.text = raw
        return self


class DetectedSignal(BaseModel):
    signal: str
    severity: Severity
    evidence: str


class LLMAnalysisPayload(BaseModel):
    """Strict schema the raw Groq JSON output must satisfy. Anything that
    doesn't validate against this is treated as an invalid LLM response,
    never silently coerced into a fake result."""

    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    is_scam: bool
    verdict: Optional[str] = "SAFE"
    confidence: float = Field(..., ge=0, le=1)
    scam_category: str
    detected_signals: List[DetectedSignal] = Field(default_factory=list)
    explanation: str
    recommended_actions: List[str] = Field(default_factory=list)


class SemanticSignal(BaseModel):
    category: str
    similarity: float


class AnalysisResponse(BaseModel):
    success: bool
    analysis_available: bool

    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    input_type: InputType = "text"

    analysis_engines_used: List[str] = Field(default_factory=list)
    analysis_engines_unavailable: List[str] = Field(default_factory=list)

    risk_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    is_scam: Optional[bool] = None
    confidence: Optional[float] = None
    scam_category: Optional[str] = None

    detected_signals: List[DetectedSignal] = Field(default_factory=list)
    semantic_signals: List[SemanticSignal] = Field(default_factory=list)

    explanation: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)

    extracted_text: Optional[str] = None

    error: Optional[str] = None


class LinkAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL string to analyze for threats")


class LinkAnalysisResponse(BaseModel):
    url: str
    is_safe: bool
    threat_types: List[str] = Field(default_factory=list)
    details: str


class FeedbackRequest(BaseModel):
    call_id: str
    alert_was_correct: bool
    transcript_snippet: str


class FeedbackResponse(BaseModel):
    status: str = "success"
    message: str
    call_id: str
