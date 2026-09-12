from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.container import scam_registry

router = APIRouter(prefix="/api/v1/community", tags=["community"])

class ReportRequest(BaseModel):
    identifier: str = Field(..., description="The value to report (e.g., UPI ID, Mobile Number, Bank Account)")
    id_type: str = Field(..., description="The type of identifier (e.g., upi, mobile, account)")
    note: str = Field("", description="Optional contextual note about the scam")

class ReportResponse(BaseModel):
    status: str
    message: str

class CheckResponse(BaseModel):
    identifier: str
    reported: bool
    risk_boost: int
    reports_count: int
    reason: str

@router.post("/report", response_model=ReportResponse, operation_id="report_scam_identifier")
def report_identifier(payload: ReportRequest):
    """
    Submit a crowdsourced scam report for a specific identifier.
    """
    try:
        scam_registry.report_identifier(
            identifier=payload.identifier,
            id_type=payload.id_type,
            note=payload.note
        )
        return ReportResponse(
            status="success",
            message=f"Identifier {payload.identifier} successfully reported."
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to report identifier: {str(exc)}"
        )

@router.get("/check/{identifier}", response_model=CheckResponse, operation_id="check_scam_identifier")
def check_identifier(identifier: str):
    """
    Check if an identifier exists in the crowdsourced scam registry.
    """
    try:
        result = scam_registry.check_identifier(identifier)
        return CheckResponse(
            identifier=identifier,
            reported=result["reported"],
            risk_boost=result["risk_boost"],
            reports_count=result.get("reports_count", 0),
            reason=result["reason"]
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to check identifier: {str(exc)}"
        )
