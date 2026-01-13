"""
False Positive Management Router

API endpoints for:
- Marking findings as false positives with feedback
- Re-verifying findings
- Getting verification status
- Bulk operations
- Feedback statistics
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.auth import get_current_user
from backend.models.models import Finding, User
from backend.services.false_positive_engine import (
    FalsePositiveEngine,
    FPVerificationResult,
    verify_findings_batch,
    ConfidenceLevel,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/fp-management", tags=["False Positive Management"])

# Global engine instance
_fp_engine: Optional[FalsePositiveEngine] = None


def get_fp_engine() -> FalsePositiveEngine:
    """Get or create the false positive engine instance."""
    global _fp_engine
    if _fp_engine is None:
        _fp_engine = FalsePositiveEngine()
    return _fp_engine


# =============================================================================
# Request/Response Models
# =============================================================================

class MarkFalsePositiveRequest(BaseModel):
    finding_id: int
    reason: str
    context: Optional[dict] = None


class BulkMarkFPRequest(BaseModel):
    finding_ids: List[int]
    reason: str


class VerifyFindingRequest(BaseModel):
    finding_id: int
    endpoint: Optional[str] = None
    method: Optional[str] = "GET"
    param_name: Optional[str] = None
    headers: Optional[dict] = None
    enable_active_validation: bool = False


class BulkVerifyRequest(BaseModel):
    finding_ids: List[int]


class VerificationResponse(BaseModel):
    finding_id: int
    original_confidence: float
    final_confidence: float
    confidence_level: str
    is_false_positive: bool
    recommendation: str
    evidence_summary: str
    verification_time_ms: int


class FeedbackStatsResponse(BaseModel):
    total_feedback: int
    false_positives_marked: int
    true_positives_marked: int
    learned_patterns: int
    top_fp_patterns: List[tuple]
    top_tp_patterns: List[tuple]


class FindingUpdateResponse(BaseModel):
    finding_id: int
    updated: bool
    message: str
    new_status: Optional[str] = None


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/mark-false-positive", response_model=FindingUpdateResponse)
async def mark_false_positive(
    request: MarkFalsePositiveRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Mark a finding as a false positive.
    Records user feedback for learning.
    """
    finding = db.query(Finding).filter(Finding.id == request.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Update finding
    finding.is_false_positive = True
    finding.false_positive_reason = request.reason
    finding.marked_false_positive_at = datetime.utcnow()
    finding.marked_false_positive_by = current_user.id
    
    # Update details with FP info
    details = finding.details or {}
    details["false_positive_feedback"] = {
        "reason": request.reason,
        "marked_by": current_user.username,
        "marked_at": datetime.utcnow().isoformat(),
        "context": request.context,
    }
    finding.details = details
    
    db.commit()
    
    # Record feedback in engine for learning (background)
    def record_feedback():
        engine = get_fp_engine()
        finding_dict = {
            "id": finding.id,
            "type": finding.type,
            "severity": finding.severity,
            "summary": finding.summary,
            "file_path": finding.file_path,
            "details": finding.details,
        }
        engine.record_user_feedback(
            finding_id=finding.id,
            marked_as="false_positive",
            reason=request.reason,
            finding_details=finding_dict
        )
    
    background_tasks.add_task(record_feedback)
    
    logger.info(f"Finding {request.finding_id} marked as false positive by {current_user.username}")
    
    return FindingUpdateResponse(
        finding_id=request.finding_id,
        updated=True,
        message="Finding marked as false positive",
        new_status="false_positive"
    )


@router.post("/unmark-false-positive", response_model=FindingUpdateResponse)
async def unmark_false_positive(
    finding_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Unmark a finding as false positive (mark as true positive).
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding.is_false_positive = False
    finding.false_positive_reason = None
    finding.marked_false_positive_at = None
    finding.marked_false_positive_by = None
    
    # Update details
    details = finding.details or {}
    details["false_positive_feedback"] = None
    details["unmarked_by"] = current_user.username
    details["unmarked_at"] = datetime.utcnow().isoformat()
    finding.details = details
    
    db.commit()
    
    # Record feedback
    def record_feedback():
        engine = get_fp_engine()
        finding_dict = {
            "id": finding.id,
            "type": finding.type,
            "severity": finding.severity,
            "summary": finding.summary,
            "file_path": finding.file_path,
            "details": finding.details,
        }
        engine.record_user_feedback(
            finding_id=finding.id,
            marked_as="true_positive",
            reason="Unmarked as false positive",
            finding_details=finding_dict
        )
    
    background_tasks.add_task(record_feedback)
    
    logger.info(f"Finding {finding_id} unmarked as false positive by {current_user.username}")
    
    return FindingUpdateResponse(
        finding_id=finding_id,
        updated=True,
        message="Finding unmarked as false positive",
        new_status="active"
    )


@router.post("/bulk-mark-fp", response_model=List[FindingUpdateResponse])
async def bulk_mark_false_positive(
    request: BulkMarkFPRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Mark multiple findings as false positives.
    """
    results = []
    
    findings = db.query(Finding).filter(Finding.id.in_(request.finding_ids)).all()
    found_ids = {f.id for f in findings}
    
    for finding in findings:
        finding.is_false_positive = True
        finding.false_positive_reason = request.reason
        finding.marked_false_positive_at = datetime.utcnow()
        finding.marked_false_positive_by = current_user.id
        
        details = finding.details or {}
        details["false_positive_feedback"] = {
            "reason": request.reason,
            "marked_by": current_user.username,
            "marked_at": datetime.utcnow().isoformat(),
            "bulk_operation": True,
        }
        finding.details = details
        
        results.append(FindingUpdateResponse(
            finding_id=finding.id,
            updated=True,
            message="Marked as false positive",
            new_status="false_positive"
        ))
    
    # Add not found results
    for fid in request.finding_ids:
        if fid not in found_ids:
            results.append(FindingUpdateResponse(
                finding_id=fid,
                updated=False,
                message="Finding not found"
            ))
    
    db.commit()
    
    logger.info(f"Bulk marked {len(findings)} findings as false positive by {current_user.username}")
    
    return results


@router.post("/verify", response_model=VerificationResponse)
async def verify_finding(
    request: VerifyFindingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Re-verify a finding using the false positive engine.
    """
    finding = db.query(Finding).filter(Finding.id == request.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    engine = get_fp_engine()
    
    # Build finding dict
    finding_dict = {
        "id": finding.id,
        "type": finding.type,
        "severity": finding.severity,
        "summary": finding.summary,
        "file_path": finding.file_path,
        "start_line": finding.start_line,
        "details": finding.details or {},
        "payload": finding.details.get("payload") if finding.details else None,
    }
    
    # Run verification
    result = await engine.verify_finding(
        finding=finding_dict,
        endpoint=request.endpoint,
        method=request.method or "GET",
        param_name=request.param_name,
        headers=request.headers,
        enable_active_validation=request.enable_active_validation,
    )
    
    # Update finding with verification results
    details = finding.details or {}
    details["last_verification"] = {
        "timestamp": datetime.utcnow().isoformat(),
        "confidence": result.final_confidence,
        "confidence_level": result.confidence_level.value,
        "is_false_positive": result.is_false_positive,
        "recommendation": result.recommendation,
        "evidence_summary": result.evidence_summary,
        "validation_results": [
            {
                "method": v.method.value,
                "passed": v.passed,
                "confidence_delta": v.confidence_delta,
                "evidence": v.evidence,
            }
            for v in result.validation_results
        ],
    }
    finding.details = details
    
    # Update confidence if significantly different
    if abs((finding.details.get("confidence", 0.5) if finding.details else 0.5) - result.final_confidence) > 0.1:
        details["confidence"] = result.final_confidence
        finding.details = details
    
    # Auto-mark as FP if engine is confident
    if result.is_false_positive and result.final_confidence < 0.3:
        finding.is_false_positive = True
        finding.false_positive_reason = f"Auto-detected: {result.recommendation}"
        finding.marked_false_positive_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"Finding {request.finding_id} verified: {result.confidence_level.value}")
    
    return VerificationResponse(
        finding_id=result.finding_id,
        original_confidence=result.original_confidence,
        final_confidence=result.final_confidence,
        confidence_level=result.confidence_level.value,
        is_false_positive=result.is_false_positive,
        recommendation=result.recommendation,
        evidence_summary=result.evidence_summary,
        verification_time_ms=result.verification_time_ms,
    )


@router.post("/bulk-verify", response_model=List[VerificationResponse])
async def bulk_verify_findings(
    request: BulkVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify multiple findings in parallel.
    """
    findings = db.query(Finding).filter(Finding.id.in_(request.finding_ids)).all()
    
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")
    
    # Build finding dicts
    finding_dicts = [
        {
            "id": f.id,
            "type": f.type,
            "severity": f.severity,
            "summary": f.summary,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "details": f.details or {},
        }
        for f in findings
    ]
    
    # Run batch verification
    engine = get_fp_engine()
    results = await verify_findings_batch(finding_dicts, engine)
    
    # Update findings
    for result in results:
        finding = next((f for f in findings if f.id == result.finding_id), None)
        if finding:
            details = finding.details or {}
            details["last_verification"] = {
                "timestamp": datetime.utcnow().isoformat(),
                "confidence": result.final_confidence,
                "confidence_level": result.confidence_level.value,
                "is_false_positive": result.is_false_positive,
            }
            finding.details = details
    
    db.commit()
    
    return [
        VerificationResponse(
            finding_id=r.finding_id,
            original_confidence=r.original_confidence,
            final_confidence=r.final_confidence,
            confidence_level=r.confidence_level.value,
            is_false_positive=r.is_false_positive,
            recommendation=r.recommendation,
            evidence_summary=r.evidence_summary,
            verification_time_ms=r.verification_time_ms,
        )
        for r in results
    ]


@router.get("/feedback-stats", response_model=FeedbackStatsResponse)
async def get_feedback_statistics(
    current_user: User = Depends(get_current_user),
):
    """
    Get statistics about user feedback and learned patterns.
    """
    engine = get_fp_engine()
    stats = engine.get_feedback_stats()
    
    return FeedbackStatsResponse(
        total_feedback=stats.get("total_feedback", 0),
        false_positives_marked=stats.get("false_positives_marked", 0),
        true_positives_marked=stats.get("true_positives_marked", 0),
        learned_patterns=stats.get("learned_patterns", 0),
        top_fp_patterns=stats.get("top_fp_patterns", []),
        top_tp_patterns=stats.get("top_tp_patterns", []),
    )


@router.get("/finding/{finding_id}/verification-history")
async def get_verification_history(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get the verification history for a finding.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    details = finding.details or {}
    history = details.get("verification_history", [])
    last_verification = details.get("last_verification")
    
    return {
        "finding_id": finding_id,
        "current_status": "false_positive" if finding.is_false_positive else "active",
        "last_verification": last_verification,
        "history": history,
    }


@router.get("/statistics/by-project/{project_id}")
async def get_project_fp_statistics(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get false positive statistics for a project.
    """
    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    
    total = len(findings)
    false_positives = sum(1 for f in findings if f.is_false_positive)
    
    # By severity
    by_severity = {}
    for severity in ["critical", "high", "medium", "low"]:
        sev_findings = [f for f in findings if f.severity == severity]
        sev_fps = [f for f in sev_findings if f.is_false_positive]
        by_severity[severity] = {
            "total": len(sev_findings),
            "false_positives": len(sev_fps),
            "fp_rate": len(sev_fps) / len(sev_findings) if sev_findings else 0,
        }
    
    # By type
    by_type = {}
    types = set(f.type for f in findings)
    for ftype in types:
        type_findings = [f for f in findings if f.type == ftype]
        type_fps = [f for f in type_findings if f.is_false_positive]
        by_type[ftype] = {
            "total": len(type_findings),
            "false_positives": len(type_fps),
            "fp_rate": len(type_fps) / len(type_findings) if type_findings else 0,
        }
    
    return {
        "project_id": project_id,
        "total_findings": total,
        "false_positives": false_positives,
        "fp_rate": false_positives / total if total else 0,
        "by_severity": by_severity,
        "by_type": by_type,
    }
