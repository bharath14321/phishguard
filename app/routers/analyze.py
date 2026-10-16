"""
app/routers/analyze.py

Protected endpoints for artifact analysis (URLs, Hashes, Emails, QR Codes, Files),
as well as user-isolated analysis history, recent analyses, and statistics.
Includes path-traversal protection, upload size limits, and IDOR access control.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app import auth, database, models, schemas
from src.analysis.unified_analyzer import (
    analyze_email as unified_analyze_email,
    analyze_file as unified_analyze_file,
    analyze_hash as unified_analyze_hash,
    analyze_qr as unified_analyze_qr,
    analyze_url as unified_analyze_url,
)

router = APIRouter(prefix="/api/v1/analyze", tags=["analysis"])

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


def _sanitize_filename(filename: Optional[str]) -> str:
    """Sanitize uploaded filenames to prevent path traversal or shell character injection."""
    if not filename:
        return "unnamed_upload.bin"
    # Extract only the base name (strip directory paths)
    base = os.path.basename(filename)
    # Remove null bytes, control characters, and path traversal sequences
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
    cleaned = re.sub(r"\.{2,}", ".", cleaned)  # collapse multiple dots
    if not cleaned or cleaned.startswith("."):
        cleaned = f"upload_{uuid.uuid4().hex[:6]}" + cleaned
    return cleaned[:100]  # limit length


def _check_and_save_upload(file: UploadFile) -> str:
    """Verify file size and safely save upload to a temporary file path."""
    try:
        file.file.seek(0, os.SEEK_END)
        size = file.file.tell()
        file.file.seek(0)
    except Exception:
        size = 0

    if size > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024 * 1024)} MB.",
        )

    safe_name = _sanitize_filename(file.filename)
    tmp_path = f"/tmp/phishguard_{uuid.uuid4().hex}_{safe_name}"

    try:
        with open(tmp_path, "wb") as buffer:
            # Read in chunks to prevent memory spikes
            bytes_read = 0
            while chunk := file.file.read(65536):
                bytes_read += len(chunk)
                if bytes_read > MAX_UPLOAD_SIZE:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Uploaded file exceeds size limit during transfer.",
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as err:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to securely store uploaded file: {str(err)}",
        )

    return tmp_path


def _save_result(
    db: Session,
    user_id: int,
    artifact_type: str,
    identifier: str,
    details: dict,
    risk_score: float,
    risk_level: str,
    explanation: dict,
) -> int:
    analysis = models.AnalysisResult(
        user_id=user_id,
        artifact_type=artifact_type,
        url=str(identifier)[:2048],
        risk_score=float(risk_score),
        risk_level=str(risk_level),
        details=json.dumps(details) if details is not None else None,
        explanation=json.dumps(explanation) if explanation is not None else None,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis.id


# ---------------------------------------------------------------------------
# ANALYSIS ENDPOINTS
# ---------------------------------------------------------------------------

@router.post("/url", response_model=schemas.AnalysisResponse)
def analyze_url_endpoint(
    payload: schemas.URLInput,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Analyze a URL artifact with multi-layer detection and record user-isolated result."""
    url_str = str(payload.url)
    if len(url_str) > 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL exceeds maximum allowed length of 2048 characters.",
        )
    result = unified_analyze_url(url_str, current_user.id)
    analysis_id = _save_result(
        db=db,
        user_id=current_user.id,
        artifact_type="url",
        identifier=url_str,
        details=result.get("details"),
        risk_score=result["risk"]["score"],
        risk_level=result["risk"]["level"],
        explanation=result.get("explanation"),
    )
    result["analysis_id"] = analysis_id
    return result


@router.post("/hash", response_model=schemas.AnalysisResponse)
def analyze_hash_endpoint(
    payload: schemas.HashInput,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Analyze a file hash against threat reputation feeds."""
    clean_hash = payload.hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", clean_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash format. Must be MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex).",
        )
    result = unified_analyze_hash(clean_hash, current_user.id)
    analysis_id = _save_result(
        db=db,
        user_id=current_user.id,
        artifact_type="hash",
        identifier=clean_hash,
        details=result.get("details"),
        risk_score=result["risk"]["score"],
        risk_level=result["risk"]["level"],
        explanation=result.get("explanation"),
    )
    result["analysis_id"] = analysis_id
    return result


@router.post("/email", response_model=schemas.AnalysisResponse)
def analyze_email_endpoint(
    file: UploadFile = File(...),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Analyze an uploaded email file (.eml / .msg) safely."""
    tmp_path = _check_and_save_upload(file)
    try:
        result = unified_analyze_email(tmp_path, current_user.id)
        safe_name = _sanitize_filename(file.filename)
        analysis_id = _save_result(
            db=db,
            user_id=current_user.id,
            artifact_type="email",
            identifier=f"email:{safe_name}",
            details=result.get("details"),
            risk_score=result["risk"]["score"],
            risk_level=result["risk"]["level"],
            explanation=result.get("explanation"),
        )
        result["analysis_id"] = analysis_id
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@router.post("/qr", response_model=schemas.AnalysisResponse)
def analyze_qr_endpoint(
    file: UploadFile = File(...),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Analyze an uploaded QR code image safely."""
    tmp_path = _check_and_save_upload(file)
    try:
        result = unified_analyze_qr(tmp_path, current_user.id)
        safe_name = _sanitize_filename(file.filename)
        analysis_id = _save_result(
            db=db,
            user_id=current_user.id,
            artifact_type="qr",
            identifier=f"qr:{safe_name}",
            details=result.get("details"),
            risk_score=result["risk"]["score"],
            risk_level=result["risk"]["level"],
            explanation=result.get("explanation"),
        )
        result["analysis_id"] = analysis_id
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@router.post("/file", response_model=schemas.AnalysisResponse)
def analyze_file_endpoint(
    file: UploadFile = File(...),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Analyze an uploaded suspicious file statically."""
    tmp_path = _check_and_save_upload(file)
    try:
        result = unified_analyze_file(tmp_path, current_user.id)
        safe_name = _sanitize_filename(file.filename)
        analysis_id = _save_result(
            db=db,
            user_id=current_user.id,
            artifact_type="file",
            identifier=f"file:{safe_name}",
            details=result.get("details"),
            risk_score=result["risk"]["score"],
            risk_level=result["risk"]["level"],
            explanation=result.get("explanation"),
        )
        result["analysis_id"] = analysis_id
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ---------------------------------------------------------------------------
# USER-ISOLATED HISTORY AND STATS ENDPOINTS
# ---------------------------------------------------------------------------

@router.get("/history")
def get_user_history(
    limit: int = 50,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Retrieve analysis history for the current authenticated user only."""
    limit = max(1, min(limit, 100))
    analyses = (
        db.query(models.AnalysisResult)
        .filter(models.AnalysisResult.user_id == current_user.id)
        .order_by(models.AnalysisResult.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": a.id,
            "artifact_type": a.artifact_type,
            "url": a.url,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in analyses
    ]


@router.get("/recent")
def get_user_recent(
    limit: int = 10,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Retrieve recent analyses for the current authenticated user only."""
    return get_user_history(limit=limit, current_user=current_user, db=db)


@router.get("/stats")
def get_user_stats(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Retrieve aggregate statistics for the current authenticated user."""
    analyses = (
        db.query(models.AnalysisResult)
        .filter(models.AnalysisResult.user_id == current_user.id)
        .all()
    )
    total = len(analyses)
    high = sum(1 for a in analyses if a.risk_level in ["HIGH", "CRITICAL"])
    medium = sum(1 for a in analyses if a.risk_level == "MEDIUM")
    low = sum(1 for a in analyses if a.risk_level == "LOW")
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
    }


@router.get("/{analysis_id}")
def get_single_analysis(
    analysis_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Retrieve one specific analysis result with strict authorization check.
    Prevents IDOR: Users can only view their own analysis results.
    """
    analysis = (
        db.query(models.AnalysisResult)
        .filter(models.AnalysisResult.id == analysis_id)
        .first()
    )
    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found.",
        )

    # Multi-tenant IDOR defense
    if analysis.user_id is not None and analysis.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this analysis result.",
        )

    try:
        explanation = json.loads(analysis.explanation) if analysis.explanation else {}
    except Exception:
        explanation = {}

    try:
        details = json.loads(analysis.details) if analysis.details else {}
    except Exception:
        details = {}

    signals = details.get("signals") or explanation.get("signals") or []
    evidence_sufficiency = details.get("evidence_sufficiency")
    if not evidence_sufficiency or not isinstance(evidence_sufficiency, dict):
        try:
            from src.analysis.evidence_sufficiency import compute_evidence_sufficiency
            reconstructed_record = {
                "artifact_type": analysis.artifact_type,
                "url": analysis.url,
                "risk": {"score": analysis.risk_score, "level": analysis.risk_level},
                "signals": signals,
                "details": details,
                "explanation": explanation,
            }
            suff = compute_evidence_sufficiency(reconstructed_record)
            evidence_sufficiency = {
                "score": suff.score,
                "level": suff.level.value,
                "evidence_classes": suff.evidence_classes_present,
                "signals_count": suff.signals_count,
                "has_contradiction": suff.has_contradiction,
                "contradictions": suff.contradictions,
            }
        except Exception:
            evidence_sufficiency = {
                "score": 0.0,
                "level": "INSUFFICIENT",
                "evidence_classes": [],
                "signals_count": len(signals),
                "has_contradiction": False,
                "contradictions": [],
            }

    ai_analyst = details.get("ai_analyst") or {
        "status": "UNCONFIGURED",
        "message": "Google Gemini API key not configured. Set GEMINI_API_KEY in backend environment to enable generative AI security analysis.",
        "provider": "security_analyst",
        "evaluation": None,
    }

    return {
        "analysis_id": analysis.id,
        "artifact_type": analysis.artifact_type,
        "url": analysis.url,
        "risk": {
            "score": analysis.risk_score,
            "level": analysis.risk_level,
        },
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "signals": signals,
        "evidence_sufficiency": evidence_sufficiency,
        "ai_analyst": ai_analyst,
        "details": details,
        "explanation": explanation,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
    }
