"""
app/routers/chat.py

Protected API endpoints for the AI Security Analyst chat assistant.
Requires authentication and provides multi-tenant access controls on analysis contexts.

Architecture:
- When analysis_id is provided, builds AUTHORITATIVE context server-side.
- Frontend-supplied analysis_context is treated as UNTRUSTED supplementary data.
- Server-side evidence ALWAYS takes precedence over frontend-supplied context.
- Uses the two-context architecture (structured evidence + relevant raw artifact).
"""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import auth, database, models, schemas
from src.analysis.security_chat import process_chat_message
from src.analysis.analyst_context import (
    build_structured_evidence,
    get_suggested_questions,
)

router = APIRouter(prefix="/api/v1/chat", tags=["chat"])

MAX_CONTEXT_SIZE_BYTES = 200_000  # 200 KB limit for inline context payloads

import threading
import time

# In-memory sliding window deduplication cache: (user_id, analysis_id, clean_msg) -> (timestamp, result)
_CHAT_DEDUPLICATION_CACHE: Dict[Any, Tuple[float, Dict[str, Any]]] = {}
_DEDUP_LOCK = threading.Lock()
_DEDUP_WINDOW_SECONDS = 5.0


@router.post("", response_model=schemas.ChatResponse)
def security_analyst_chat_endpoint(
    payload: schemas.ChatRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Protected chat endpoint for the PHISHGUARD AI Security Analyst.

    Allows an authenticated security analyst to query findings, risk breakdowns,
    and investigation guidance for a specific analysis result.

    Two-context architecture:
    1. If analysis_id is provided, loads the authoritative analysis from the DB
       and builds structured evidence server-side (Context 1).
       The user's question drives raw artifact selection (Context 2).
    2. Frontend-supplied analysis_context is treated as untrusted supplementary
       information — it CANNOT override server-side authoritative evidence.
    3. Idempotent Deduplication: Identical requests submitted within 5 seconds return
       the cached response to guarantee exactly one AI answer per question.
    """
    # --- Input validation ---
    message = payload.message.strip()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message cannot be empty or whitespace only.",
        )

    if len(message) > 2000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message exceeds maximum allowed length of 2000 characters.",
        )

    # --- Idempotency & Deduplication Check ---
    now = time.time()
    dedup_key = (current_user.id, payload.analysis_id, message.lower())

    with _DEDUP_LOCK:
        # Purge stale entries older than 30 seconds
        for k in list(_CHAT_DEDUPLICATION_CACHE.keys()):
            if now - _CHAT_DEDUPLICATION_CACHE[k][0] > 30.0:
                del _CHAT_DEDUPLICATION_CACHE[k]

        if dedup_key in _CHAT_DEDUPLICATION_CACHE:
            cached_ts, cached_result = _CHAT_DEDUPLICATION_CACHE[dedup_key]
            if now - cached_ts <= _DEDUP_WINDOW_SECONDS:
                return cached_result

    context: Dict[str, Any] = {}
    authoritative_context_loaded = False

    # --- Step 1: Load authoritative context from database (if analysis_id provided) ---
    if payload.analysis_id is not None:
        analysis_record = (
            db.query(models.AnalysisResult)
            .filter(models.AnalysisResult.id == payload.analysis_id)
            .first()
        )
        if analysis_record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis with ID {payload.analysis_id} not found.",
            )

        # Enforce multi-tenant access control: user can only chat about their own analyses
        if analysis_record.user_id is not None and analysis_record.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access another user's analysis context.",
            )

        # Parse stored record details — these are AUTHORITATIVE server-side data
        try:
            stored_details = json.loads(analysis_record.details) if analysis_record.details else {}
        except Exception:
            stored_details = {}

        try:
            stored_explanation = json.loads(analysis_record.explanation) if analysis_record.explanation else {}
        except Exception:
            stored_explanation = {}

        # Build authoritative context from DB record
        context = {
            "analysis_id": analysis_record.id,
            "artifact_type": analysis_record.artifact_type,
            "url": analysis_record.url,
            "risk_score": analysis_record.risk_score,
            "risk_level": analysis_record.risk_level,
            "risk": {
                "score": analysis_record.risk_score,
                "level": analysis_record.risk_level,
            },
            "details": stored_details,
            "explanation": stored_explanation,
            "summary": stored_explanation.get("summary", ""),
        }

        # Extract risk signals from stored details/explanation if available
        signals = stored_details.get("signals") or stored_explanation.get("signals") or []
        if signals:
            context["signals"] = signals

        # Extract ML info if available
        ml_info = stored_details.get("ml") or stored_explanation.get("ml") or {}
        if ml_info:
            context["ml"] = ml_info

        authoritative_context_loaded = True

    # --- Step 2: Handle frontend-supplied analysis_context (UNTRUSTED) ---
    if payload.analysis_context:
        try:
            serialized = json.dumps(payload.analysis_context)
            if len(serialized) > MAX_CONTEXT_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Analysis context payload exceeds maximum allowed size.",
                )
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON structure in analysis context.",
            )

        if authoritative_context_loaded:
            # SECURITY: Server-side authoritative context takes precedence.
            # Only merge fields from frontend that are NOT already in the authoritative context.
            # This prevents a tampered frontend from overriding real analysis evidence.
            for key, value in payload.analysis_context.items():
                if key not in context or context[key] is None:
                    context[key] = value
        else:
            # No authoritative context — use frontend context as primary (untrusted)
            context = payload.analysis_context

    # --- Step 3: Process chat message through security analyst engine ---
    try:
        chat_result = process_chat_message(
            user_message=message,
            analysis_context=context,
        )

        # Add analysis_id to response if available (for frontend association)
        if payload.analysis_id is not None:
            chat_result["analysis_id"] = payload.analysis_id

        # Cache the result for sliding window idempotency
        with _DEDUP_LOCK:
            _CHAT_DEDUPLICATION_CACHE[dedup_key] = (time.time(), chat_result)

        return chat_result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception:
        # SECURITY: Never expose internal details or API keys in error messages
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security analyst failed to process query.",
        )


@router.get("/suggestions/{analysis_id}")
def get_analyst_suggestions(
    analysis_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Return suggested analyst questions for a specific analysis.

    Generates context-aware question suggestions based on the artifact type
    and the evidence that actually exists in the analysis record.
    """
    analysis_record = (
        db.query(models.AnalysisResult)
        .filter(models.AnalysisResult.id == analysis_id)
        .first()
    )
    if analysis_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found.",
        )

    # Enforce ownership
    if analysis_record.user_id is not None and analysis_record.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this analysis.",
        )

    # Build evidence to determine which suggestions are appropriate
    try:
        stored_details = json.loads(analysis_record.details) if analysis_record.details else {}
    except Exception:
        stored_details = {}

    try:
        stored_explanation = json.loads(analysis_record.explanation) if analysis_record.explanation else {}
    except Exception:
        stored_explanation = {}

    context = {
        "artifact_type": analysis_record.artifact_type,
        "risk_score": analysis_record.risk_score,
        "risk_level": analysis_record.risk_level,
        "details": stored_details,
        "explanation": stored_explanation,
    }

    evidence = build_structured_evidence(context)
    suggestions = get_suggested_questions(
        analysis_record.artifact_type or "unknown",
        evidence,
    )

    return {
        "analysis_id": analysis_id,
        "artifact_type": analysis_record.artifact_type,
        "risk_level": analysis_record.risk_level,
        "suggestions": suggestions,
    }
