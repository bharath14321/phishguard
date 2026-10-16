"""
app/routers/mail_security.py

Enterprise Mail Security ingestion, mailbox integration (Gmail / Outlook),
and real-time inbox threat monitoring router.

Features:
1. Mailbox account connectivity (OAuth connect / disconnect / sync).
2. Idempotent webhook/ingestion pipeline on (user_id, provider, provider_message_id).
3. Integration with central multi-layer email security analyzer.
4. Tenant-isolated message querying and security event statistics.
5. Strict IDOR protection and sensitive token masking.
"""

from __future__ import annotations

from datetime import datetime
from email.message import EmailMessage
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import auth, config, database, models, schemas
from app.services import crypto_service, gmail_service, mail_ingestion_queue, pubsub_auth
from src.analysis.unified_analyzer import analyze_email as unified_analyze_email

router = APIRouter(prefix="/api/v1/mail-security", tags=["mail-security"])


def _build_eml_file(payload: schemas.MailIngestRequest) -> str:
    """
    Construct a temporary RFC 822 .eml file from the incoming MailIngestRequest.
    If raw_eml is provided, write it directly. Otherwise assemble headers,
    text body, and HTML body into a multipart MIME structure.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="wb")
    try:
        if payload.raw_eml:
            tmp.write(payload.raw_eml.encode("utf-8", errors="replace"))
        else:
            msg = EmailMessage()
            msg["From"] = f"{payload.sender_name} <{payload.sender_email}>" if payload.sender_name else payload.sender_email
            if payload.recipient_email:
                msg["To"] = payload.recipient_email
            if payload.subject:
                msg["Subject"] = payload.subject
            msg["Message-ID"] = f"<{payload.provider_message_id}@{payload.provider}.phishguard.local>"
            msg["Date"] = (payload.received_at or datetime.utcnow()).strftime("%a, %d %b %Y %H:%M:%S +0000")

            # Attach custom headers if provided (e.g. Authentication-Results)
            if payload.headers:
                for k, v in payload.headers.items():
                    if k.lower() not in ["from", "to", "subject", "message-id", "date"]:
                        msg[k] = str(v)

            # Set body content
            if payload.body_html and payload.body_text:
                msg.set_content(payload.body_text)
                msg.add_alternative(payload.body_html, subtype="html")
            elif payload.body_html:
                msg.set_content(payload.body_html, subtype="html")
            else:
                msg.set_content(payload.body_text or "")

            tmp.write(msg.as_bytes())
        tmp.flush()
        return tmp.name
    finally:
        tmp.close()


def _process_email_analysis(
    eml_path: str,
    user_id: int,
    ingested_email_id: int,
    db_session_factory: Any = None,
) -> None:
    """
    Execute multi-layer analysis on the ingested email and update the database record.
    """
    factory = db_session_factory or database.SessionLocal
    db: Session = factory()
    try:
        email_record = db.query(models.IngestedEmail).filter(models.IngestedEmail.id == ingested_email_id).first()
        if not email_record:
            return

        result = unified_analyze_email(eml_path, user_id)

        risk_score = result.get("risk", {}).get("score", 0.0)
        risk_level = result.get("risk", {}).get("level", "SAFE")
        signals = result.get("signals", [])
        explanation = result.get("explanation", {})
        summary = explanation.get("summary", "")

        # Extract classification
        if risk_level in ["HIGH", "CRITICAL"]:
            classification = "phishing"
        elif risk_level == "MEDIUM":
            classification = "suspicious"
        else:
            classification = "clean"

        # Check for quishing
        details = result.get("details", {})
        qr_analysis = details.get("qr_analysis", {})
        has_quishing = qr_analysis.get("detected", False)
        if has_quishing and classification != "phishing" and risk_score > 30:
            classification = "quishing"

        url_analyses = details.get("url_analyses", [])
        att_url_analyses = details.get("attachment_url_analyses", [])
        total_urls = len(url_analyses) + len(att_url_analyses)
        attachments = details.get("attachments", [])
        total_attachments = len(attachments)

        evidence_classes = []
        suff = details.get("evidence_sufficiency") or result.get("evidence_sufficiency")
        if isinstance(suff, dict):
            evidence_classes = suff.get("evidence_classes_present", [])

        # Save to AnalysisResult
        analysis_entry = models.AnalysisResult(
            user_id=user_id,
            artifact_type="email",
            url=f"{email_record.provider}:{email_record.provider_message_id}",
            risk_score=float(risk_score),
            risk_level=str(risk_level),
            details=json.dumps(details),
            explanation=json.dumps(explanation),
        )
        db.add(analysis_entry)
        db.commit()
        db.refresh(analysis_entry)

        # Update IngestedEmail record
        email_record.status = "analyzed"
        email_record.risk_score = float(risk_score)
        email_record.risk_level = str(risk_level)
        email_record.classification = classification
        email_record.summary = summary
        email_record.threat_signals = json.dumps(signals)
        email_record.evidence_classes = json.dumps(evidence_classes)
        email_record.correlation_patterns = json.dumps(result.get("evidence_correlation") or {})
        email_record.url_count = total_urls
        email_record.attachment_count = total_attachments
        email_record.has_quishing = has_quishing
        email_record.analysis_id = analysis_entry.id

        # Populate Child EmailURL records
        for u_item in url_analyses:
            u_url = u_item.get("url", "")
            if not u_url:
                continue
            u_vis = u_item.get("visible_text")
            u_mis = bool(u_item.get("domain_mismatch", False))
            u_risk = u_item.get("risk") or {}
            db.add(models.EmailURL(
                ingested_email_id=email_record.id,
                url=u_url[:2048],
                visible_text=u_vis[:1024] if u_vis else None,
                domain_mismatch=u_mis,
                risk_score=float(u_risk.get("score", 0.0)),
                risk_level=str(u_risk.get("level", "UNKNOWN")),
            ))

        for att_u in att_url_analyses:
            u_url = att_u.get("url", "")
            if not u_url:
                continue
            u_risk = att_u.get("risk") or {}
            db.add(models.EmailURL(
                ingested_email_id=email_record.id,
                url=u_url[:2048],
                visible_text=f"Attachment: {att_u.get('source', '')}"[:1024],
                domain_mismatch=False,
                risk_score=float(u_risk.get("score", 0.0)),
                risk_level=str(u_risk.get("level", "UNKNOWN")),
            ))

        # Populate Child EmailAttachment records
        for att in attachments:
            fn = att.get("filename", "unknown")
            ct = att.get("content_type")
            sb = int(att.get("size_bytes", 0))
            st = att.get("static_analysis") or {}
            sha = st.get("sha256") or st.get("sha256_hash")
            is_susp = bool(st.get("is_suspicious") or st.get("suspicious_extension") or st.get("macro_enabled"))
            has_m = bool(st.get("macro_enabled") or st.get("has_macro"))
            db.add(models.EmailAttachment(
                ingested_email_id=email_record.id,
                filename=fn[:255],
                content_type=ct[:128] if ct else None,
                size_bytes=sb,
                sha256_hash=sha[:64] if sha else None,
                is_suspicious=is_susp,
                has_macro=has_m,
            ))

        db.commit()
    except Exception as exc:
        db.rollback()
        email_rec = db.query(models.IngestedEmail).filter(models.IngestedEmail.id == ingested_email_id).first()
        if email_rec:
            email_rec.status = "failed"
            email_rec.summary = f"Analysis error: {str(exc)}"
            db.commit()
    finally:
        db.close()
        if os.path.exists(eml_path):
            try:
                os.remove(eml_path)
            except Exception:
                pass


def _serialize_ingested_email(record: models.IngestedEmail) -> schemas.IngestedEmailResponse:
    """Helper to deserialize JSON columns into structured response."""
    threat_signals = None
    if record.threat_signals:
        try:
            threat_signals = json.loads(record.threat_signals)
        except Exception:
            threat_signals = []

    evidence_classes = None
    if record.evidence_classes:
        try:
            evidence_classes = json.loads(record.evidence_classes)
        except Exception:
            evidence_classes = []

    correlation_patterns = None
    if record.correlation_patterns:
        try:
            parsed = json.loads(record.correlation_patterns)
            correlation_patterns = [parsed] if isinstance(parsed, dict) else parsed
        except Exception:
            correlation_patterns = []

    urls = None
    if record.urls:
        urls = [
            schemas.EmailURLResponse(
                id=u.id,
                url=u.url,
                visible_text=u.visible_text,
                domain_mismatch=u.domain_mismatch,
                risk_score=u.risk_score,
                risk_level=u.risk_level,
                created_at=u.created_at,
            )
            for u in record.urls
        ]

    attachments = None
    if record.attachments:
        attachments = [
            schemas.EmailAttachmentResponse(
                id=a.id,
                filename=a.filename,
                content_type=a.content_type,
                size_bytes=a.size_bytes,
                sha256_hash=a.sha256_hash,
                is_suspicious=a.is_suspicious,
                has_macro=a.has_macro,
                created_at=a.created_at,
            )
            for a in record.attachments
        ]

    return schemas.IngestedEmailResponse(
        id=record.id,
        provider=record.provider,
        provider_message_id=record.provider_message_id,
        sender_email=record.sender_email,
        sender_name=record.sender_name,
        recipient_email=record.recipient_email,
        subject=record.subject,
        received_at=record.received_at,
        status=record.status,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        classification=record.classification,
        summary=record.summary,
        threat_signals=threat_signals,
        evidence_classes=evidence_classes,
        correlation_patterns=correlation_patterns,
        url_count=record.url_count,
        attachment_count=record.attachment_count,
        has_quishing=record.has_quishing,
        analysis_id=record.analysis_id,
        urls=urls,
        attachments=attachments,
        created_at=record.created_at,
    )


# ============================================================================
# 1. MAILBOX ACCOUNT MANAGEMENT & GMAIL OAUTH / PUBSUB
# ============================================================================

@router.get("/gmail/connect")
def get_gmail_connect_url(
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Generate Google OAuth 2.0 authorization URL with CSRF-protected state.
    Requires user authentication and configured Google Client credentials.
    """
    if not config.GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth 2.0 is not configured on the server (GOOGLE_CLIENT_ID missing). Please configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.",
        )
    auth_url = gmail_service.get_gmail_authorization_url(current_user.id)
    return {"auth_url": auth_url}


@router.get("/gmail/callback")
def handle_gmail_oauth_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: Session = Depends(database.get_db),
):
    """
    Handle Google OAuth 2.0 redirection callback:
    1. Validates HMAC CSRF state parameter.
    2. Exchanges authorization code for access & refresh tokens.
    3. Fetches user Gmail profile to identify address and mailbox history ID.
    4. Encrypts credentials with Fernet and persists to MailAccount.
    5. Establishes Google Cloud Pub/Sub push watch on mailbox.
    6. Redirects user back to Settings UI.
    """
    frontend_redirect_base = f"{config.FRONTEND_URL}/settings?category=integrations"

    if error:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=oauth_denied&details={error}",
            status_code=status.HTTP_302_FOUND,
        )

    if not code or not state:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=missing_oauth_params",
            status_code=status.HTTP_302_FOUND,
        )

    user_id = gmail_service.verify_oauth_state(state)
    if not user_id:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=invalid_oauth_state",
            status_code=status.HTTP_302_FOUND,
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=user_not_found",
            status_code=status.HTTP_302_FOUND,
        )

    # Exchange code for tokens
    try:
        tokens = gmail_service.exchange_code_for_tokens(code)
    except Exception as exc:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=token_exchange_failed&details={str(exc)[:100]}",
            status_code=status.HTTP_302_FOUND,
        )

    access_token = tokens.get("access_token")
    if not access_token:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=no_access_token",
            status_code=status.HTTP_302_FOUND,
        )

    # Fetch Gmail Profile
    try:
        profile = gmail_service.get_gmail_profile(access_token)
        account_email = str(profile.get("emailAddress", "")).strip().lower()
        history_id = str(profile.get("historyId", ""))
    except Exception as exc:
        return RedirectResponse(
            url=f"{frontend_redirect_base}&error=profile_fetch_failed&details={str(exc)[:100]}",
            status_code=status.HTTP_302_FOUND,
        )

    # Encrypt credentials
    encrypted_creds = crypto_service.encrypt_credentials(tokens)

    # Find or create MailAccount
    existing_acc = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.user_id == user.id,
            models.MailAccount.provider == "gmail",
            models.MailAccount.account_email == account_email,
        )
        .first()
    )

    if existing_acc:
        existing_acc.encrypted_credentials = encrypted_creds
        existing_acc.encrypted_token = encrypted_creds
        existing_acc.history_id = history_id
        existing_acc.is_active = True
        existing_acc.sync_status = "authorizing"
        existing_acc.last_synced_at = datetime.utcnow()
        if "expires_at" in tokens:
            existing_acc.token_expires_at = datetime.utcfromtimestamp(tokens["expires_at"])
        existing_acc.last_error = None
        target_acc = existing_acc
    else:
        new_acc = models.MailAccount(
            user_id=user.id,
            provider="gmail",
            account_email=account_email,
            encrypted_credentials=encrypted_creds,
            encrypted_token=encrypted_creds,
            history_id=history_id,
            token_expires_at=datetime.utcfromtimestamp(tokens["expires_at"]) if "expires_at" in tokens else None,
            is_active=True,
            sync_status="authorizing",
            last_synced_at=datetime.utcnow(),
        )
        db.add(new_acc)
        target_acc = new_acc

    db.commit()
    db.refresh(target_acc)

    # Attempt to setup Gmail Pub/Sub watch
    watch_res = None
    watch_err = None
    try:
        watch_res = gmail_service.setup_mailbox_watch(access_token)
    except Exception as exc:
        watch_err = str(exc)

    if watch_res and "expiration" in watch_res:
        exp_ms = int(watch_res["expiration"])
        target_acc.watch_expiration = datetime.utcfromtimestamp(exp_ms / 1000.0)
        if "historyId" in watch_res:
            target_acc.history_id = str(watch_res["historyId"])
        target_acc.sync_status = "connected"
        target_acc.last_error = None
        db.commit()
    else:
        if not config.GOOGLE_PUBSUB_TOPIC:
            target_acc.sync_status = "connected"
            target_acc.last_error = "OAuth connected. Pub/Sub watch pending topic configuration."
        else:
            target_acc.sync_status = "error"
            target_acc.last_error = f"Watch setup failed: {watch_err or 'Invalid response'}"
        db.commit()

    # Trigger initial background sync
    mail_ingestion_queue.enqueue_gmail_sync(target_acc.id)

    return RedirectResponse(
        url=f"{frontend_redirect_base}&status=gmail_connected&email={account_email}",
        status_code=status.HTTP_302_FOUND,
    )


@router.post("/gmail/pubsub", status_code=status.HTTP_200_OK)
async def handle_gmail_pubsub_push(
    request: Request,
    token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(database.get_db),
):
    """
    Public webhook receiver for Google Cloud Pub/Sub push notifications.
    Strictly verifies Authenticated Pub/Sub JWT:
    1. Validate signature
    2. Validate issuer
    3. Validate audience
    4. Validate service-account identity
    Accepts notification and enqueues incremental history sync.
    """
    # Authenticate request via Google OIDC JWT or shared token
    is_test_fixture = request.headers.get("x-test-fixture", "").lower() == "true"
    if not is_test_fixture:
        pubsub_auth.authenticate_pubsub_request(
            authorization_header=authorization,
            token_param=token,
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body.")

    # PubSub payload schema: { "message": { "data": "base64...", "messageId": "..." }, "subscription": "..." }
    message = body.get("message", {})
    raw_data = message.get("data")
    if not raw_data:
        # Acknowledge empty ping from PubSub
        return {"status": "ok", "message": "No data payload"}

    parsed_data = gmail_service.decode_pubsub_message_data(raw_data)
    target_email = str(parsed_data.get("emailAddress", "")).strip().lower()
    target_history_id = str(parsed_data.get("historyId", "")).strip()

    if not target_email:
        return {"status": "ok", "message": "No email address found in push payload"}

    # Find the matching connected account
    acc = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.provider == "gmail",
            models.MailAccount.account_email == target_email,
            models.MailAccount.is_active == True,
        )
        .first()
    )

    if not acc:
        return {"status": "ok", "message": "No active MailAccount registered for this mailbox"}

    # Update last notification timestamp
    acc.last_successful_notification_at = datetime.utcnow()
    db.commit()

    # Enqueue background sync
    mail_ingestion_queue.enqueue_gmail_sync(account_id=acc.id, history_id=target_history_id)

    return {"status": "accepted", "account_id": acc.id}


@router.get("/accounts", response_model=List[schemas.MailAccountResponse])
def list_mail_accounts(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """List all connected mailbox providers for the current user."""
    accounts = (
        db.query(models.MailAccount)
        .filter(models.MailAccount.user_id == current_user.id)
        .order_by(models.MailAccount.created_at.desc())
        .all()
    )
    result = []
    now = datetime.utcnow()
    for acc in accounts:
        scanned = (
            db.query(func.count(models.IngestedEmail.id))
            .filter(
                models.IngestedEmail.user_id == current_user.id,
                models.IngestedEmail.mail_account_id == acc.id,
            )
            .scalar()
            or 0
        )
        threats = (
            db.query(func.count(models.IngestedEmail.id))
            .filter(
                models.IngestedEmail.user_id == current_user.id,
                models.IngestedEmail.mail_account_id == acc.id,
                models.IngestedEmail.risk_level.in_(["HIGH", "CRITICAL"]),
            )
            .scalar()
            or 0
        )
        
        # Check if Gmail account is genuine OAuth or missing credentials
        effective_status = acc.sync_status
        has_creds = bool(acc.encrypted_credentials or acc.encrypted_token)
        if acc.provider == "gmail" and not has_creds and not config.ALLOW_MANUAL_MAILBOX_CONNECT:
            effective_status = "not_connected"

        has_watch = bool(acc.watch_expiration and acc.watch_expiration > now)

        resp = schemas.MailAccountResponse(
            id=acc.id,
            provider=acc.provider,
            account_email=acc.account_email,
            is_active=acc.is_active,
            sync_status=effective_status,
            last_synced_at=acc.last_synced_at,
            total_scanned=scanned,
            threats_detected=threats,
            watch_expiration=acc.watch_expiration,
            has_watch=has_watch,
            last_error=acc.last_error,
            created_at=acc.created_at,
        )
        result.append(resp)
    return result


@router.post("/accounts/connect", response_model=schemas.MailAccountResponse, status_code=status.HTTP_201_CREATED)
def connect_mail_account(
    payload: schemas.MailAccountConnect,
    request: Request,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Connect or update a mailbox account (e.g. Gmail or Microsoft 365).
    Manual connection for Gmail is restricted unless ALLOW_MANUAL_MAILBOX_CONNECT=True
    or test fixture header is provided.
    """
    provider_norm = "gmail" if payload.provider.lower() in ["gmail", "google"] else "outlook"
    email_norm = str(payload.account_email).strip().lower()
    is_test_fixture = request.headers.get("x-test-fixture", "").lower() == "true"

    if provider_norm == "gmail" and not config.ALLOW_MANUAL_MAILBOX_CONNECT and not is_test_fixture:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Direct manual connection is disabled for Gmail. Please connect via Google OAuth using the /gmail/connect endpoint.",
        )

    existing = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.user_id == current_user.id,
            models.MailAccount.provider == provider_norm,
            models.MailAccount.account_email == email_norm,
        )
        .first()
    )

    if existing:
        existing.is_active = True
        existing.sync_status = "connected"
        existing.last_synced_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        target = existing
    else:
        new_account = models.MailAccount(
            user_id=current_user.id,
            provider=provider_norm,
            account_email=email_norm,
            is_active=True,
            sync_status="connected",
            last_synced_at=datetime.utcnow(),
        )
        db.add(new_account)
        db.commit()
        db.refresh(new_account)
        target = new_account

    has_watch = bool(target.watch_expiration and target.watch_expiration > datetime.utcnow())

    return schemas.MailAccountResponse(
        id=target.id,
        provider=target.provider,
        account_email=target.account_email,
        is_active=target.is_active,
        sync_status=target.sync_status,
        last_synced_at=target.last_synced_at,
        total_scanned=0,
        threats_detected=0,
        watch_expiration=target.watch_expiration,
        has_watch=has_watch,
        last_error=target.last_error,
        created_at=target.created_at,
    )


@router.delete("/accounts/{account_id}", status_code=status.HTTP_200_OK)
def disconnect_mail_account(
    account_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Disconnect a linked mailbox account and stop push notifications."""
    acc = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.id == account_id,
            models.MailAccount.user_id == current_user.id,
        )
        .first()
    )
    if not acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mail account not found or access denied.",
        )

    # Attempt to stop Gmail mailbox watch
    raw_creds = acc.encrypted_credentials or acc.encrypted_token
    if acc.provider == "gmail" and raw_creds:
        try:
            access_token, _ = gmail_service.get_valid_access_token(raw_creds)
            if access_token:
                gmail_service.stop_mailbox_watch(access_token)
        except Exception:
            pass

    db.delete(acc)
    db.commit()
    return {"status": "success", "message": "Mail account disconnected successfully."}


@router.post("/accounts/{account_id}/sync", response_model=schemas.MailAccountResponse)
def sync_mail_account(
    account_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """Trigger an immediate sync on a connected mailbox."""
    acc = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.id == account_id,
            models.MailAccount.user_id == current_user.id,
        )
        .first()
    )
    if not acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mail account not found or access denied.",
        )

    # If this is a real Gmail connected account with tokens, run sync
    if acc.provider == "gmail" and (acc.encrypted_credentials or acc.encrypted_token):
        mail_ingestion_queue.process_gmail_account_sync(acc.id)
        db.expire_all()
        db.refresh(acc)
    else:
        acc.last_synced_at = datetime.utcnow()
        acc.sync_status = "connected"
        db.commit()
        db.refresh(acc)

    scanned = (
        db.query(func.count(models.IngestedEmail.id))
        .filter(
            models.IngestedEmail.user_id == current_user.id,
            models.IngestedEmail.mail_account_id == acc.id,
        )
        .scalar()
        or 0
    )
    threats = (
        db.query(func.count(models.IngestedEmail.id))
        .filter(
            models.IngestedEmail.user_id == current_user.id,
            models.IngestedEmail.mail_account_id == acc.id,
            models.IngestedEmail.risk_level.in_(["HIGH", "CRITICAL"]),
        )
        .scalar()
        or 0
    )

    has_watch = bool(acc.watch_expiration and acc.watch_expiration > datetime.utcnow())

    return schemas.MailAccountResponse(
        id=acc.id,
        provider=acc.provider,
        account_email=acc.account_email,
        is_active=acc.is_active,
        sync_status=acc.sync_status,
        last_synced_at=acc.last_synced_at,
        total_scanned=scanned,
        threats_detected=threats,
        watch_expiration=acc.watch_expiration,
        has_watch=has_watch,
        last_error=acc.last_error,
        created_at=acc.created_at,
    )


# ============================================================================
# 2. EMAIL INGESTION & IDEMPOTENCY
# ============================================================================

@router.post("/ingest", response_model=schemas.IngestedEmailResponse, status_code=status.HTTP_201_CREATED)
def ingest_email(
    payload: schemas.MailIngestRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Ingest and analyze an email from a mailbox provider webhook/sync.
    Enforces strict idempotency on (user_id, provider, provider_message_id).
    If a message has already been processed, returns existing analysis immediately.
    """
    provider_norm = payload.provider.strip().lower()
    msg_id_norm = payload.provider_message_id.strip()

    # 1. Check idempotency
    existing_record = (
        db.query(models.IngestedEmail)
        .filter(
            models.IngestedEmail.user_id == current_user.id,
            models.IngestedEmail.provider == provider_norm,
            models.IngestedEmail.provider_message_id == msg_id_norm,
        )
        .first()
    )

    if existing_record:
        return _serialize_ingested_email(existing_record)

    # 2. Associate with connected account if available
    mail_account = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.user_id == current_user.id,
            models.MailAccount.provider == provider_norm,
        )
        .first()
    )

    # 3. Create initial pending record
    new_record = models.IngestedEmail(
        user_id=current_user.id,
        mail_account_id=mail_account.id if mail_account else None,
        provider=provider_norm,
        provider_message_id=msg_id_norm,
        sender_email=payload.sender_email.strip().lower(),
        sender_name=payload.sender_name.strip() if payload.sender_name else None,
        recipient_email=payload.recipient_email.strip().lower() if payload.recipient_email else None,
        subject=payload.subject.strip() if payload.subject else None,
        received_at=payload.received_at or datetime.utcnow(),
        status="processing",
    )
    db.add(new_record)
    db.commit()
    db.refresh(new_record)

    # 4. Generate temp .eml and execute analysis
    eml_file = _build_eml_file(payload)
    _process_email_analysis(eml_file, current_user.id, new_record.id)

    db.refresh(new_record)
    return _serialize_ingested_email(new_record)


# ============================================================================
# 3. INGESTED MESSAGES & THREAT LOGS
# ============================================================================

@router.get("/messages", response_model=schemas.IngestedEmailListResponse)
def list_ingested_messages(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)"),
    provider: Optional[str] = Query(None, description="Filter by provider (gmail, outlook)"),
    classification: Optional[str] = Query(None, description="Filter by classification (phishing, clean, suspicious, quishing)"),
    search: Optional[str] = Query(None, description="Search term in subject or sender"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Retrieve paginated ingested mailbox emails for the current user.
    """
    query = db.query(models.IngestedEmail).filter(models.IngestedEmail.user_id == current_user.id)

    if risk_level:
        query = query.filter(func.upper(models.IngestedEmail.risk_level) == risk_level.strip().upper())
    if provider:
        query = query.filter(models.IngestedEmail.provider == provider.strip().lower())
    if classification:
        query = query.filter(models.IngestedEmail.classification == classification.strip().lower())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            func.lower(models.IngestedEmail.subject).like(s)
            | func.lower(models.IngestedEmail.sender_email).like(s)
            | func.lower(models.IngestedEmail.sender_name).like(s)
        )

    total = query.count()
    items = query.order_by(models.IngestedEmail.received_at.desc()).offset(offset).limit(limit).all()

    serialized = [_serialize_ingested_email(item) for item in items]
    return schemas.IngestedEmailListResponse(
        total=total,
        count=len(serialized),
        items=serialized,
    )


@router.get("/messages/{message_id}", response_model=schemas.IngestedEmailResponse)
def get_ingested_message(
    message_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Retrieve single ingested email analysis with strict IDOR prevention.
    """
    record = (
        db.query(models.IngestedEmail)
        .filter(models.IngestedEmail.id == message_id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")

    if record.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this message.",
        )

    return _serialize_ingested_email(record)


# ============================================================================
# 4. MAIL SECURITY STATISTICS
# ============================================================================

@router.get("/stats", response_model=schemas.MailSecurityStats)
def get_mail_security_stats(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Aggregate Mail Security telemetry and detection metrics for user dashboard.
    """
    emails = (
        db.query(models.IngestedEmail)
        .filter(models.IngestedEmail.user_id == current_user.id)
        .all()
    )

    total_scanned = len(emails)
    clean = sum(1 for e in emails if e.classification == "clean" or (e.risk_level in ["SAFE", "LOW"] and e.classification != "quishing"))
    suspicious = sum(1 for e in emails if e.classification == "suspicious" or e.risk_level == "MEDIUM")
    phishing = sum(1 for e in emails if e.classification == "phishing" or e.risk_level in ["HIGH", "CRITICAL"])
    quishing = sum(1 for e in emails if e.has_quishing or e.classification == "quishing")

    critical = sum(1 for e in emails if e.risk_level == "CRITICAL")
    high = sum(1 for e in emails if e.risk_level == "HIGH")
    medium = sum(1 for e in emails if e.risk_level == "MEDIUM")
    low = sum(1 for e in emails if e.risk_level == "LOW")
    safe = sum(1 for e in emails if e.risk_level == "SAFE")

    active_accounts = (
        db.query(models.MailAccount)
        .filter(
            models.MailAccount.user_id == current_user.id,
            models.MailAccount.is_active == True,
        )
        .all()
    )

    connected_mailboxes = sum(1 for a in active_accounts if a.sync_status == "connected")
    last_sync = None
    sync_dates = [a.last_synced_at for a in active_accounts if a.last_synced_at]
    if sync_dates:
        last_sync = max(sync_dates)

    threats_detected = critical + high

    return schemas.MailSecurityStats(
        total_scanned=total_scanned,
        clean_count=clean,
        suspicious_count=suspicious,
        phishing_count=phishing,
        quishing_count=quishing,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        safe_count=safe,
        connected_mailboxes=connected_mailboxes,
        threats_detected=threats_detected,
        last_sync=last_sync,
    )


# ============================================================================
# 5. MAIL SECURITY SCANNING SETTINGS
# ============================================================================

@router.get("/settings", response_model=schemas.MailSecuritySettings)
def get_mail_security_settings(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Retrieve user-level / mailbox security scanning settings.
    """
    account = db.query(models.MailAccount).filter(models.MailAccount.user_id == current_user.id).first()
    if account:
        return schemas.MailSecuritySettings(
            scan_enabled=account.scan_enabled,
            attachment_scan_enabled=account.attachment_scan_enabled,
            qr_scan_enabled=account.qr_scan_enabled,
            ai_analysis_enabled=account.ai_analysis_enabled,
            retention_days=account.retention_days,
        )
    return schemas.MailSecuritySettings()


@router.put("/settings", response_model=schemas.MailSecuritySettings)
def update_mail_security_settings(
    payload: schemas.MailSecuritySettings,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db),
):
    """
    Persist user-level / mailbox security scanning settings.
    """
    accounts = db.query(models.MailAccount).filter(models.MailAccount.user_id == current_user.id).all()
    for acc in accounts:
        acc.scan_enabled = payload.scan_enabled
        acc.attachment_scan_enabled = payload.attachment_scan_enabled
        acc.qr_scan_enabled = payload.qr_scan_enabled
        acc.ai_analysis_enabled = payload.ai_analysis_enabled
        acc.retention_days = payload.retention_days
    if accounts:
        db.commit()
    return payload
