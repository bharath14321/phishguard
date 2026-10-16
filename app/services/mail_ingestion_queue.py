"""
app/services/mail_ingestion_queue.py

Asynchronous ingestion queue and worker for processing Gmail notifications and mailbox syncs.
Decouples Pub/Sub push webhook acknowledgement from heavy multi-layer email security analysis.

Architecture:
1. Pub/Sub webhook validates and enqueues sync tasks.
2. Ingestion worker retrieves new messages from Gmail via incremental history sync.
3. Enforces strict idempotency on (user_id, provider, provider_message_id) before analysis.
4. Passes raw RFC 822 email payload directly into PHISHGUARD's unified multi-layer email analyzer.
5. Updates threat intelligence, evidence sufficiency, and risk scores on IngestedEmail and AnalysisResult.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email import policy
from email.parser import BytesParser
import logging
import os
import tempfile
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app import database, models
from app.services import crypto_service, gmail_service

logger = logging.getLogger("phishguard.ingestion_queue")

# Thread pool for non-blocking background mailbox processing
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="mail_ingest_worker")


def enqueue_gmail_sync(account_id: int, history_id: Optional[str] = None) -> None:
    """
    Enqueue a background sync job for a specific connected Gmail account ID.

    Args:
        account_id: The ID of the MailAccount to synchronize.
        history_id: Optional target history ID from Pub/Sub push notification.
    """
    _executor.submit(process_gmail_account_sync, account_id, history_id)


def process_gmail_account_sync(
    account_id: int,
    target_history_id: Optional[str] = None,
    db_session_factory: Any = None,
) -> Dict[str, Any]:
    """
    Execute incremental Gmail history sync and process new Inbox messages.

    Args:
        account_id: The ID of the MailAccount to synchronize.
        target_history_id: Optional target history ID.
        db_session_factory: SQLAlchemy session maker.

    Returns:
        Dictionary summary: {"status": "success"|"error", "synced_count": int, "new_history_id": str}
    """
    factory = db_session_factory or database.SessionLocal
    db: Session = factory()
    try:
        acc = db.query(models.MailAccount).filter(models.MailAccount.id == account_id).first()
        raw_token_data = (acc.encrypted_credentials or acc.encrypted_token) if acc else None
        if not acc or not acc.is_active or not raw_token_data:
            logger.warning("Account ID %s not active or missing credentials. Skipping sync.", account_id)
            return {"status": "error", "synced_count": 0, "message": "Account inactive or uncredentialed"}

        # 1. Obtain valid access token (refreshes if needed)
        try:
            access_token, updated_creds = gmail_service.get_valid_access_token(raw_token_data)
            enc_updated = crypto_service.encrypt_credentials(updated_creds)
            acc.encrypted_credentials = enc_updated
            acc.encrypted_token = enc_updated
            if "expires_at" in updated_creds:
                acc.token_expires_at = datetime.utcfromtimestamp(updated_creds["expires_at"])
            db.commit()
        except gmail_service.GoogleAuthRevokedError as exc:
            logger.warning("Google authorization revoked or expired for account %s: %s", acc.account_email, exc)
            acc.sync_status = "requires_reauth"
            acc.last_error = "Google authorization expired or revoked. Please reconnect your Gmail account."
            db.commit()
            return {"status": "error", "synced_count": 0, "message": "Re-authentication required"}
        except Exception as exc:
            logger.error("Failed to authenticate with Gmail for account %s: %s", acc.account_email, exc)
            acc.sync_status = "error"
            acc.last_error = f"Authentication failure: {str(exc)}"
            db.commit()
            return {"status": "error", "synced_count": 0, "message": str(exc)}

        # 2. Synchronize history
        start_history_id = acc.history_id or target_history_id or "1"
        try:
            msg_ids, latest_history_id = gmail_service.fetch_history_changes(access_token, start_history_id)
        except Exception as exc:
            logger.error("Error fetching history for %s: %s", acc.account_email, exc)
            acc.sync_status = "error"
            acc.last_error = f"History sync failure: {str(exc)}"
            db.commit()
            return {"status": "error", "synced_count": 0, "message": str(exc)}

        logger.info("Found %d new candidate message(s) for %s", len(msg_ids), acc.account_email)
        ingested_count = 0

        # 3. Process each message
        for msg_id in msg_ids:
            try:
                # Check idempotency first
                existing = (
                    db.query(models.IngestedEmail)
                    .filter(
                        models.IngestedEmail.user_id == acc.user_id,
                        models.IngestedEmail.provider == "gmail",
                        models.IngestedEmail.provider_message_id == msg_id,
                    )
                    .first()
                )
                if existing:
                    logger.debug("Message %s already ingested for user %s. Skipping.", msg_id, acc.user_id)
                    continue

                # Fetch raw email bytes
                raw_bytes = gmail_service.fetch_raw_message_bytes(access_token, msg_id)
                if not raw_bytes:
                    continue

                # Parse basic RFC822 metadata
                parsed_msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                sender = parsed_msg.get("From", "Unknown Sender")
                recipient = parsed_msg.get("To", acc.account_email)
                subject = parsed_msg.get("Subject", "(No Subject)")
                date_header = parsed_msg.get("Date")

                received_dt = datetime.utcnow()
                if date_header:
                    try:
                        from email.utils import parsedate_to_datetime
                        received_dt = parsedate_to_datetime(date_header)
                    except Exception:
                        pass

                # Create initial IngestedEmail record
                ingested = models.IngestedEmail(
                    user_id=acc.user_id,
                    mail_account_id=acc.id,
                    provider="gmail",
                    provider_message_id=msg_id,
                    sender_email=str(sender)[:255],
                    sender_name=str(sender)[:255],
                    recipient_email=str(recipient)[:255],
                    subject=str(subject)[:1024],
                    received_at=received_dt,
                    status="processing",
                )
                db.add(ingested)
                db.commit()
                db.refresh(ingested)

                # Write raw email to temp file for multi-layer analyzer
                with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp_eml:
                    tmp_eml.write(raw_bytes)
                    tmp_eml_path = tmp_eml.name

                try:
                    # Import and execute analysis
                    from app.routers.mail_security import _process_email_analysis
                    _process_email_analysis(tmp_eml_path, acc.user_id, ingested.id, db_session_factory=factory)
                    ingested_count += 1
                finally:
                    if os.path.exists(tmp_eml_path):
                        try:
                            os.remove(tmp_eml_path)
                        except Exception:
                            pass

            except Exception as item_exc:
                logger.error("Error processing message %s: %s", msg_id, item_exc)

        # 4. Update sync status
        acc.history_id = latest_history_id or target_history_id or acc.history_id
        acc.last_synced_at = datetime.utcnow()
        acc.sync_status = "connected"
        acc.last_error = None
        db.commit()

        return {
            "status": "success",
            "synced_count": ingested_count,
            "new_history_id": acc.history_id,
        }

    except Exception as outer_exc:
        logger.error("Unexpected error during sync for account %s: %s", account_id, outer_exc)
        return {"status": "error", "synced_count": 0, "message": str(outer_exc)}
    finally:
        db.close()
