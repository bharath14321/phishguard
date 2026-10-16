"""
app/services/gmail_sync_job.py

Scheduled maintenance and background jobs for Gmail Mailbox Integrations.
Handles:
1. Watch Renewal: Gmail mailbox watches expire every 7 days (604800s).
   This service renews active watches expiring within 24 hours.
2. Fallback Polling: Syncs active accounts if no Pub/Sub notifications
   have been received for a configured period.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Dict, List

from sqlalchemy.orm import Session

from app import config, database, models
from app.services import crypto_service, gmail_service, mail_ingestion_queue

logger = logging.getLogger("phishguard.gmail_sync_job")


def renew_expiring_gmail_watches(db_session_factory: Any = None) -> Dict[str, int]:
    """
    Find all active Gmail accounts whose watch_expiration is within 24 hours (or None)
    and renew their watch with Google Pub/Sub.
    """
    factory = db_session_factory or database.SessionLocal
    db: Session = factory()
    results = {"total_checked": 0, "renewed": 0, "failed": 0}
    try:
        threshold = datetime.utcnow() + timedelta(hours=24)
        active_accounts = (
            db.query(models.MailAccount)
            .filter(
                models.MailAccount.provider == "gmail",
                models.MailAccount.is_active == True,
            )
            .all()
        )

        results["total_checked"] = len(active_accounts)

        for acc in active_accounts:
            # Check if watch needs renewal (expiration is None, or <= threshold)
            needs_renewal = (
                acc.watch_expiration is None
                or acc.watch_expiration <= threshold
            )
            raw_creds = acc.encrypted_credentials or acc.encrypted_token
            if not needs_renewal or not raw_creds:
                continue

            try:
                access_token, updated_creds = gmail_service.get_valid_access_token(raw_creds)
                if not access_token:
                    logger.warning("Cannot renew watch for account %s: token refresh failed", acc.id)
                    results["failed"] += 1
                    continue

                # Persist refreshed credentials if updated
                enc_updated = crypto_service.encrypt_credentials(updated_creds)
                acc.encrypted_credentials = enc_updated
                acc.encrypted_token = enc_updated
                if "expires_at" in updated_creds:
                    acc.token_expires_at = datetime.utcfromtimestamp(updated_creds["expires_at"])

                watch_res = gmail_service.setup_mailbox_watch(access_token)
                if watch_res and "expiration" in watch_res:
                    exp_ms = int(watch_res["expiration"])
                    acc.watch_expiration = datetime.utcfromtimestamp(exp_ms / 1000.0)
                    if "historyId" in watch_res:
                        acc.history_id = str(watch_res["historyId"])
                    acc.last_error = None
                    db.commit()
                    results["renewed"] += 1
                    logger.info("Successfully renewed Gmail watch for account %s (expires %s)", acc.id, acc.watch_expiration)
                else:
                    results["failed"] += 1
            except gmail_service.GoogleAuthRevokedError as exc:
                logger.warning("Revoked Gmail credentials during watch renewal for account %s: %s", acc.id, exc)
                acc.sync_status = "requires_reauth"
                acc.last_error = "Google authorization expired or revoked. Please reconnect your Gmail account."
                db.commit()
                results["failed"] += 1
            except Exception as exc:
                logger.error("Error renewing watch for account %s: %s", acc.id, exc)
                acc.last_error = f"Watch renewal error: {str(exc)[:250]}"
                db.commit()
                results["failed"] += 1

        return results
    finally:
        db.close()


def run_periodic_fallback_sync(db_session_factory: Any = None) -> Dict[str, int]:
    """
    Periodic fallback synchronization for active Gmail mailboxes.
    Processes any accounts that have been inactive or missed webhook pushes.
    """
    factory = db_session_factory or database.SessionLocal
    db: Session = factory()
    results = {"enqueued": 0}
    try:
        active_accounts = (
            db.query(models.MailAccount)
            .filter(
                models.MailAccount.provider == "gmail",
                models.MailAccount.is_active == True,
            )
            .all()
        )

        for acc in active_accounts:
            mail_ingestion_queue.enqueue_gmail_sync(acc.id)
            results["enqueued"] += 1

        return results
    finally:
        db.close()
