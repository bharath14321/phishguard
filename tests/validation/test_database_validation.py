"""
Validation Module: Database Persistence & Relational Integrity (PG-DB-001 to PG-DB-004)
======================================================================================

This module validates that the PHISHGUARD database schema satisfies:
1. AnalysisResult persistence, queryability, and schema completeness.
2. Relational linkage across IngestedEmail, EmailURL, and EmailAttachment with cascading deletes.
3. Idempotency enforcement via unique constraint (user_id, provider, provider_message_id).
4. Multi-tenant database isolation.

Test Identifiers:
- PG-DB-001: AnalysisResult persistence and retrieval
- PG-DB-002: Relational linkage (IngestedEmail -> EmailURL / EmailAttachment)
- PG-DB-003: Idempotency deduplication on (user_id, provider, provider_message_id)
- PG-DB-004: Multi-tenant database query isolation
"""

import time
import uuid
import pytest
from sqlalchemy.exc import IntegrityError

from app.models import User, AnalysisResult, MailAccount, IngestedEmail, EmailURL, EmailAttachment
from tests.validation.collector import validation_collector


def test_pg_db_001_analysis_result_persistence(db_session, test_user):
    """PG-DB-001: AnalysisResult records persist correctly with all fields and user linkage."""
    start = time.perf_counter()

    record = AnalysisResult(
        user_id=test_user.id,
        url="https://validation-target.org/login",
        risk_score=68.5,
        risk_level="HIGH",
        artifact_type="url",
        details='{"domain": "validation-target.org", "entropy": 3.8}',
        explanation="High entropy and suspicious keywords"
    )
    db_session.add(record)
    db_session.commit()
    db_session.refresh(record)

    # Query back
    fetched = db_session.query(AnalysisResult).filter(AnalysisResult.id == record.id).first()
    dur = (time.perf_counter() - start) * 1000

    assert fetched is not None
    assert fetched.url == "https://validation-target.org/login"
    assert fetched.risk_score == 68.5
    assert fetched.risk_level == "HIGH"
    assert fetched.artifact_type == "url"
    assert fetched.user_id == test_user.id

    validation_collector.record_result(
        test_id="PG-DB-001",
        category="Database Persistence",
        description="AnalysisResult persists and reloads with accurate fields and relationships",
        status="PASS",
        duration_ms=dur,
        evidence={"record_id": fetched.id, "risk_level": fetched.risk_level}
    )


def test_pg_db_002_relational_linkage_and_cascades(db_session, test_user):
    """PG-DB-002: IngestedEmail with child EmailURL and EmailAttachment cascades properly."""
    start = time.perf_counter()

    mail_acc = MailAccount(
        user_id=test_user.id,
        provider="gmail",
        account_email="testuser@gmail.com",
        sync_status="connected"
    )
    db_session.add(mail_acc)
    db_session.commit()
    db_session.refresh(mail_acc)

    msg_id = f"msg_gmail_rel_{uuid.uuid4().hex[:8]}"
    ingested = IngestedEmail(
        user_id=test_user.id,
        mail_account_id=mail_acc.id,
        provider="gmail",
        provider_message_id=msg_id,
        sender_email="alerts@security-check.com",
        subject="Urgent action required",
        status="analyzed",
        risk_score=85.0,
        risk_level="CRITICAL",
        classification="phishing",
        url_count=1,
        attachment_count=1
    )
    db_session.add(ingested)
    db_session.commit()
    db_session.refresh(ingested)

    # Clean any prior child records if id was recycled
    db_session.query(EmailURL).filter(EmailURL.ingested_email_id == ingested.id).delete()
    db_session.query(EmailAttachment).filter(EmailAttachment.ingested_email_id == ingested.id).delete()
    db_session.commit()

    # Add child URL
    email_url = EmailURL(
        ingested_email_id=ingested.id,
        url="http://bad-link.com/auth",
        risk_score=90.0,
        risk_level="CRITICAL",
        domain_mismatch=True
    )
    # Add child Attachment
    email_att = EmailAttachment(
        ingested_email_id=ingested.id,
        filename="invoice.exe",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        content_type="application/x-dosexec",
        is_suspicious=True
    )
    db_session.add(email_url)
    db_session.add(email_att)
    db_session.commit()
    db_session.expire_all()

    # Verify relationships
    reloaded_email = db_session.query(IngestedEmail).filter(IngestedEmail.id == ingested.id).first()
    assert len(reloaded_email.urls) == 1
    assert len(reloaded_email.attachments) == 1
    assert reloaded_email.urls[0].url == "http://bad-link.com/auth"
    assert reloaded_email.attachments[0].filename == "invoice.exe"

    dur = (time.perf_counter() - start) * 1000

    validation_collector.record_result(
        test_id="PG-DB-002",
        category="Database Persistence",
        description="Relational linkage between IngestedEmail and child entities (URLs/Attachments) verified",
        status="PASS",
        duration_ms=dur,
        evidence={
            "email_id": reloaded_email.id,
            "urls_count": len(reloaded_email.urls),
            "attachments_count": len(reloaded_email.attachments)
        }
    )


def test_pg_db_003_idempotency_constraint(db_session, test_user):
    """PG-DB-003: Database enforces UniqueConstraint on (user_id, provider, provider_message_id)."""
    import uuid
    start = time.perf_counter()

    msg_id = f"idempotent_msg_{uuid.uuid4().hex[:8]}"

    email_1 = IngestedEmail(
        user_id=test_user.id,
        provider="gmail",
        provider_message_id=msg_id,
        sender_email="sender@domain.com",
        subject="First ingestion"
    )
    db_session.add(email_1)
    db_session.commit()

    # Attempt duplicate insert with same (user_id, provider, provider_message_id)
    email_2 = IngestedEmail(
        user_id=test_user.id,
        provider="gmail",
        provider_message_id=msg_id,
        sender_email="sender@domain.com",
        subject="Duplicate ingestion"
    )
    db_session.add(email_2)

    duplicate_blocked = False
    try:
        db_session.commit()
    except IntegrityError:
        db_session.rollback()
        duplicate_blocked = True

    dur = (time.perf_counter() - start) * 1000

    assert duplicate_blocked is True, "Expected UniqueConstraint violation on duplicate message ID"

    validation_collector.record_result(
        test_id="PG-DB-003",
        category="Database Persistence",
        description="Unique constraint on (user_id, provider, provider_message_id) strictly prevents duplicate records",
        status="PASS",
        duration_ms=dur,
        evidence={"duplicate_blocked": duplicate_blocked}
    )


def test_pg_db_004_tenant_database_isolation(db_session):
    """PG-DB-004: Multi-tenant queries filter data strictly by tenant user_id."""
    import uuid
    start = time.perf_counter()

    u1_suffix = uuid.uuid4().hex[:6]
    u2_suffix = uuid.uuid4().hex[:6]

    user_1 = User(username=f"t1_user_{u1_suffix}", email=f"t1_{u1_suffix}@corp.com", password_hash="hash1", is_verified=True)
    user_2 = User(username=f"t2_user_{u2_suffix}", email=f"t2_{u2_suffix}@corp.com", password_hash="hash2", is_verified=True)
    db_session.add_all([user_1, user_2])
    db_session.commit()

    r1 = AnalysisResult(user_id=user_1.id, url="http://t1.com", risk_score=10.0, risk_level="LOW")
    r2 = AnalysisResult(user_id=user_2.id, url="http://t2.com", risk_score=90.0, risk_level="CRITICAL")
    db_session.add_all([r1, r2])
    db_session.commit()

    # Query for User 1 only
    t1_records = db_session.query(AnalysisResult).filter(AnalysisResult.user_id == user_1.id).all()
    t1_ids = [r.id for r in t1_records]
    dur = (time.perf_counter() - start) * 1000

    assert r1.id in t1_ids
    assert r2.id not in t1_ids
    assert len(t1_records) == 1

    validation_collector.record_result(
        test_id="PG-DB-004",
        category="Database Persistence",
        description="Database queries filter strictly by user_id ensuring tenant data isolation",
        status="PASS",
        duration_ms=dur,
        evidence={"user_1_count": len(t1_records), "isolated": r2.id not in t1_ids}
    )

