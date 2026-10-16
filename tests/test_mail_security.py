"""
tests/test_mail_security.py

Enterprise Mail Security Test Suite.
Verifies:
1. Mailbox account connectivity (Gmail, Microsoft 365 / Outlook).
2. Mailbox sync and disconnect lifecycle.
3. Automated email ingestion webhook and multi-layer analysis execution.
4. Idempotency enforcement on (user_id, provider, provider_message_id).
5. Quarantine / detection classifications (clean, suspicious, phishing, quishing).
6. Multi-tenant isolation and IDOR prevention for mailbox records and telemetry.
7. Mail Security stats and metrics aggregation.
"""

from datetime import datetime, timedelta
import json
import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import models, database, auth as auth_utils, schemas
from app.services import email_service

client = TestClient(app)

TEST_USER_1 = {
    "username": "secops_admin",
    "email": "secops@phishguard.org",
    "password": "SecurePassword123!",
}

TEST_USER_2 = {
    "username": "other_analyst",
    "email": "analyst2@phishguard.org",
    "password": "SecurePassword456@",
}


@pytest.fixture(scope="function", autouse=True)
def reset_database():
    """Ensure tables exist and clear test data for clean test isolation."""
    database.engine.dispose()
    models.Base.metadata.create_all(bind=database.engine)
    db = database.SessionLocal()
    try:
        db.query(models.IngestedEmail).delete()
        db.query(models.MailAccount).delete()
        db.query(models.AnalysisResult).delete()
        db.query(models.User).filter(
            models.User.email.in_([TEST_USER_1["email"], TEST_USER_2["email"]])
            | models.User.username.in_([TEST_USER_1["username"], TEST_USER_2["username"]])
        ).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    yield


@pytest.fixture(autouse=True)
def mock_smtp_sender(monkeypatch):
    """Mock outbound email OTPs."""
    mock = MagicMock(return_value=True)
    monkeypatch.setattr(email_service, "send_otp_email", mock)
    return mock


def create_authenticated_user(user_data):
    """Helper to register, verify, and authenticate a test user, returning auth headers and user object."""
    client.post("/api/v1/auth/register", json=user_data)
    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == user_data["email"]).first()
        user.is_verified = True
        user.is_active = True
        db.commit()
        db.refresh(user)
        user_id = user.id
    finally:
        db.close()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": user_data["email"], "password": user_data["password"]},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-Test-Fixture": "true"}
    return {"headers": headers, "user_id": user_id, "email": user_data["email"]}


# ============================================================================
# 1. MAILBOX ACCOUNT CONNECTIVITY
# ============================================================================

def test_connect_and_list_mail_accounts():
    """Users can connect Gmail and Outlook accounts and list them."""
    auth_user = create_authenticated_user(TEST_USER_1)
    headers = auth_user["headers"]

    # Connect Gmail
    r1 = client.post(
        "/api/v1/mail-security/accounts/connect",
        json={"provider": "gmail", "account_email": "inbox.alice@company.com"},
        headers=headers,
    )
    assert r1.status_code == 201
    d1 = r1.json()
    assert d1["provider"] == "gmail"
    assert d1["account_email"] == "inbox.alice@company.com"
    assert d1["sync_status"] == "connected"

    # Connect Outlook
    r2 = client.post(
        "/api/v1/mail-security/accounts/connect",
        json={"provider": "outlook", "account_email": "alice@enterprisemsft.com"},
        headers=headers,
    )
    assert r2.status_code == 201
    assert r2.json()["provider"] == "outlook"

    # List accounts
    r3 = client.get("/api/v1/mail-security/accounts", headers=headers)
    assert r3.status_code == 200
    accounts = r3.json()
    assert len(accounts) == 2
    emails = [a["account_email"] for a in accounts]
    assert "inbox.alice@company.com" in emails
    assert "alice@enterprisemsft.com" in emails


def test_sync_and_disconnect_mail_account():
    """Users can trigger mailbox sync and disconnect accounts."""
    auth_user = create_authenticated_user(TEST_USER_1)
    headers = auth_user["headers"]

    connect_res = client.post(
        "/api/v1/mail-security/accounts/connect",
        json={"provider": "gmail", "account_email": "sync.test@company.com"},
        headers=headers,
    )
    account_id = connect_res.json()["id"]

    # Trigger Sync
    sync_res = client.post(f"/api/v1/mail-security/accounts/{account_id}/sync", headers=headers)
    assert sync_res.status_code == 200
    assert sync_res.json()["sync_status"] == "connected"

    # Disconnect
    del_res = client.delete(f"/api/v1/mail-security/accounts/{account_id}", headers=headers)
    assert del_res.status_code == 200

    # Verify deleted
    list_res = client.get("/api/v1/mail-security/accounts", headers=headers)
    assert len(list_res.json()) == 0


# ============================================================================
# 2. EMAIL INGESTION & IDEMPOTENCY
# ============================================================================

def test_ingest_email_and_execute_analysis():
    """Ingesting an email executes multi-layer analysis and populates risk assessment."""
    auth_user = create_authenticated_user(TEST_USER_1)
    headers = auth_user["headers"]

    payload = {
        "provider": "gmail",
        "provider_message_id": "msg_xyz_1001",
        "sender_email": "notifications@security-alert-center.com",
        "sender_name": "Microsoft Security Team",
        "recipient_email": auth_user["email"],
        "subject": "CRITICAL: Urgent Password Reset Required",
        "body_text": "Please update your password immediately at http://192.168.1.1/login or your account will be suspended within 24 hours.",
        "body_html": "<p>Please update your password immediately at <a href='http://192.168.1.1/login'>https://login.microsoftonline.com</a></p>",
    }

    ingest_res = client.post("/api/v1/mail-security/ingest", json=payload, headers=headers)
    assert ingest_res.status_code == 201
    data = ingest_res.json()

    assert data["provider"] == "gmail"
    assert data["provider_message_id"] == "msg_xyz_1001"
    assert data["status"] == "analyzed"
    assert data["risk_score"] is not None
    assert data["risk_score"] > 0
    assert data["risk_level"] in ["HIGH", "CRITICAL", "MEDIUM"]
    assert data["classification"] in ["phishing", "suspicious"]
    assert data["analysis_id"] is not None
    assert len(data["threat_signals"]) > 0


def test_ingestion_idempotency_enforcement():
    """Re-ingesting the exact same message ID returns the existing analysis without duplicate records."""
    auth_user = create_authenticated_user(TEST_USER_1)
    headers = auth_user["headers"]

    payload = {
        "provider": "outlook",
        "provider_message_id": "msg_idempotent_999",
        "sender_email": "service@trustedcorp.com",
        "sender_name": "Service Team",
        "recipient_email": auth_user["email"],
        "subject": "Monthly Report",
        "body_text": "Hello, here is your clean monthly report summary.",
    }

    # First ingest
    r1 = client.post("/api/v1/mail-security/ingest", json=payload, headers=headers)
    assert r1.status_code == 201
    first_id = r1.json()["id"]

    # Second ingest (duplicate webhook or sync event)
    r2 = client.post("/api/v1/mail-security/ingest", json=payload, headers=headers)
    assert r2.status_code == 201  # Or 200
    second_id = r2.json()["id"]

    assert first_id == second_id

    # Verify total record count is exactly 1
    list_res = client.get("/api/v1/mail-security/messages", headers=headers)
    assert list_res.json()["total"] == 1


# ============================================================================
# 3. MULTI-TENANT ISOLATION & IDOR PREVENTION
# ============================================================================

def test_tenant_isolation_on_messages_and_accounts():
    """User 2 cannot view or access User 1's ingested emails or mailbox accounts."""
    u1 = create_authenticated_user(TEST_USER_1)
    u2 = create_authenticated_user(TEST_USER_2)

    # User 1 connects account and ingests email
    client.post(
        "/api/v1/mail-security/accounts/connect",
        json={"provider": "gmail", "account_email": "u1.inbox@company.com"},
        headers=u1["headers"],
    )
    r1 = client.post(
        "/api/v1/mail-security/ingest",
        json={
            "provider": "gmail",
            "provider_message_id": "secret_msg_u1",
            "sender_email": "boss@company.com",
            "subject": "Confidential Strategy",
            "body_text": "Top secret meeting tomorrow.",
        },
        headers=u1["headers"],
    )
    u1_msg_id = r1.json()["id"]

    # User 2 lists messages -> should be empty
    u2_list = client.get("/api/v1/mail-security/messages", headers=u2["headers"])
    assert u2_list.status_code == 200
    assert u2_list.json()["total"] == 0
    assert len(u2_list.json()["items"]) == 0

    # User 2 tries to GET User 1's specific message by ID -> 403 Forbidden
    u2_get = client.get(f"/api/v1/mail-security/messages/{u1_msg_id}", headers=u2["headers"])
    assert u2_get.status_code == 403

    # User 2 lists accounts -> should be empty
    u2_accounts = client.get("/api/v1/mail-security/accounts", headers=u2["headers"])
    assert len(u2_accounts.json()) == 0


# ============================================================================
# 4. MAIL SECURITY TELEMETRY & STATS
# ============================================================================

def test_mail_security_stats_aggregation():
    """Mail security stats endpoint aggregates scanned counts and classifications."""
    u1 = create_authenticated_user(TEST_USER_1)
    headers = u1["headers"]

    # Ingest clean email
    client.post(
        "/api/v1/mail-security/ingest",
        json={
            "provider": "gmail",
            "provider_message_id": "clean_msg_1",
            "sender_email": "colleague@company.com",
            "subject": "Project update",
            "body_text": "Everything is proceeding on schedule.",
        },
        headers=headers,
    )

    # Ingest malicious phishing email
    client.post(
        "/api/v1/mail-security/ingest",
        json={
            "provider": "gmail",
            "provider_message_id": "phish_msg_2",
            "sender_email": "security@fake-bank-login.com",
            "sender_name": "Chase Security Alert",
            "subject": "URGENT: Unauthorized login detected",
            "body_text": "Verify your identity at http://185.220.101.5/chase-verify immediately.",
        },
        headers=headers,
    )

    stats_res = client.get("/api/v1/mail-security/stats", headers=headers)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_scanned"] == 2
    assert (stats["phishing_count"] + stats["suspicious_count"]) >= 1
    assert stats["clean_count"] >= 1


# ============================================================================
# 5. CHILD MODELS & SETTINGS PERSISTENCE
# ============================================================================

def test_extracted_urls_and_child_models():
    """Extracted URLs are persisted to child models and serialized in API responses."""
    u1 = create_authenticated_user(TEST_USER_1)
    headers = u1["headers"]

    payload = {
        "provider": "gmail",
        "provider_message_id": "msg_with_urls_1",
        "sender_email": "alerts@account-security.net",
        "sender_name": "Account Center",
        "subject": "Security notice",
        "body_html": "<p>Please visit <a href='http://185.220.101.5/verify'>Account Review</a></p>",
        "body_text": "Or click http://185.220.101.5/verify",
    }

    resp = client.post("/api/v1/mail-security/ingest", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["urls"] is not None
    assert len(data["urls"]) >= 1
    assert any("185.220.101.5" in u["url"] for u in data["urls"])

    # Direct database verification of child table
    db = database.SessionLocal()
    try:
        urls_in_db = db.query(models.EmailURL).filter(models.EmailURL.ingested_email_id == data["id"]).all()
        assert len(urls_in_db) >= 1
        assert any("185.220.101.5" in u.url for u in urls_in_db)
    finally:
        db.close()


def test_mail_security_settings_lifecycle():
    """Users can get and update their mailbox scanning preferences."""
    u1 = create_authenticated_user(TEST_USER_1)
    headers = u1["headers"]

    # Connect an account first
    client.post(
        "/api/v1/mail-security/accounts/connect",
        json={"provider": "gmail", "account_email": "settings.test@phishguard.org"},
        headers=headers,
    )

    # Get settings defaults
    get_res = client.get("/api/v1/mail-security/settings", headers=headers)
    assert get_res.status_code == 200
    defaults = get_res.json()
    assert defaults["scan_enabled"] is True
    assert defaults["attachment_scan_enabled"] is True
    assert defaults["qr_scan_enabled"] is True
    assert defaults["ai_analysis_enabled"] is True
    assert defaults["retention_days"] == 90

    # Update settings
    update_res = client.put(
        "/api/v1/mail-security/settings",
        json={
            "scan_enabled": True,
            "attachment_scan_enabled": False,
            "qr_scan_enabled": True,
            "ai_analysis_enabled": True,
            "retention_days": 180,
        },
        headers=headers,
    )
    assert update_res.status_code == 200
    updated = update_res.json()
    assert updated["attachment_scan_enabled"] is False
    assert updated["retention_days"] == 180

    # Verify persisted in database
    db = database.SessionLocal()
    try:
        acc = db.query(models.MailAccount).filter(models.MailAccount.user_id == u1["user_id"]).first()
        assert acc.attachment_scan_enabled is False
        assert acc.retention_days == 180
    finally:
        db.close()
