"""
tests/test_gmail_integration.py

Comprehensive test suite for Gmail Mailbox Integration:
- OAuth 2.0 flow & HMAC state verification
- Credential encryption/decryption at rest (Fernet)
- Gmail API interactions (Profile, Watch, History, Raw message retrieval)
- Cloud Pub/Sub push notification webhook endpoint
- Incremental history sync & Raw RFC 822 ingestion into unified analyzer
- Account disconnection and watch teardown
- Watch renewal background job
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app import auth, config, database, models
from app.main import app
from app.services import crypto_service, email_service, gmail_service, gmail_sync_job, mail_ingestion_queue

client = TestClient(app)

TEST_USER_1 = {
    "username": "gmail_secops_user",
    "email": "secops.gmail@phishguard.test",
    "password": "SecurePassword123!",
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
            (models.User.email == TEST_USER_1["email"])
            | (models.User.username == TEST_USER_1["username"])
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


def create_authenticated_user(user_data=TEST_USER_1):
    """Helper to create and authenticate a test user, returning auth headers and user info."""
    db = database.SessionLocal()
    try:
        user = models.User(
            username=user_data["username"],
            email=user_data["email"],
            password_hash=auth.hash_password(user_data["password"]),
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id
        token = auth.create_access_token(data={"sub": str(user.id), "username": user.username})
        headers = {"Authorization": f"Bearer {token}"}
        return {"headers": headers, "user_id": user_id, "email": user_data["email"]}
    finally:
        db.close()


# ============================================================================
# 1. OAUTH STATE & CRYPTO TESTS
# ============================================================================

def test_oauth_state_generation_and_verification():
    user_id = 42
    state = gmail_service.generate_oauth_state(user_id)
    assert state is not None
    assert "." in state

    # Verify matching state
    verified_uid = gmail_service.verify_oauth_state(state)
    assert verified_uid == user_id

    # Verify tampered state fails
    parts = state.split(".")
    tampered = f"{parts[0]}.invalid_signature"
    assert gmail_service.verify_oauth_state(tampered) is None

    # Verify empty or malformed state fails
    assert gmail_service.verify_oauth_state("") is None
    assert gmail_service.verify_oauth_state("invalid") is None


def test_credential_encryption_and_decryption():
    test_creds = {
        "access_token": "ya29.test_access_token_12345",
        "refresh_token": "1//test_refresh_token_67890",
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    encrypted = crypto_service.encrypt_credentials(test_creds)
    assert encrypted is not None
    assert isinstance(encrypted, str)
    assert encrypted != json.dumps(test_creds)

    decrypted = crypto_service.decrypt_credentials(encrypted)
    assert decrypted["access_token"] == test_creds["access_token"]
    assert decrypted["refresh_token"] == test_creds["refresh_token"]


# ============================================================================
# 2. GMAIL OAUTH CONNECT & CALLBACK ENDPOINTS
# ============================================================================

def test_gmail_connect_endpoint():
    auth_user = create_authenticated_user(TEST_USER_1)
    response = client.get("/api/v1/mail-security/gmail/connect", headers=auth_user["headers"])
    assert response.status_code == 200
    data = response.json()
    assert "auth_url" in data
    assert "accounts.google.com/o/oauth2/v2/auth" in data["auth_url"]
    assert "gmail.readonly" in data["auth_url"]


@patch("app.services.gmail_service.setup_mailbox_watch")
@patch("app.services.gmail_service.get_gmail_profile")
@patch("app.services.gmail_service.exchange_code_for_tokens")
def test_gmail_callback_success(mock_exchange, mock_profile, mock_watch):
    auth_user = create_authenticated_user(TEST_USER_1)
    mock_exchange.return_value = {
        "access_token": "mock_access_token",
        "refresh_token": "mock_refresh_token",
        "expires_in": 3600,
        "token_type": "Bearer",
    }
    mock_profile.return_value = {
        "emailAddress": "security@gmail.com",
        "historyId": "10001",
    }
    mock_watch.return_value = {
        "historyId": "10001",
        "expiration": "1770000000000",
    }

    state = gmail_service.generate_oauth_state(auth_user["user_id"])

    response = client.get(
        f"/api/v1/mail-security/gmail/callback?code=mock_code&state={state}",
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "status=gmail_connected" in response.headers["location"]

    # Check database persistence
    db = database.SessionLocal()
    try:
        account = (
            db.query(models.MailAccount)
            .filter(models.MailAccount.user_id == auth_user["user_id"], models.MailAccount.provider == "gmail")
            .first()
        )
        assert account is not None
        assert account.account_email == "security@gmail.com"
        assert account.history_id == "10001"
        assert account.is_active is True
        assert account.encrypted_credentials is not None
    finally:
        db.close()


def test_gmail_callback_invalid_state():
    response = client.get(
        "/api/v1/mail-security/gmail/callback?code=mock_code&state=bad_state",
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "error=invalid_oauth_state" in response.headers["location"]


# ============================================================================
# 3. PUBSUB PUSH NOTIFICATION WEBHOOK
# ============================================================================

def test_pubsub_webhook_push_notification():
    auth_user = create_authenticated_user(TEST_USER_1)
    db = database.SessionLocal()
    try:
        account = models.MailAccount(
            user_id=auth_user["user_id"],
            provider="gmail",
            account_email="alerts@phishguard.test",
            is_active=True,
            history_id="5000",
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        account_id = account.id
    finally:
        db.close()

    pubsub_msg = {
        "emailAddress": "alerts@phishguard.test",
        "historyId": "5050",
    }
    raw_b64 = base64.b64encode(json.dumps(pubsub_msg).encode("utf-8")).decode("utf-8")

    payload = {
        "message": {
            "data": raw_b64,
            "messageId": "pubsub-msg-12345",
            "publishTime": "2026-10-06T12:00:00Z",
        },
        "subscription": "projects/test/subscriptions/gmail-sub",
    }

    with patch("app.services.mail_ingestion_queue.enqueue_gmail_sync") as mock_enqueue:
        response = client.post(
            "/api/v1/mail-security/gmail/pubsub",
            json=payload,
            headers={"X-Test-Fixture": "true"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        mock_enqueue.assert_called_once_with(account_id=account_id, history_id="5050")


def test_pubsub_webhook_empty_payload():
    response = client.post(
        "/api/v1/mail-security/gmail/pubsub",
        json={"message": {}},
        headers={"X-Test-Fixture": "true"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ============================================================================
# 4. GMAIL SYNC, RAW EML RETRIEVAL & UNIFIED INGESTION
# ============================================================================

@patch("app.services.gmail_service.fetch_raw_message_bytes")
@patch("app.services.gmail_service.fetch_history_changes")
@patch("app.services.gmail_service.get_valid_access_token")
def test_gmail_account_sync_worker(mock_token, mock_history, mock_raw_msg):
    auth_user = create_authenticated_user(TEST_USER_1)
    creds = {"access_token": "ya29.test", "refresh_token": "1//test"}
    enc_creds = crypto_service.encrypt_credentials(creds)

    db = database.SessionLocal()
    try:
        account = models.MailAccount(
            user_id=auth_user["user_id"],
            provider="gmail",
            account_email="analyst@domain.com",
            encrypted_credentials=enc_creds,
            encrypted_token=enc_creds,
            history_id="1000",
            is_active=True,
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        acc_id = account.id
    finally:
        db.close()

    mock_token.return_value = ("ya29.valid_access_token", creds)
    mock_history.return_value = (["msg_test_001"], "1050")

    # Mock RFC 822 Email content
    mock_eml_content = (
        b"From: phisher@badsite.com\r\n"
        b"To: analyst@domain.com\r\n"
        b"Subject: Urgent Account Verification Required\r\n"
        b"Date: Tue, 06 Oct 2026 12:00:00 +0000\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please verify your credentials immediately at http://login-security-check.ru/verify\r\n"
    )
    mock_raw_msg.return_value = mock_eml_content

    res = mail_ingestion_queue.process_gmail_account_sync(
        account_id=acc_id,
        target_history_id="1050",
    )

    assert res["status"] == "success"
    assert res["synced_count"] == 1
    assert res["new_history_id"] == "1050"

    # Verify IngestedEmail was created and analyzed
    db = database.SessionLocal()
    try:
        ingested = (
            db.query(models.IngestedEmail)
            .filter(models.IngestedEmail.provider_message_id == "msg_test_001")
            .first()
        )
        assert ingested is not None
        assert ingested.provider == "gmail"
        assert ingested.sender_email == "phisher@badsite.com"
        assert ingested.subject == "Urgent Account Verification Required"
        assert ingested.status == "analyzed"
        assert ingested.risk_level in ["MEDIUM", "HIGH", "CRITICAL"]

        # Verify idempotency: running sync again does not duplicate record
        res2 = mail_ingestion_queue.process_gmail_account_sync(
            account_id=acc_id,
            target_history_id="1050",
        )
        assert res2["status"] == "success"
        assert res2["synced_count"] == 0

        total_count = (
            db.query(models.IngestedEmail)
            .filter(models.IngestedEmail.provider_message_id == "msg_test_001")
            .count()
        )
        assert total_count == 1
    finally:
        db.close()


# ============================================================================
# 5. ACCOUNT DISCONNECTION & STOP WATCH
# ============================================================================

@patch("app.services.gmail_service.stop_mailbox_watch")
@patch("app.services.gmail_service.get_valid_access_token")
def test_disconnect_mail_account_stops_watch(mock_token, mock_stop_watch):
    auth_user = create_authenticated_user(TEST_USER_1)
    creds = {"access_token": "ya29.test", "refresh_token": "1//test"}
    enc_creds = crypto_service.encrypt_credentials(creds)

    db = database.SessionLocal()
    try:
        account = models.MailAccount(
            user_id=auth_user["user_id"],
            provider="gmail",
            account_email="disconnect-me@domain.com",
            encrypted_credentials=enc_creds,
            encrypted_token=enc_creds,
            is_active=True,
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        acc_id = account.id
    finally:
        db.close()

    mock_token.return_value = ("ya29.valid_access_token", creds)

    response = client.delete(f"/api/v1/mail-security/accounts/{acc_id}", headers=auth_user["headers"])
    assert response.status_code == 200
    mock_stop_watch.assert_called_once_with("ya29.valid_access_token")

    db = database.SessionLocal()
    try:
        deleted = db.query(models.MailAccount).filter(models.MailAccount.id == acc_id).first()
        assert deleted is None
    finally:
        db.close()


# ============================================================================
# 6. WATCH RENEWAL JOB
# ============================================================================

@patch("app.services.gmail_service.setup_mailbox_watch")
@patch("app.services.gmail_service.get_valid_access_token")
def test_renew_expiring_gmail_watches(mock_token, mock_watch):
    auth_user = create_authenticated_user(TEST_USER_1)
    creds = {"access_token": "ya29.test", "refresh_token": "1//test"}
    enc_creds = crypto_service.encrypt_credentials(creds)

    db = database.SessionLocal()
    try:
        # Account expiring in 2 hours (needs renewal)
        expiring_acc = models.MailAccount(
            user_id=auth_user["user_id"],
            provider="gmail",
            account_email="expiring@domain.com",
            encrypted_credentials=enc_creds,
            encrypted_token=enc_creds,
            watch_expiration=datetime.utcnow() + timedelta(hours=2),
            is_active=True,
        )
        # Account expiring in 5 days (does not need renewal)
        fresh_acc = models.MailAccount(
            user_id=auth_user["user_id"],
            provider="gmail",
            account_email="fresh@domain.com",
            encrypted_credentials=enc_creds,
            encrypted_token=enc_creds,
            watch_expiration=datetime.utcnow() + timedelta(days=5),
            is_active=True,
        )
        db.add_all([expiring_acc, fresh_acc])
        db.commit()
    finally:
        db.close()

    mock_token.return_value = ("ya29.valid_token", creds)
    mock_watch.return_value = {
        "historyId": "20001",
        "expiration": "1780000000000",
    }

    results = gmail_sync_job.renew_expiring_gmail_watches()
    assert results["total_checked"] == 2
    assert results["renewed"] == 1
    assert results["failed"] == 0
