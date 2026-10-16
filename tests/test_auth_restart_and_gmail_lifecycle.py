"""
tests/test_auth_restart_and_gmail_lifecycle.py

Comprehensive test suite verifying:
1. Deterministic database persistence and schema resilience across server restart simulations.
2. User registration, OTP verification, and login persistence across engine disposal and re-initialization.
3. Gmail OAuth token lifecycle:
   - Valid token reuse without redundant network roundtrips.
   - Automatic pre-emptive refresh on approaching expiry (5-minute window).
   - Automatic refresh on expired token.
   - Preservation of existing refresh_token when Google does not rotate it.
   - Storage of updated encrypted credentials and token_expires_at in database.
   - Explicit handling of invalid_grant / revoked consent (transitions sync_status to requires_reauth).
   - Graceful recovery from corrupted / missing credentials.
4. Symmetric encryption key stability and credential protection at rest.
5. Absolute prevention of secret, token, or key leakage in logs or error messages.
6. Sync worker and watch renewal lifecycle behaviors.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import auth as auth_utils, config, database, models, schemas
from app.main import app
from app.services import crypto_service, gmail_service, gmail_sync_job, mail_ingestion_queue


# ============================================================================
# TEST FIXTURES & ISOLATION
# ============================================================================

@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch):
    """
    Create a persistent SQLite database on disk in tmp_path to simulate server
    restarts, engine disposals, and persistent storage lifecycles.
    """
    db_file = tmp_path / "test_phishguard_persistent.db"
    db_url = f"sqlite:///{db_file}"

    test_engine = create_engine(db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Initialize schema
    models.Base.metadata.create_all(bind=test_engine)
    database.ensure_sqlite_schema(test_engine)

    # Patch global engine and SessionLocal so all workers use this test db
    monkeypatch.setattr(database, "engine", test_engine)
    monkeypatch.setattr(database, "SessionLocal", TestingSessionLocal)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[database.get_db] = override_get_db

    yield {
        "engine": test_engine,
        "session_factory": TestingSessionLocal,
        "db_file": db_file,
        "db_url": db_url,
    }

    # Teardown
    app.dependency_overrides.pop(database.get_db, None)
    test_engine.dispose()


@pytest.fixture
def client(isolated_db):
    """FastAPI TestClient backed by the isolated test database."""
    return TestClient(app)


# ============================================================================
# 1. DATABASE PATH & PERSISTENCE DETERMINISM
# ============================================================================

def test_database_url_deterministic_resolution():
    """Verify that DATABASE_URL resolves deterministically to an absolute path."""
    assert os.path.isabs(config.DATABASE_URL.replace("sqlite:///", ""))
    assert "phishguard.db" in config.DATABASE_URL


def test_user_persistence_across_engine_restart(isolated_db):
    """
    Verify that user signup, OTP verification, and account data persist
    intact when the database engine is disposed and reconnected.
    """
    factory = isolated_db["session_factory"]
    engine = isolated_db["engine"]

    # 1. Create a verified user in first session
    with factory() as db:
        hashed_pw = auth_utils.hash_password("SecurePassword123!")
        user = models.User(
            email="persistence_test@example.com",
            username="persistuser",
            password_hash=hashed_pw,
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()
        user_id = user.id

    # 2. Simulate complete server shutdown & engine restart
    engine.dispose()
    restarted_engine = create_engine(isolated_db["db_url"], connect_args={"check_same_thread": False})
    RestartedSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=restarted_engine)
    database.ensure_sqlite_schema(restarted_engine)

    # 3. Verify user exists and credentials authenticate after restart
    with RestartedSessionLocal() as db:
        loaded_user = db.query(models.User).filter(models.User.id == user_id).first()
        assert loaded_user is not None
        assert loaded_user.email == "persistence_test@example.com"
        assert loaded_user.username == "persistuser"
        assert loaded_user.is_verified is True
        assert auth_utils.verify_password("SecurePassword123!", loaded_user.password_hash) is True
        assert auth_utils.verify_password("WrongPassword!", loaded_user.password_hash) is False

    restarted_engine.dispose()


def test_user_login_flow_across_simulated_restart(client, isolated_db, monkeypatch):
    """
    Test complete register -> OTP verify -> server restart simulation -> login flow via REST API.
    """
    factory = isolated_db["session_factory"]

    # 1. Register a new user
    signup_payload = {
        "email": "lifecycle_user@example.com",
        "username": "lifecycle_user",
        "password": "LifecyclePassword456!",
    }
    with patch("app.services.email_service.send_otp_email", return_value=True):
        res = client.post("/api/v1/auth/register", json=signup_payload)
        assert res.status_code == status.HTTP_201_CREATED, res.text

    # 2. Verify OTP in database
    with factory() as db:
        user = db.query(models.User).filter(models.User.email == "lifecycle_user@example.com").first()
        assert user is not None
        assert user.is_verified is False

        otp_record = (
            db.query(models.EmailVerificationOTP)
            .filter(models.EmailVerificationOTP.user_id == user.id)
            .order_by(models.EmailVerificationOTP.last_sent_at.desc())
            .first()
        )
        assert otp_record is not None

        # Verify OTP
        otp_val = "123456"
        otp_record.otp_hash = auth_utils.hash_otp(otp_val)
        otp_record.expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()

    verify_res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": "lifecycle_user@example.com", "otp": "123456"},
    )
    assert verify_res.status_code == status.HTTP_200_OK, verify_res.text

    # 3. Simulate Server Restart by creating a new engine instance
    isolated_db["engine"].dispose()
    restarted_engine = create_engine(isolated_db["db_url"], connect_args={"check_same_thread": False})
    RestartedSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=restarted_engine)
    monkeypatch.setattr(database, "engine", restarted_engine)
    monkeypatch.setattr(database, "SessionLocal", RestartedSessionLocal)

    def override_get_db():
        db = RestartedSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[database.get_db] = override_get_db

    # 4. Login after restart
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": "lifecycle_user@example.com",
            "password": "LifecyclePassword456!",
        },
    )
    assert login_res.status_code == status.HTTP_200_OK, login_res.text
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["user"]["email"] == "lifecycle_user@example.com"


# ============================================================================
# 2. GMAIL OAUTH TOKEN LIFECYCLE & AUTOMATIC REFRESH
# ============================================================================

def test_get_valid_access_token_active_token_no_network():
    """
    A token with remaining validity (> 300s) must be returned immediately
    without making any HTTP request to Google token endpoints.
    """
    creds = {
        "access_token": "active_valid_access_token_xyz",
        "refresh_token": "valid_refresh_token_123",
        "expires_at": int(time.time()) + 3600,  # 1 hour from now
    }

    with patch("httpx.Client") as mock_client:
        token, updated_creds = gmail_service.get_valid_access_token(creds)
        assert token == "active_valid_access_token_xyz"
        assert updated_creds["access_token"] == "active_valid_access_token_xyz"
        assert updated_creds["refresh_token"] == "valid_refresh_token_123"
        # Network must NOT be called
        mock_client.assert_not_called()


def test_get_valid_access_token_near_expiry_triggers_refresh():
    """
    A token expiring within the 300s buffer must trigger an automatic refresh,
    update access_token and expires_at, and preserve the existing refresh_token.
    """
    creds = {
        "access_token": "expiring_soon_access_token",
        "refresh_token": "original_refresh_token_abc",
        "expires_at": int(time.time()) + 120,  # 2 minutes from now (within 300s window)
    }

    fake_google_response = {
        "access_token": "brand_new_refreshed_access_token",
        "expires_in": 3599,
        "token_type": "Bearer",
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_google_response

    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp
    mock_client_instance.__enter__.return_value = mock_client_instance
    mock_client_instance.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client_instance):
        token, updated_creds = gmail_service.get_valid_access_token(creds)

        assert token == "brand_new_refreshed_access_token"
        assert updated_creds["access_token"] == "brand_new_refreshed_access_token"
        # Crucial check: original refresh_token must be preserved
        assert updated_creds["refresh_token"] == "original_refresh_token_abc"
        assert updated_creds["expires_at"] > int(time.time()) + 3500

        # Verify Google endpoint was called with correct parameters
        mock_client_instance.post.assert_called_once()
        call_args = mock_client_instance.post.call_args
        assert call_args[0][0] == gmail_service.GOOGLE_OAUTH_TOKEN_URL
        assert call_args[1]["data"]["grant_type"] == "refresh_token"
        assert call_args[1]["data"]["refresh_token"] == "original_refresh_token_abc"


def test_get_valid_access_token_expired_token_triggers_refresh():
    """
    A token whose expires_at is in the past must automatically refresh.
    """
    creds = {
        "access_token": "completely_expired_access_token",
        "refresh_token": "refresh_token_def",
        "expires_at": int(time.time()) - 1000,
    }

    fake_google_response = {
        "access_token": "fresh_access_token_after_expiration",
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_google_response

    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp
    mock_client_instance.__enter__.return_value = mock_client_instance
    mock_client_instance.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client_instance):
        token, updated_creds = gmail_service.get_valid_access_token(creds)
        assert token == "fresh_access_token_after_expiration"
        assert updated_creds["refresh_token"] == "refresh_token_def"


def test_get_valid_access_token_rotated_refresh_token_handled():
    """
    If Google rotates the refresh_token during refresh, the new refresh_token
    must replace the old one in updated_creds.
    """
    creds = {
        "access_token": "old_token",
        "refresh_token": "old_refresh_token",
        "expires_at": int(time.time()) - 10,
    }

    fake_google_response = {
        "access_token": "new_access_token",
        "refresh_token": "brand_new_rotated_refresh_token",
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_google_response

    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp
    mock_client_instance.__enter__.return_value = mock_client_instance
    mock_client_instance.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client_instance):
        _, updated_creds = gmail_service.get_valid_access_token(creds)
        assert updated_creds["access_token"] == "new_access_token"
        assert updated_creds["refresh_token"] == "brand_new_rotated_refresh_token"


def test_get_valid_access_token_revoked_raises_google_auth_revoked_error():
    """
    When Google responds with HTTP 400 (invalid_grant), get_valid_access_token
    must raise GoogleAuthRevokedError so callers know re-auth is needed.
    """
    creds = {
        "access_token": "expired_token",
        "refresh_token": "revoked_or_invalid_refresh_token",
        "expires_at": int(time.time()) - 100,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {
        "error": "invalid_grant",
        "error_description": "Token has been expired or revoked.",
    }

    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp
    mock_client_instance.__enter__.return_value = mock_client_instance
    mock_client_instance.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client_instance):
        with pytest.raises(gmail_service.GoogleAuthRevokedError) as exc_info:
            gmail_service.get_valid_access_token(creds)

        assert "invalid or revoked" in str(exc_info.value).lower() or "invalid_grant" in str(exc_info.value).lower()


def test_get_valid_access_token_missing_refresh_token_raises_revoked_error():
    """
    If credentials contain an expired access token and no refresh token,
    GoogleAuthRevokedError must be raised.
    """
    creds = {
        "access_token": "expired_token",
        "refresh_token": "",
        "expires_at": int(time.time()) - 100,
    }

    with pytest.raises(gmail_service.GoogleAuthRevokedError) as exc_info:
        gmail_service.get_valid_access_token(creds)

    assert "re-authentication required" in str(exc_info.value).lower() or "refresh token" in str(exc_info.value).lower()


# ============================================================================
# 3. ENCRYPTION AT REST STABILITY & CIPHERTEXT INTEGRITY
# ============================================================================

def test_fernet_credential_encryption_roundtrip_and_stability():
    """
    Verify that credentials encrypted with crypto_service can be decrypted
    reliably, preserve all fields, and handle corrupted strings safely.
    """
    original_creds = {
        "access_token": "ya29.a0AfH6SMA-test-access-token",
        "refresh_token": "1//04test-refresh-token",
        "expires_in": 3599,
        "expires_at": 1799999999,
        "token_type": "Bearer",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
    }

    ciphertext = crypto_service.encrypt_credentials(original_creds)
    assert isinstance(ciphertext, str)
    assert len(ciphertext) > 50
    # Ciphertext must not contain plaintext tokens
    assert "ya29" not in ciphertext
    assert "1//04" not in ciphertext

    decrypted = crypto_service.decrypt_credentials(ciphertext)
    assert decrypted == original_creds

    # Corrupted ciphertext handling
    bad_decrypted = crypto_service.decrypt_credentials("invalid_ciphertext_garbage_data")
    assert bad_decrypted == {}

    empty_decrypted = crypto_service.decrypt_credentials(None)
    assert empty_decrypted == {}


# ============================================================================
# 4. BACKGROUND SYNC WORKER & REAUTH STATE TRANSITIONS
# ============================================================================

def test_sync_worker_auto_refreshes_and_persists_credentials(isolated_db):
    """
    When the sync worker runs on an account whose token is expiring soon,
    it must refresh the token and update the encrypted credentials and token_expires_at in the DB.
    """
    factory = isolated_db["session_factory"]

    # 1. Create user and mail account with expiring token
    with factory() as db:
        user = models.User(
            email="sync_worker_test@example.com",
            username="sync_worker_user",
            password_hash=auth_utils.hash_password("Pass123!"),
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()

        expiring_creds = {
            "access_token": "old_expiring_access_tok",
            "refresh_token": "worker_refresh_tok",
            "expires_at": int(time.time()) + 60,  # Expiring in 60s
        }
        enc = crypto_service.encrypt_credentials(expiring_creds)

        acc = models.MailAccount(
            user_id=user.id,
            provider="gmail",
            account_email="sync_worker_test@gmail.com",
            encrypted_credentials=enc,
            encrypted_token=enc,
            is_active=True,
            sync_status="connected",
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

    # 2. Mock Google responses for refresh & history
    fake_refreshed_token_data = {
        "access_token": "new_refreshed_token_from_worker",
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_refreshed_token_data

    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client), \
         patch("app.services.gmail_service.fetch_history_changes", return_value=([], "5000")):
        res = mail_ingestion_queue.process_gmail_account_sync(acc_id, db_session_factory=factory)
        assert res["status"] == "success"

    # 3. Verify DB record was updated with refreshed credentials
    with factory() as db:
        updated_acc = db.query(models.MailAccount).filter(models.MailAccount.id == acc_id).first()
        assert updated_acc.sync_status == "connected"
        assert updated_acc.last_error is None

        decrypted = crypto_service.decrypt_credentials(updated_acc.encrypted_credentials)
        assert decrypted["access_token"] == "new_refreshed_token_from_worker"
        assert decrypted["refresh_token"] == "worker_refresh_tok"
        assert updated_acc.token_expires_at is not None


def test_sync_worker_handles_revoked_token_with_requires_reauth(isolated_db):
    """
    When refresh fails with invalid_grant, the sync worker must transition
    the MailAccount to sync_status='requires_reauth' with a clear diagnostic message.
    """
    factory = isolated_db["session_factory"]

    with factory() as db:
        user = models.User(
            email="revoked_test@example.com",
            username="revoked_user",
            password_hash=auth_utils.hash_password("Pass123!"),
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()

        expired_creds = {
            "access_token": "expired_tok",
            "refresh_token": "revoked_refresh_tok",
            "expires_at": int(time.time()) - 500,
        }
        enc = crypto_service.encrypt_credentials(expired_creds)

        acc = models.MailAccount(
            user_id=user.id,
            provider="gmail",
            account_email="revoked_test@gmail.com",
            encrypted_credentials=enc,
            encrypted_token=enc,
            is_active=True,
            sync_status="connected",
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"error": "invalid_grant", "error_description": "Token has been revoked"}

    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client):
        res = mail_ingestion_queue.process_gmail_account_sync(acc_id, db_session_factory=factory)
        assert res["status"] == "error"
        assert "re-authentication" in res["message"].lower() or "required" in res["message"].lower()

    with factory() as db:
        updated_acc = db.query(models.MailAccount).filter(models.MailAccount.id == acc_id).first()
        assert updated_acc.sync_status == "requires_reauth"
        assert "reconnect" in updated_acc.last_error.lower() or "revoked" in updated_acc.last_error.lower()


# ============================================================================
# 5. WATCH RENEWAL PERSISTENCE & REAUTH
# ============================================================================

def test_renew_expiring_gmail_watches_refreshes_and_persists(isolated_db):
    """
    Watch renewal job must refresh expiring tokens and persist the new credentials.
    """
    factory = isolated_db["session_factory"]

    with factory() as db:
        user = models.User(
            email="watch_renew_test@example.com",
            username="watch_renew_user",
            password_hash=auth_utils.hash_password("Pass123!"),
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()

        expiring_creds = {
            "access_token": "expiring_watch_token",
            "refresh_token": "watch_refresh_tok",
            "expires_at": int(time.time()) + 30,  # Expiring soon
        }
        enc = crypto_service.encrypt_credentials(expiring_creds)

        acc = models.MailAccount(
            user_id=user.id,
            provider="gmail",
            account_email="watch_renew_test@gmail.com",
            encrypted_credentials=enc,
            encrypted_token=enc,
            is_active=True,
            sync_status="connected",
            watch_expiration=datetime.utcnow() + timedelta(hours=2),  # Needs renewal (<24h)
        )
        db.add(acc)
        db.commit()
        acc_id = acc.id

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "refreshed_for_watch_renewal",
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client), \
         patch("app.services.gmail_service.setup_mailbox_watch", return_value={"expiration": "1799999999000", "historyId": "9999"}):
        res = gmail_sync_job.renew_expiring_gmail_watches(db_session_factory=factory)
        assert res["renewed"] == 1
        assert res["failed"] == 0

    with factory() as db:
        updated_acc = db.query(models.MailAccount).filter(models.MailAccount.id == acc_id).first()
        decrypted = crypto_service.decrypt_credentials(updated_acc.encrypted_credentials)
        assert decrypted["access_token"] == "refreshed_for_watch_renewal"
        assert updated_acc.history_id == "9999"


# ============================================================================
# 6. MANUAL SYNC ENDPOINT PRESERVES STATUS
# ============================================================================

def test_manual_sync_endpoint_preserves_reauth_status(client, isolated_db):
    """
    When POST /accounts/{id}/sync is called for an account whose token was revoked,
    the response must reflect sync_status='requires_reauth' rather than resetting to 'connected'.
    """
    factory = isolated_db["session_factory"]

    with factory() as db:
        user = models.User(
            email="manual_sync_reauth@example.com",
            username="manual_sync_user",
            password_hash=auth_utils.hash_password("Pass123!"),
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()

        expired_creds = {
            "access_token": "expired_token_val",
            "refresh_token": "revoked_token_val",
            "expires_at": int(time.time()) - 1000,
        }
        enc = crypto_service.encrypt_credentials(expired_creds)

        acc = models.MailAccount(
            user_id=user.id,
            provider="gmail",
            account_email="manual_sync_reauth@gmail.com",
            encrypted_credentials=enc,
            encrypted_token=enc,
            is_active=True,
            sync_status="connected",
        )
        db.add(acc)
        db.commit()
        user_id = user.id
        acc_id = acc.id

    auth_token = auth_utils.create_access_token(data={"sub": str(user_id)})
    headers = {"Authorization": f"Bearer {auth_token}"}

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"error": "invalid_grant"}

    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client):
        res = client.post(f"/api/v1/mail-security/accounts/{acc_id}/sync", headers=headers)
        assert res.status_code == status.HTTP_200_OK, res.text
        data = res.json()
        assert data["sync_status"] == "requires_reauth"
        assert data["last_error"] is not None


# ============================================================================
# 7. LOG SANITIZATION & NO SECRET LEAKAGE
# ============================================================================

def test_no_secret_or_token_leakage_in_logs(caplog):
    """
    Verify that throughout token refresh operations, errors, and decryption,
    plaintext secrets (refresh tokens, access tokens, client secret) never appear in logs.
    """
    caplog.set_level(logging.DEBUG)

    sensitive_refresh_token = "secret_refresh_token_12345_sensitive"
    sensitive_access_token = "secret_access_token_67890_sensitive"

    creds = {
        "access_token": sensitive_access_token,
        "refresh_token": sensitive_refresh_token,
        "expires_at": int(time.time()) - 100,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {
        "error": "invalid_grant",
        "error_description": "Token has been expired or revoked.",
    }

    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("httpx.Client", return_value=mock_client):
        try:
            gmail_service.get_valid_access_token(creds)
        except Exception:
            pass

    # Check all logged text
    log_text = caplog.text
    assert sensitive_refresh_token not in log_text
    assert sensitive_access_token not in log_text
    assert config.GOOGLE_CLIENT_SECRET not in log_text if config.GOOGLE_CLIENT_SECRET else True
