"""
tests/test_pubsub_auth.py

Test suite for Google Cloud Pub/Sub Push Authentication & OIDC JWT Verification:
1. Validate signature:
   - Valid RSA signature passes.
   - Tampered signature or wrong RSA key fails with 401.
2. Validate issuer:
   - 'https://accounts.google.com' or 'accounts.google.com' passes.
   - Unauthorized/untrusted issuer fails with 401.
3. Validate audience:
   - Matching audience passes.
   - Mismatched audience fails with 403.
4. Validate service-account identity:
   - Matching service account email with email_verified=True passes.
   - Mismatched service account email fails with 403.
   - email_verified=False fails with 403.
5. Webhook Integration (/api/v1/mail-security/gmail/pubsub):
   - Authenticated Pub/Sub JWT accepted -> 200 OK.
   - Invalid Pub/Sub JWT rejected -> 401 / 403.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
import json
import time
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
import jwt
import pytest

from app import config, database, models
from app.main import app
from app.services import pubsub_auth

client = TestClient(app)


# Fixture generating RSA key pair for self-contained cryptographic testing
@pytest.fixture(scope="module")
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Secondary key pair to simulate invalid/different signer
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_private_pem = other_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return {
        "private_key": private_key,
        "private_pem": private_pem,
        "public_pem": public_pem,
        "other_private_key": other_private_key,
        "other_private_pem": other_private_pem,
    }


def create_mock_oidc_jwt(
    private_key_pem: bytes,
    issuer: str = "https://accounts.google.com",
    audience: str = "https://phishguard.internal/api/v1/mail-security/gmail/pubsub",
    email: str = "pubsub-invoker@phishguard-project.iam.gserviceaccount.com",
    email_verified: bool = True,
    expires_in_seconds: int = 3600,
    headers: dict = None,
) -> str:
    """Helper to generate signed OIDC JWT with custom claims."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "10928374659281726354",
        "email": email,
        "email_verified": email_verified,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    jwt_headers = headers or {"kid": "google-test-key-1"}
    return jwt.encode(payload, private_key_pem, algorithm="RS256", headers=jwt_headers)


# ============================================================================
# 1. SIGNATURE VALIDATION TESTS
# ============================================================================

def test_validate_jwt_signature_success(rsa_keys):
    """Valid RSA signature verified against public key succeeds."""
    token = create_mock_oidc_jwt(rsa_keys["private_pem"])
    payload = pubsub_auth.validate_pubsub_jwt(
        token=token,
        signing_key_override=rsa_keys["public_pem"],
    )
    assert payload["iss"] == "https://accounts.google.com"
    assert payload["email"] == "pubsub-invoker@phishguard-project.iam.gserviceaccount.com"
    assert payload["email_verified"] is True


def test_validate_jwt_invalid_signature_fails(rsa_keys):
    """Token signed by untrusted/different private key fails signature verification."""
    untrusted_token = create_mock_oidc_jwt(rsa_keys["other_private_pem"])
    with pytest.raises(HTTPException) as exc_info:
        pubsub_auth.validate_pubsub_jwt(
            token=untrusted_token,
            signing_key_override=rsa_keys["public_pem"],
        )
    assert exc_info.value.status_code == 401
    assert "Invalid Pub/Sub authentication token" in exc_info.value.detail or "Signature verification failed" in exc_info.value.detail


def test_validate_jwt_expired_fails(rsa_keys):
    """Expired JWT is rejected with 401."""
    expired_token = create_mock_oidc_jwt(rsa_keys["private_pem"], expires_in_seconds=-60)
    with pytest.raises(HTTPException) as exc_info:
        pubsub_auth.validate_pubsub_jwt(
            token=expired_token,
            signing_key_override=rsa_keys["public_pem"],
        )
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


# ============================================================================
# 2. ISSUER VALIDATION TESTS
# ============================================================================

def test_validate_jwt_google_issuers_accepted(rsa_keys):
    """Both https://accounts.google.com and accounts.google.com are accepted."""
    for valid_iss in ["https://accounts.google.com", "accounts.google.com"]:
        token = create_mock_oidc_jwt(rsa_keys["private_pem"], issuer=valid_iss)
        payload = pubsub_auth.validate_pubsub_jwt(
            token=token,
            signing_key_override=rsa_keys["public_pem"],
        )
        assert payload["iss"] == valid_iss


def test_validate_jwt_invalid_issuer_rejected(rsa_keys):
    """Untrusted issuer (e.g. attacker domain) is rejected with 401."""
    fraudulent_token = create_mock_oidc_jwt(rsa_keys["private_pem"], issuer="https://attacker.evil.com")
    with pytest.raises(HTTPException) as exc_info:
        pubsub_auth.validate_pubsub_jwt(
            token=fraudulent_token,
            signing_key_override=rsa_keys["public_pem"],
        )
    assert exc_info.value.status_code == 401
    assert "Invalid token issuer" in exc_info.value.detail or "Invalid issuer" in exc_info.value.detail


# ============================================================================
# 3. AUDIENCE VALIDATION TESTS
# ============================================================================

def test_validate_jwt_matching_audience_success(rsa_keys):
    """Target audience matching the token passes verification."""
    expected_aud = "https://phishguard.internal/api/v1/mail-security/gmail/pubsub"
    token = create_mock_oidc_jwt(rsa_keys["private_pem"], audience=expected_aud)
    payload = pubsub_auth.validate_pubsub_jwt(
        token=token,
        expected_audience=expected_aud,
        signing_key_override=rsa_keys["public_pem"],
    )
    assert payload["aud"] == expected_aud


def test_validate_jwt_mismatched_audience_rejected(rsa_keys):
    """Mismatched audience fails with 403 Forbidden."""
    token = create_mock_oidc_jwt(rsa_keys["private_pem"], audience="https://other-service.internal/webhook")
    with pytest.raises(HTTPException) as exc_info:
        pubsub_auth.validate_pubsub_jwt(
            token=token,
            expected_audience="https://phishguard.internal/api/v1/mail-security/gmail/pubsub",
            signing_key_override=rsa_keys["public_pem"],
        )
    assert exc_info.value.status_code == 403
    assert "audience mismatch" in exc_info.value.detail.lower()


# ============================================================================
# 4. SERVICE ACCOUNT IDENTITY VALIDATION TESTS
# ============================================================================

def test_validate_jwt_matching_service_account_success(rsa_keys):
    """Authorized service account identity passes verification."""
    sa_email = "pubsub-invoker@phishguard-project.iam.gserviceaccount.com"
    token = create_mock_oidc_jwt(rsa_keys["private_pem"], email=sa_email, email_verified=True)
    payload = pubsub_auth.validate_pubsub_jwt(
        token=token,
        expected_service_account=sa_email,
        signing_key_override=rsa_keys["public_pem"],
    )
    assert payload["email"] == sa_email
    assert payload["email_verified"] is True


def test_validate_jwt_mismatched_service_account_rejected(rsa_keys):
    """Token from unauthorized service account fails with 403 Forbidden."""
    token = create_mock_oidc_jwt(rsa_keys["private_pem"], email="rogue-service@rogue-project.iam.gserviceaccount.com")
    with pytest.raises(HTTPException) as exc_info:
        pubsub_auth.validate_pubsub_jwt(
            token=token,
            expected_service_account="pubsub-invoker@phishguard-project.iam.gserviceaccount.com",
            signing_key_override=rsa_keys["public_pem"],
        )
    assert exc_info.value.status_code == 403
    assert "Unauthorized Pub/Sub service account" in exc_info.value.detail


def test_validate_jwt_unverified_email_rejected(rsa_keys):
    """Token with email_verified=False fails with 403 Forbidden."""
    token = create_mock_oidc_jwt(rsa_keys["private_pem"], email_verified=False)
    with pytest.raises(HTTPException) as exc_info:
        pubsub_auth.validate_pubsub_jwt(
            token=token,
            signing_key_override=rsa_keys["public_pem"],
        )
    assert exc_info.value.status_code == 403
    assert "unverified" in exc_info.value.detail.lower()


# ============================================================================
# 5. END-TO-END WEBHOOK AUTHENTICATION (/gmail/pubsub)
# ============================================================================

def test_webhook_authenticated_pubsub_jwt_accepted(rsa_keys, monkeypatch):
    """
    Authenticated Pub/Sub JWT with valid signature, issuer, audience,
    and service-account identity accepts notification (HTTP 200).
    """
    expected_aud = "https://phishguard.internal/api/v1/mail-security/gmail/pubsub"
    expected_sa = "pubsub-invoker@phishguard-project.iam.gserviceaccount.com"

    monkeypatch.setattr(config, "GOOGLE_PUBSUB_AUDIENCE", expected_aud)
    monkeypatch.setattr(config, "GOOGLE_PUBSUB_SERVICE_ACCOUNT", expected_sa)

    token = create_mock_oidc_jwt(
        rsa_keys["private_pem"],
        issuer="https://accounts.google.com",
        audience=expected_aud,
        email=expected_sa,
        email_verified=True,
    )

    # Setup database test account
    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == "pubsub_test_user").first()
        if not user:
            user = models.User(
                username="pubsub_test_user",
                email="pubsub_user@domain.com",
                password_hash="$argon2id$mockhash",
                is_active=True,
                is_verified=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        account = (
            db.query(models.MailAccount)
            .filter(models.MailAccount.user_id == user.id, models.MailAccount.account_email == "alerts@phishguard.test")
            .first()
        )
        if not account:
            account = models.MailAccount(
                user_id=user.id,
                provider="gmail",
                account_email="alerts@phishguard.test",
                is_active=True,
                history_id="1000",
            )
            db.add(account)
            db.commit()
            db.refresh(account)
        account_id = account.id
    finally:
        db.close()

    pubsub_msg = {
        "emailAddress": "alerts@phishguard.test",
        "historyId": "1050",
    }
    raw_b64 = base64.b64encode(json.dumps(pubsub_msg).encode("utf-8")).decode("utf-8")
    payload = {
        "message": {
            "data": raw_b64,
            "messageId": "pubsub-jwt-msg-001",
            "publishTime": "2026-10-06T12:00:00Z",
        },
        "subscription": "projects/test/subscriptions/gmail-sub",
    }

    # Patch JWKS client resolution to return our test public key
    mock_jwk = MagicMock()
    mock_jwk.key = rsa_keys["public_pem"]
    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_jwk

    with patch("app.services.pubsub_auth.get_jwks_client", return_value=mock_client), \
         patch("app.services.mail_ingestion_queue.enqueue_gmail_sync") as mock_enqueue:
        response = client.post(
            "/api/v1/mail-security/gmail/pubsub",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"
        mock_enqueue.assert_called_once_with(account_id=account_id, history_id="1050")


def test_webhook_unauthenticated_pubsub_jwt_rejected(rsa_keys, monkeypatch):
    """
    Pub/Sub webhook with invalid JWT signature is rejected with 401 Unauthorized.
    """
    monkeypatch.setattr(config, "GOOGLE_PUBSUB_AUDIENCE", "https://phishguard.internal/api/v1/mail-security/gmail/pubsub")
    bad_token = create_mock_oidc_jwt(rsa_keys["other_private_pem"])

    mock_jwk = MagicMock()
    mock_jwk.key = rsa_keys["public_pem"]
    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_jwk

    with patch("app.services.pubsub_auth.get_jwks_client", return_value=mock_client):
        response = client.post(
            "/api/v1/mail-security/gmail/pubsub",
            headers={"Authorization": f"Bearer {bad_token}"},
            json={"message": {"data": "eyJlbWFpbEFkZHJlc3MiOiJ0ZXN0QGdtYWlsLmNvbSJ9"}},
        )
        assert response.status_code == 401
