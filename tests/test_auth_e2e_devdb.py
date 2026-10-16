"""
tests/test_auth_e2e_devdb.py

Comprehensive End-to-End verification of the authentication flow against
the persistent development database architecture:
1. Deterministic database persistence across transactions.
2. Signup with Argon2id password hashing and explicit verification.
3. Case-insensitive and whitespace-trimmed uniqueness checks.
4. Duplicate username/email 409 Conflict handling.
5. JSON-compatible login by username and email.
6. Secure JWT verification via /api/v1/auth/me.
7. Diagnostic status endpoint protection in production mode.
"""

import os
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import database, models
from app.services import email_service


@pytest.fixture(autouse=True)
def mock_smtp_sender(monkeypatch):
    """Mock email dispatch so tests execute reliably without live outbound SMTP."""
    mock = MagicMock(return_value=True)
    monkeypatch.setattr(email_service, "send_otp_email", mock)
    return mock


@pytest.fixture(autouse=True)
def clean_auth_test_users():
    """Ensure test users are cleaned up before and after test runs."""
    models.Base.metadata.create_all(bind=database.engine)
    db = database.SessionLocal()
    try:
        db.query(models.EmailVerificationOTP).delete()
        db.query(models.User).filter(
            models.User.username.in_(["bharath_e2e", "bharath_dup", "user_space_test"])
            | models.User.email.in_(["bharath_e2e@example.com", "bharath_dup@example.com", "space@example.com"])
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    yield

    db = database.SessionLocal()
    try:
        db.query(models.EmailVerificationOTP).delete()
        db.query(models.User).filter(
            models.User.username.in_(["bharath_e2e", "bharath_dup", "user_space_test"])
            | models.User.email.in_(["bharath_e2e@example.com", "bharath_dup@example.com", "space@example.com"])
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def test_auth_signup_persists_in_database():
    client = TestClient(app)

    # 1. Register a new user
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "bharath_e2e",
            "email": "bharath_e2e@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "pending_verification"
    assert data["email"] == "bharath_e2e@example.com"

    # 2. Directly verify persistence in a separate, isolated DB session
    db = database.SessionLocal()
    try:
        user_in_db = db.query(models.User).filter(models.User.username == "bharath_e2e").first()
        assert user_in_db is not None
        assert user_in_db.email == "bharath_e2e@example.com"
        assert user_in_db.is_active is True
        assert user_in_db.password_hash.startswith("$argon2")
    finally:
        db.close()


def test_auth_duplicate_username_and_email_conflicts():
    client = TestClient(app)

    # Register initial user
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "bharath_e2e",
            "email": "bharath_e2e@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert resp.status_code == 201

    # Duplicate username (case-insensitive with whitespace)
    resp_dup_user = client.post(
        "/api/v1/auth/register",
        json={
            "username": "  BHARATH_E2E  ",
            "email": "different_email@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert resp_dup_user.status_code == 409
    assert resp_dup_user.json()["detail"]["error"]["code"] == "USERNAME_ALREADY_REGISTERED"

    # Duplicate email (case-insensitive with whitespace)
    resp_dup_email = client.post(
        "/api/v1/auth/register",
        json={
            "username": "bharath_dup",
            "email": "  BHARATH_E2E@EXAMPLE.COM  ",
            "password": "SecurePassword123!",
        },
    )
    assert resp_dup_email.status_code == 409
    assert resp_dup_email.json()["detail"]["error"]["code"] == "EMAIL_ALREADY_REGISTERED"


def test_auth_login_with_username_and_email():
    client = TestClient(app)

    # Register
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "bharath_e2e",
            "email": "bharath_e2e@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert reg_resp.status_code == 201

    # Mark user verified for login test
    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == "bharath_e2e").first()
        user.is_verified = True
        db.commit()
    finally:
        db.close()

    # 1. Login using username
    login_user = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": "bharath_e2e",
            "password": "SecurePassword123!",
        },
    )
    assert login_user.status_code == 200
    token_resp = login_user.json()
    assert "access_token" in token_resp
    assert token_resp["token_type"] == "bearer"

    # Verify authenticated user endpoint with JWT
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token_resp['access_token']}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "bharath_e2e"

    # 2. Login using email
    login_email_json = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": "bharath_e2e@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert login_email_json.status_code == 200
    token_json = login_email_json.json()
    assert "access_token" in token_json

    # 3. Negative Login - Wrong Password
    bad_pwd = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": "bharath_e2e",
            "password": "WrongPassword999!",
        },
    )
    assert bad_pwd.status_code == 401
    bad_pwd_msg = bad_pwd.json()["detail"]["error"]["message"]
    assert "Incorrect password" in bad_pwd_msg or "Incorrect email or password" in bad_pwd_msg

    # 4. Negative Login - Unknown Username
    unknown_user = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": "non_existent_user_999",
            "password": "AnyPassword123!",
        },
    )
    assert unknown_user.status_code == 401
    unknown_msg = unknown_user.json()["detail"]["error"]["message"]
    assert "Account not found" in unknown_msg or "Incorrect email or password" in unknown_msg


def test_auth_status_diagnostic_guarded_in_production(monkeypatch):
    client = TestClient(app)

    # Register user
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "bharath_e2e",
            "email": "bharath_e2e@example.com",
            "password": "SecurePassword123!",
        },
    )

    # In dev/test: status returns metadata without secrets
    diag_dev = client.get("/api/v1/auth/status/bharath_e2e")
    assert diag_dev.status_code == 200
    data = diag_dev.json()
    assert data["exists"] is True
    assert data["username"] == "bharath_e2e"
    assert "password" not in data
    assert "password_hash" not in data

    # In production: diagnostic status is forbidden to prevent enumeration
    monkeypatch.setenv("ENVIRONMENT", "production")
    diag_prod = client.get("/api/v1/auth/status/bharath_e2e")
    assert diag_prod.status_code == 403
