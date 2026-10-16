"""
tests/test_auth_consistency.py

Comprehensive Regression Test Suite for Signup/Login Consistency and Database Integrity:
1. Register a new user.
2. Verify the account using the normal OTP flow.
3. Log in using the email.
4. Log in using the username.
5. Attempt signup with the same email using different casing (e.g. UPPERCASE/Mixed).
6. Attempt signup with surrounding email whitespace.
7. Log out and log in again.
8. Restart the application (re-bind engine against same SQLite file) and verify the account still exists.
9. Confirm duplicate signup cannot create a second account (verifying record count invariance).
10. Confirm invalid passwords remain rejected (401 INVALID_PASSWORD).
11. Confirm an unverified account remains unable to log in (403 EMAIL_NOT_VERIFIED).
12. Confirm signup and login access the same SQLite database file on disk.

Uses a real temporary SQLite database file to verify real persistence without mocks.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from app import auth as auth_utils, config, database, models
from app.main import app
from app.routers.auth import normalize_email, normalize_username
from app.services import email_service


FIXED_OTP = "543210"


@pytest.fixture(scope="module")
def real_temp_db():
    """Create a real temporary SQLite database on disk for integration testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_auth_consistency.db"
        db_url = f"sqlite:///{db_path}"

        test_engine = create_engine(db_url, connect_args={"check_same_thread": False})
        models.Base.metadata.create_all(bind=test_engine)
        database.ensure_sqlite_schema(test_engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        # Wire dependency override for the app
        app.dependency_overrides[database.get_db] = override_get_db

        yield {
            "path": db_path,
            "url": db_url,
            "engine": test_engine,
            "SessionLocal": TestingSessionLocal,
        }

        app.dependency_overrides.pop(database.get_db, None)
        test_engine.dispose()


@pytest.fixture(autouse=True)
def mock_smtp(monkeypatch):
    """Mock SMTP email dispatch and generate known OTP for deterministic testing."""
    mock = MagicMock(return_value=True)
    monkeypatch.setattr(email_service, "send_otp_email", mock)
    monkeypatch.setattr(auth_utils, "generate_otp", lambda: FIXED_OTP)
    return mock


def test_auth_consistency_requirements_1_to_12(real_temp_db):
    """
    Execute end-to-end authentication consistency checks across all 12 specification requirements.
    """
    client = TestClient(app)
    db_session_factory = real_temp_db["SessionLocal"]

    test_username = "consistency_user"
    test_email = "consistency_user@phishguard.org"
    test_password = "SecurePassword123!"

    # -------------------------------------------------------------
    # 1. Register a new user
    # -------------------------------------------------------------
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": test_username,
            "email": test_email,
            "password": test_password,
        },
    )
    assert reg_resp.status_code == 201, f"Signup failed: {reg_resp.text}"
    reg_data = reg_resp.json()
    assert reg_data["status"] == "pending_verification"
    assert reg_data["email"] == test_email.lower()

    # -------------------------------------------------------------
    # 11 (Early check): Confirm unverified account cannot log in
    # -------------------------------------------------------------
    unverified_login_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_email,
            "password": test_password,
        },
    )
    assert unverified_login_resp.status_code == 403
    unverified_data = unverified_login_resp.json()
    assert unverified_data["detail"]["error"]["code"] == "EMAIL_NOT_VERIFIED"
    assert "verify your email" in unverified_data["detail"]["error"]["message"].lower()

    # -------------------------------------------------------------
    # 2. Verify the account using the normal OTP flow
    # -------------------------------------------------------------
    verify_resp = client.post(
        "/api/v1/auth/verify-otp",
        json={
            "email": test_email,
            "otp": FIXED_OTP,
        },
    )
    assert verify_resp.status_code == 200, f"OTP verification failed: {verify_resp.text}"
    assert verify_resp.json()["status"] == "verified"

    # Confirm verified status in real database session
    with db_session_factory() as session:
        user_record = session.query(models.User).filter(models.User.email == test_email.lower()).first()
        assert user_record is not None
        assert user_record.is_verified is True
        assert user_record.is_active is True

    # -------------------------------------------------------------
    # 3. Log in using the email
    # -------------------------------------------------------------
    login_email_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_email,
            "password": test_password,
        },
    )
    assert login_email_resp.status_code == 200, f"Email login failed: {login_email_resp.text}"
    token_email_data = login_email_resp.json()
    assert "access_token" in token_email_data
    assert token_email_data["user"]["email"] == test_email.lower()
    assert token_email_data["user"]["is_verified"] is True

    # -------------------------------------------------------------
    # 4. Log in using the username
    # -------------------------------------------------------------
    login_user_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_username,
            "password": test_password,
        },
    )
    assert login_user_resp.status_code == 200, f"Username login failed: {login_user_resp.text}"
    token_user_data = login_user_resp.json()
    assert "access_token" in token_user_data
    assert token_user_data["user"]["username"] == test_username

    # -------------------------------------------------------------
    # 5. Attempt signup with the same email using different casing
    # -------------------------------------------------------------
    mixed_cased_email = "CoNsIsTeNcY_uSeR@PhIsHgUaRd.OrG"
    dup_case_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "different_handle_1",
            "email": mixed_cased_email,
            "password": "AnotherPassword123!",
        },
    )
    assert dup_case_resp.status_code == 409
    dup_case_err = dup_case_resp.json()["detail"]["error"]
    assert dup_case_err["code"] == "EMAIL_ALREADY_REGISTERED"

    # -------------------------------------------------------------
    # 6. Attempt signup with surrounding email whitespace
    # -------------------------------------------------------------
    whitespace_email = f"   {test_email}   "
    dup_ws_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "different_handle_2",
            "email": whitespace_email,
            "password": "AnotherPassword123!",
        },
    )
    assert dup_ws_resp.status_code == 409
    dup_ws_err = dup_ws_resp.json()["detail"]["error"]
    assert dup_ws_err["code"] == "EMAIL_ALREADY_REGISTERED"

    # -------------------------------------------------------------
    # 7. Log out (client discard) and log in again
    # -------------------------------------------------------------
    # Simulate client discarding token and performing fresh login
    relogin_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_email,
            "password": test_password,
        },
    )
    assert relogin_resp.status_code == 200
    new_token = relogin_resp.json()["access_token"]

    # Verify new token authenticates /api/v1/auth/me
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == test_username

    # -------------------------------------------------------------
    # 8. Restart application (re-bind engine against same SQLite file)
    # -------------------------------------------------------------
    # Dispose active engine and re-create a new engine against the exact same file path
    restarted_engine = create_engine(real_temp_db["url"], connect_args={"check_same_thread": False})
    database.ensure_sqlite_schema(restarted_engine)
    RestartedSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=restarted_engine)

    def restarted_get_db():
        db = RestartedSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[database.get_db] = restarted_get_db

    restarted_login_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_username,
            "password": test_password,
        },
    )
    assert restarted_login_resp.status_code == 200
    assert restarted_login_resp.json()["user"]["username"] == test_username

    # -------------------------------------------------------------
    # 9. Confirm duplicate signup cannot create a second account
    # -------------------------------------------------------------
    with RestartedSessionLocal() as session:
        count_before = session.query(models.User).count()

    dup_signup_attempt = client.post(
        "/api/v1/auth/register",
        json={
            "username": "duplicate_attempt",
            "email": test_email,
            "password": "NewPassword123!",
        },
    )
    assert dup_signup_attempt.status_code == 409

    with RestartedSessionLocal() as session:
        count_after = session.query(models.User).count()
        assert count_after == count_before, "Duplicate signup must never increase user count"

    # -------------------------------------------------------------
    # 10. Confirm invalid passwords remain rejected
    # -------------------------------------------------------------
    invalid_pw_resp = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_email,
            "password": "WrongPassword999!",
        },
    )
    assert invalid_pw_resp.status_code == 401
    inv_err = invalid_pw_resp.json()["detail"]["error"]
    assert inv_err["code"] == "INVALID_PASSWORD"
    assert "incorrect password" in inv_err["message"].lower()

    # -------------------------------------------------------------
    # 12. Confirm signup and login access the same SQLite database file
    # -------------------------------------------------------------
    # Register a dedicated user via API
    dedicated_user = "db_file_verify_user"
    dedicated_email = "db_file_verify@phishguard.org"
    reg_file_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": dedicated_user,
            "email": dedicated_email,
            "password": "SecurePassword123!",
        },
    )
    assert reg_file_resp.status_code == 201

    # Check direct SQLite on disk using native sqlite3 connection to same file
    import sqlite3
    disk_conn = sqlite3.connect(real_temp_db["path"])
    disk_cur = disk_conn.cursor()
    disk_cur.execute("SELECT username, email FROM users WHERE LOWER(email) = ?", (dedicated_email.lower(),))
    disk_row = disk_cur.fetchone()
    disk_conn.close()

    assert disk_row is not None
    assert disk_row[0] == dedicated_user
    assert disk_row[1] == dedicated_email.lower()

    restarted_engine.dispose()
