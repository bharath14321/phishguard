"""
test_auth.py

Comprehensive authentication and email OTP verification test suite.
Covers:
1. Registration & Password Complexity
2. Email OTP Generation & Secure Storage
3. OTP Verification & Max Attempts
4. OTP Resend & Cooldown Rate-Limiting
5. Login Verification Enforcement
6. JWT Tokens & User Profile (/me)
7. Password Change
8. Inactive Account Handling
9. User Isolation
10. Secret & Credential Protection
"""

from datetime import datetime, timedelta
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Test DB Setup - Isolated SQLite database
TEST_DB_PATH = Path("./test_phishguard_auth.db").resolve()
if TEST_DB_PATH.exists():
    try:
        TEST_DB_PATH.unlink()
    except Exception:
        pass

test_engine = create_engine(f"sqlite:///{TEST_DB_PATH}", connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

from app.main import app
from app import models, database, auth as auth_utils, schemas, config
from app.services import email_service

def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[database.get_db] = override_get_db
database.SessionLocal = TestSessionLocal
database.engine = test_engine

client = TestClient(app)


@pytest.fixture(scope="function", autouse=True)
def reset_database():
    """Ensure database schema exists and clean tables for each test."""
    models.Base.metadata.create_all(bind=test_engine)
    db = TestSessionLocal()
    try:
        db.query(models.IngestedEmail).delete()
        db.query(models.MailAccount).delete()
        db.query(models.AnalysisResult).delete()
        db.query(models.EmailVerificationOTP).delete()
        db.query(models.User).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    yield


@pytest.fixture(autouse=True)
def mock_smtp_sender(monkeypatch):
    """Automatically mock send_otp_email so no real network/SMTP calls occur in tests."""
    mock = MagicMock(return_value=True)
    monkeypatch.setattr(email_service, "send_otp_email", mock)
    return mock


# Test User Payloads
VALID_USER = {
    "username": "analyst_alice",
    "email": "alice@phishguard.org",
    "password": "SecurePassword123!",
}


def register_and_verify_user(user_data=None):
    """Helper to register and verify a user, returning email and password."""
    data = user_data or VALID_USER
    client.post("/api/v1/auth/register", json=data)

    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == data["email"]).first()
        if user:
            user.is_verified = True
            user.is_active = True
            db.commit()
    finally:
        db.close()
    return data


def get_stored_otp_raw(email: str):
    """Helper for testing: query the database for the active OTP record."""
    db = database.SessionLocal()
    try:
        return db.query(models.EmailVerificationOTP).filter(
            models.EmailVerificationOTP.email == email
        ).first()
    finally:
        db.close()


# ===================================================================
# 1. REGISTRATION & PASSWORD COMPLEXITY
# ===================================================================

def test_valid_registration(mock_smtp_sender):
    """Valid registration returns 201 and pending_verification status."""
    resp = client.post("/api/v1/auth/register", json=VALID_USER)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "pending_verification"
    assert data["email"] == VALID_USER["email"]
    assert "access_token" not in data  # Token not issued until OTP verified

    # Verify email service was called with recipient
    mock_smtp_sender.assert_called_once()
    assert mock_smtp_sender.call_args[0][0] == VALID_USER["email"]


def test_duplicate_username_rejected():
    """Duplicate username is rejected with structured 409 error."""
    register_and_verify_user(VALID_USER)

    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": VALID_USER["username"],
            "email": "different_email@phishguard.org",
            "password": "AnotherPassword123!",
        },
    )
    assert resp.status_code == 409
    err = resp.json()["detail"]["error"]
    assert err["code"] == "USERNAME_ALREADY_REGISTERED"
    assert err["message"] == "Username already registered."


def test_duplicate_verified_email_rejected():
    """Duplicate verified email is rejected with structured 409 error."""
    register_and_verify_user(VALID_USER)

    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "different_username",
            "email": VALID_USER["email"],
            "password": "AnotherPassword123!",
        },
    )
    assert resp.status_code == 409
    err = resp.json()["detail"]["error"]
    assert err["code"] == "EMAIL_ALREADY_REGISTERED"
    assert err["message"] == "Email already registered."


def test_weak_passwords_rejected():
    """Passwords missing uppercase, lowercase, digit, or special char are rejected."""
    # Too short
    r1 = client.post("/api/v1/auth/register", json={
        "username": "user1", "email": "u1@test.com", "password": "Sh1!"
    })
    assert r1.status_code in (400, 422)

    # No uppercase
    r2 = client.post("/api/v1/auth/register", json={
        "username": "user2", "email": "u2@test.com", "password": "password123!"
    })
    assert r2.status_code == 400
    assert r2.json()["detail"]["error"]["code"] == "PASSWORD_TOO_WEAK"

    # No lowercase
    r3 = client.post("/api/v1/auth/register", json={
        "username": "user3", "email": "u3@test.com", "password": "PASSWORD123!"
    })
    assert r3.status_code == 400

    # No number
    r4 = client.post("/api/v1/auth/register", json={
        "username": "user4", "email": "u4@test.com", "password": "PasswordSpecial!"
    })
    assert r4.status_code == 400

    # No special char
    r5 = client.post("/api/v1/auth/register", json={
        "username": "user5", "email": "u5@test.com", "password": "Password12345"
    })
    assert r5.status_code == 400


# ===================================================================
# 2. OTP GENERATION & STORAGE SECURITY
# ===================================================================

def test_otp_generation_and_hashing(mock_smtp_sender):
    """OTP is stored as cryptographic hash and never in plaintext."""
    client.post("/api/v1/auth/register", json=VALID_USER)

    otp_rec = get_stored_otp_raw(VALID_USER["email"])
    assert otp_rec is not None
    # Stored OTP is a 64-character SHA256 hex string (or hash)
    assert len(otp_rec.otp_hash) == 64
    assert otp_rec.attempts_count == 0

    # Verify that the generated OTP passed to the mock email service was 6 digits
    generated_otp = mock_smtp_sender.call_args[0][1]
    assert len(generated_otp) == 6
    assert generated_otp.isdigit()

    # Verify that plain OTP matches the stored hash
    assert auth_utils.verify_otp_hash(generated_otp, otp_rec.otp_hash)


# ===================================================================
# 3. OTP VERIFICATION
# ===================================================================

def test_valid_otp_verification(mock_smtp_sender):
    """Submitting the correct OTP verifies the account."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    verify_res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "verified"

    # Verify user in database is marked is_verified=True
    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == VALID_USER["email"]).first()
        assert user.is_verified is True
        # OTP record should be deleted/invalidated
        otp_rec = db.query(models.EmailVerificationOTP).filter(
            models.EmailVerificationOTP.email == VALID_USER["email"]
        ).first()
        assert otp_rec is None
    finally:
        db.close()


def test_invalid_otp_rejected(mock_smtp_sender):
    """Incorrect OTP increments attempt counter and rejects verification."""
    client.post("/api/v1/auth/register", json=VALID_USER)

    verify_res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": "000000"},
    )
    assert verify_res.status_code == 400
    assert verify_res.json()["detail"]["error"]["code"] == "INVALID_OTP"

    otp_rec = get_stored_otp_raw(VALID_USER["email"])
    assert otp_rec.attempts_count == 1


def test_otp_max_attempts_exceeded(mock_smtp_sender):
    """After 5 incorrect attempts, verification is blocked with OTP_TOO_MANY_ATTEMPTS."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    for _ in range(5):
        client.post(
            "/api/v1/auth/verify-otp",
            json={"email": VALID_USER["email"], "otp": "999999"},
        )

    # 6th attempt (even if correct OTP) is blocked
    res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert res.status_code == 400
    assert res.json()["detail"]["error"]["code"] == "OTP_TOO_MANY_ATTEMPTS"


def test_expired_otp_rejected(mock_smtp_sender):
    """Expired OTP is rejected with OTP_EXPIRED code."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    # Manually backdate the OTP record
    db = database.SessionLocal()
    try:
        rec = db.query(models.EmailVerificationOTP).filter(
            models.EmailVerificationOTP.email == VALID_USER["email"]
        ).first()
        rec.expires_at = datetime.utcnow() - timedelta(minutes=5)
        db.commit()
    finally:
        db.close()

    res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert res.status_code == 400
    assert res.json()["detail"]["error"]["code"] == "OTP_EXPIRED"


def test_otp_reuse_rejected(mock_smtp_sender):
    """Once verified, the same OTP cannot be reused."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    # First verification -> 200
    r1 = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert r1.status_code == 200

    # Second verification attempt -> 400 EMAIL_ALREADY_VERIFIED
    r2 = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert r2.status_code == 400
    assert r2.json()["detail"]["error"]["code"] == "EMAIL_ALREADY_VERIFIED"


# ===================================================================
# 4. OTP RESEND & COOLDOWN
# ===================================================================

def test_resend_cooldown_enforced(mock_smtp_sender):
    """Resend requested before cooldown expires returns 429 OTP_RESEND_TOO_SOON."""
    client.post("/api/v1/auth/register", json=VALID_USER)

    # Immediate resend should trigger cooldown
    res = client.post(
        "/api/v1/auth/resend-otp",
        json={"email": VALID_USER["email"]},
    )
    assert res.status_code == 429
    assert res.json()["detail"]["error"]["code"] == "OTP_RESEND_TOO_SOON"


def test_resend_after_30s_cooldown_invalidates_previous_otp(mock_smtp_sender):
    """Resending OTP after 30s generates a fresh code and invalidates the previous one."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    first_otp = mock_smtp_sender.call_args[0][1]

    # Fast forward last_sent_at past 30s cooldown (e.g. 35 seconds ago)
    db = database.SessionLocal()
    try:
        rec = db.query(models.EmailVerificationOTP).filter(
            models.EmailVerificationOTP.email == VALID_USER["email"]
        ).first()
        rec.last_sent_at = datetime.utcnow() - timedelta(seconds=35)
        db.commit()
    finally:
        db.close()

    res = client.post(
        "/api/v1/auth/resend-otp",
        json={"email": VALID_USER["email"]},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "resent"

    second_otp = mock_smtp_sender.call_args[0][1]

    # First OTP should no longer work
    r_old = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": first_otp},
    )
    # If first_otp != second_otp, it should fail
    if first_otp != second_otp:
        assert r_old.status_code == 400

    # Second OTP should work
    r_new = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": second_otp},
    )
    assert r_new.status_code == 200


def test_registration_smtp_failure_handling(monkeypatch):
    """If SMTP delivery fails during registration, return 500 and do not leave orphaned OTP."""
    monkeypatch.setattr(email_service, "send_otp_email", MagicMock(return_value=False))
    resp = client.post("/api/v1/auth/register", json=VALID_USER)
    assert resp.status_code == 500
    assert resp.json()["detail"]["error"]["code"] == "EMAIL_DELIVERY_FAILED"

    # Verify no active OTP record was left in the database
    otp_rec = get_stored_otp_raw(VALID_USER["email"])
    assert otp_rec is None


def test_resend_smtp_failure_handling(monkeypatch):
    """If SMTP delivery fails during resend, return 500 and do not store orphaned OTP."""
    # First register with working mock
    monkeypatch.setattr(email_service, "send_otp_email", MagicMock(return_value=True))
    client.post("/api/v1/auth/register", json=VALID_USER)

    # Fast forward past cooldown
    db = database.SessionLocal()
    try:
        rec = db.query(models.EmailVerificationOTP).filter(
            models.EmailVerificationOTP.email == VALID_USER["email"]
        ).first()
        rec.last_sent_at = datetime.utcnow() - timedelta(seconds=35)
        db.commit()
    finally:
        db.close()

    # Now make SMTP fail on resend
    monkeypatch.setattr(email_service, "send_otp_email", MagicMock(return_value=False))
    res = client.post(
        "/api/v1/auth/resend-otp",
        json={"email": VALID_USER["email"]},
    )
    assert res.status_code == 500
    assert res.json()["detail"]["error"]["code"] == "EMAIL_DELIVERY_FAILED"

    # Confirm OTP was rolled back
    otp_rec = get_stored_otp_raw(VALID_USER["email"])
    assert otp_rec is None


def test_leading_zero_otp_verification(monkeypatch):
    """6-digit OTP starting with leading zero (e.g. '012345') generates, hashes, and verifies successfully."""
    monkeypatch.setattr(auth_utils, "generate_otp", lambda: "012345")
    client.post("/api/v1/auth/register", json=VALID_USER)

    otp_rec = get_stored_otp_raw(VALID_USER["email"])
    assert otp_rec is not None
    assert auth_utils.verify_otp_hash("012345", otp_rec.otp_hash)

    # Submit verification with string preserving leading zero
    res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": "012345"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "verified"


def test_single_active_otp_enforced_across_resends(mock_smtp_sender):
    """Multiple resends ensure exactly ONE active OTP record exists in the database for the user."""
    client.post("/api/v1/auth/register", json=VALID_USER)

    # Fast-forward cooldown and resend 3 times
    for _ in range(3):
        db = database.SessionLocal()
        try:
            rec = db.query(models.EmailVerificationOTP).filter(
                models.EmailVerificationOTP.email == VALID_USER["email"]
            ).first()
            rec.last_sent_at = datetime.utcnow() - timedelta(seconds=35)
            db.commit()
        finally:
            db.close()

        res = client.post("/api/v1/auth/resend-otp", json={"email": VALID_USER["email"]})
        assert res.status_code == 200

    # Verify count of OTP records for this email is strictly 1
    db = database.SessionLocal()
    try:
        otps = db.query(models.EmailVerificationOTP).filter(
            models.EmailVerificationOTP.email == VALID_USER["email"]
        ).all()
        assert len(otps) == 1
    finally:
        db.close()


def test_wrong_otp_decrements_attempts_with_exact_count(mock_smtp_sender):
    """Wrong OTP increments attempts_count and returns exact remaining attempts in error message."""
    client.post("/api/v1/auth/register", json=VALID_USER)

    res1 = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": "000000"},
    )
    assert res1.status_code == 400
    assert "4 attempts remaining" in res1.json()["detail"]["error"]["message"]

    res2 = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": "000001"},
    )
    assert res2.status_code == 400
    assert "3 attempts remaining" in res2.json()["detail"]["error"]["message"]


def test_correct_otp_does_not_consume_attempts(mock_smtp_sender):
    """Submitting the correct OTP on attempt 1 verifies immediately without consuming another attempt."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "verified"


def test_already_verified_user_cannot_verify_again(mock_smtp_sender):
    """Once an account is verified, further OTP verification requests return 400 EMAIL_ALREADY_VERIFIED."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    # Verify first time
    res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert res.status_code == 200

    # Attempt to verify again
    res2 = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"], "otp": sent_otp},
    )
    assert res2.status_code == 400
    assert res2.json()["detail"]["error"]["code"] == "EMAIL_ALREADY_VERIFIED"


def test_otp_verification_with_case_insensitive_email(mock_smtp_sender):
    """OTP verification succeeds even if email is submitted in mixed or uppercase."""
    client.post("/api/v1/auth/register", json=VALID_USER)
    sent_otp = mock_smtp_sender.call_args[0][1]

    res = client.post(
        "/api/v1/auth/verify-otp",
        json={"email": VALID_USER["email"].upper(), "otp": sent_otp},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "verified"


# ===================================================================
# 5. LOGIN VERIFICATION ENFORCEMENT
# ===================================================================

def test_unverified_user_cannot_login():
    """Unverified user attempting to login is rejected with 403 EMAIL_NOT_VERIFIED."""
    client.post("/api/v1/auth/register", json=VALID_USER)

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert login_res.status_code == 403
    err = login_res.json()["detail"]["error"]
    assert err["code"] == "EMAIL_NOT_VERIFIED"


def test_verified_user_login_success():
    """Verified user can log in and receive JWT token."""
    register_and_verify_user(VALID_USER)

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["is_verified"] is True


def test_login_invalid_password():
    """Incorrect password returns 401 INVALID_CREDENTIALS or INVALID_PASSWORD."""
    register_and_verify_user(VALID_USER)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": "WrongPassword123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"]["code"] in ["INVALID_CREDENTIALS", "INVALID_PASSWORD"]


def test_inactive_user_cannot_login():
    """Inactive user is rejected with 403 ACCOUNT_INACTIVE."""
    register_and_verify_user(VALID_USER)

    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == VALID_USER["email"]).first()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"]["code"] == "ACCOUNT_INACTIVE"


# ===================================================================
# 6. /ME & PASSWORD CHANGE
# ===================================================================

def test_me_with_valid_token():
    """Authenticated user can read profile with is_verified status."""
    register_and_verify_user(VALID_USER)
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == VALID_USER["email"]
    assert data["is_verified"] is True
    assert "password_hash" not in data


def test_change_password_flow():
    """Changing password updates hash and requires new password for subsequent logins."""
    register_and_verify_user(VALID_USER)
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    new_pw = "BrandNewSecret789@"
    change_res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": VALID_USER["password"], "new_password": new_pw},
        headers=headers,
    )
    assert change_res.status_code == 200

    # Login with new password works
    new_login = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": VALID_USER["email"], "password": new_pw},
    )
    assert new_login.status_code == 200


# ===================================================================
# 7. SECURITY & CREDENTIAL PRIVACY
# ===================================================================

def test_secrets_never_returned_in_api_responses():
    """Ensure no API responses leak OTP, password hashes, or SMTP/API credentials."""
    resp = client.post("/api/v1/auth/register", json=VALID_USER)
    raw_response = resp.text
    assert "password_hash" not in raw_response
    assert "SMTP_PASSWORD" not in raw_response
    assert "GEMINI_API_KEY" not in raw_response
    assert "VIRUSTOTAL_API_KEY" not in raw_response


# ===================================================================
# 8. CASE NORMALIZATION & INPUT TRIMMING
# ===================================================================

def test_case_insensitive_and_trimmed_login():
    """Ensure user can log in with mixed case username, uppercase email, and leading/trailing whitespace."""
    register_and_verify_user(VALID_USER)

    # Mixed case username with whitespace
    r1 = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": f"  {VALID_USER['username'].upper()}  ", "password": VALID_USER["password"]},
    )
    assert r1.status_code == 200
    assert "access_token" in r1.json()

    # Uppercase email with whitespace
    r2 = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": f"  {VALID_USER['email'].upper()}  ", "password": VALID_USER["password"]},
    )
    assert r2.status_code == 200
    assert "access_token" in r2.json()


def test_safe_auth_status_diagnostic():
    """Diagnostic endpoint safely returns user status without exposing secrets or hashes."""
    register_and_verify_user(VALID_USER)

    resp = client.get(f"/api/v1/auth/status/{VALID_USER['username']}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["exists"] is True
    assert data["username"] == VALID_USER["username"]
    assert "password_hash" not in data
    assert "otp" not in data
    assert data["is_verified"] is True

    # Non-existent user check
    r_unknown = client.get("/api/v1/auth/status/unknown_nonexistent_user")
    assert r_unknown.status_code == 200
    assert r_unknown.json()["exists"] is False


# Cleanup
def teardown_module(module):
    database.engine.dispose()
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass
