"""
tests/test_auth_logout_regression.py

Dedicated Regression Test Suite for User Persistence Across Logout and Re-login.
Verifies that:
1. Registration -> OTP Verification -> First Login succeeds.
2. Logout does not delete or deactivate user account in the database.
3. Subsequent login with exact same username succeeds.
4. Subsequent login with exact same email succeeds.
5. Case-insensitive and whitespace-tolerant login succeeds.
6. Database state remains fully persistent across sessions.
7. Auth tokens obtained after re-login correctly authenticate /api/v1/auth/me.
8. Unregistered accounts cleanly return USER_NOT_FOUND (401).
9. Unverified accounts cleanly return EMAIL_NOT_VERIFIED (403).
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func

from app.main import app
from app import database, models, auth as auth_utils

client = TestClient(app)

FIXED_OTP = "654321"
TEST_USER_NAME = "logout_reg_user"
TEST_USER_EMAIL = "logout_reg_user@example.com"
TEST_USER_PASSWORD = "StrongLogoutPassword123!"


@pytest.fixture(autouse=True)
def clean_test_user():
    """Ensure test user is cleaned up before and after each test."""
    db = database.SessionLocal()
    try:
        db.query(models.EmailVerificationOTP).filter(
            (func.lower(models.EmailVerificationOTP.email) == TEST_USER_EMAIL.lower())
        ).delete()
        db.query(models.User).filter(
            (func.lower(models.User.email) == TEST_USER_EMAIL.lower())
            | (func.lower(models.User.username) == TEST_USER_NAME.lower())
        ).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    yield

    db = database.SessionLocal()
    try:
        db.query(models.EmailVerificationOTP).filter(
            (func.lower(models.EmailVerificationOTP.email) == TEST_USER_EMAIL.lower())
        ).delete()
        db.query(models.User).filter(
            (func.lower(models.User.email) == TEST_USER_EMAIL.lower())
            | (func.lower(models.User.username) == TEST_USER_NAME.lower())
        ).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def test_auth_logout_01_full_lifecycle_and_relogin():
    """
    AUTH-LOGOUT-01 & 02 & 03 & 04 & 05 & 06:
    Verify full lifecycle from registration through OTP, first login, logout simulation,
    and multiple re-logins by username, email, and mixed-case whitespace strings.
    """
    with patch("app.services.email_service.send_otp_email", return_value=True), \
         patch("app.auth.generate_otp", return_value=FIXED_OTP):

        # 1. Registration
        reg_payload = {
            "username": TEST_USER_NAME,
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
            "full_name": "Logout Regression Tester",
        }
        res_reg = client.post("/api/v1/auth/register", json=reg_payload)
        assert res_reg.status_code == 201, f"Registration failed: {res_reg.text}"
        assert res_reg.json()["status"] == "pending_verification"

        # 2. Verify OTP
        verify_payload = {
            "email": TEST_USER_EMAIL,
            "otp": FIXED_OTP,
        }
        res_ver = client.post("/api/v1/auth/verify-otp", json=verify_payload)
        assert res_ver.status_code == 200, f"OTP verification failed: {res_ver.text}"
        assert res_ver.json()["status"] == "verified"

        # 3. First Login via Username
        res_login1 = client.post("/api/v1/auth/login", json={
            "email_or_username": TEST_USER_NAME,
            "password": TEST_USER_PASSWORD,
        })
        assert res_login1.status_code == 200, f"First login failed: {res_login1.text}"
        token1 = res_login1.json()["access_token"]
        assert token1 is not None

        # Verify /me endpoint with first token
        res_me1 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"})
        assert res_me1.status_code == 200
        assert res_me1.json()["username"] == TEST_USER_NAME

        # 4. Simulate Logout: Client drops token (no backend mutation)
        del token1

        # 5. Direct Database Persistence Check (AUTH-LOGOUT-05)
        db = database.SessionLocal()
        persisted_user = db.query(models.User).filter(
            func.lower(models.User.username) == TEST_USER_NAME.lower()
        ).first()
        assert persisted_user is not None, "User disappeared from database after logout!"
        assert persisted_user.is_active is True
        assert persisted_user.is_verified is True
        db.close()

        # 6. Re-Login with Username (AUTH-LOGOUT-02)
        res_login2 = client.post("/api/v1/auth/login", json={
            "email_or_username": TEST_USER_NAME,
            "password": TEST_USER_PASSWORD,
        })
        assert res_login2.status_code == 200, f"Re-login by username failed: {res_login2.text}"
        token2 = res_login2.json()["access_token"]
        assert token2 is not None

        # 7. Re-Login with Email (AUTH-LOGOUT-03)
        res_login3 = client.post("/api/v1/auth/login", json={
            "email_or_username": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
        })
        assert res_login3.status_code == 200, f"Re-login by email failed: {res_login3.text}"
        token3 = res_login3.json()["access_token"]
        assert token3 is not None

        # 8. Re-Login with Mixed-Case & Whitespace (AUTH-LOGOUT-04)
        res_login4 = client.post("/api/v1/auth/login", json={
            "email_or_username": f"  {TEST_USER_NAME.upper()}  ",
            "password": TEST_USER_PASSWORD,
        })
        assert res_login4.status_code == 200, f"Re-login with uppercase username failed: {res_login4.text}"

        res_login5 = client.post("/api/v1/auth/login", json={
            "email_or_username": f"  {TEST_USER_EMAIL.upper()}  ",
            "password": TEST_USER_PASSWORD,
        })
        assert res_login5.status_code == 200, f"Re-login with uppercase email failed: {res_login5.text}"

        # 9. Verify /me endpoint with newly acquired token (AUTH-LOGOUT-06)
        res_me3 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token3}"})
        assert res_me3.status_code == 200
        assert res_me3.json()["email"] == TEST_USER_EMAIL
        assert res_me3.json()["is_active"] is True


def test_auth_logout_07_unregistered_user_not_found():
    """
    AUTH-LOGOUT-07:
    Verify that an genuinely unregistered account returns structured 401 USER_NOT_FOUND.
    """
    res = client.post("/api/v1/auth/login", json={
        "email_or_username": "non_existent_random_user_99999",
        "password": "AnyPassword123!",
    })
    assert res.status_code == 401
    detail = res.json()["detail"]["error"]
    assert detail["code"] == "USER_NOT_FOUND"
    assert "Account not found" in detail["message"]


def test_auth_logout_08_unverified_account_forbidden():
    """
    AUTH-LOGOUT-08:
    Verify that registered but unverified accounts return structured 403 EMAIL_NOT_VERIFIED.
    """
    with patch("app.services.email_service.send_otp_email", return_value=True), \
         patch("app.auth.generate_otp", return_value=FIXED_OTP):

        reg_payload = {
            "username": TEST_USER_NAME,
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
        }
        res_reg = client.post("/api/v1/auth/register", json=reg_payload)
        assert res_reg.status_code == 201

        # Attempt to login before OTP verification
        res_login = client.post("/api/v1/auth/login", json={
            "email_or_username": TEST_USER_NAME,
            "password": TEST_USER_PASSWORD,
        })
        assert res_login.status_code == 403
        detail = res_login.json()["detail"]["error"]
        assert detail["code"] == "EMAIL_NOT_VERIFIED"
