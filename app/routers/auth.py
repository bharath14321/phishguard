"""
app/routers/auth.py

Authentication router for PHISHGUARD.
Provides:
1. User registration with password complexity enforcement and email OTP dispatch.
2. 6-digit email OTP verification.
3. Resend OTP with cooldown rate-limiting.
4. Login with email/username, password verification, and email verification check.
5. Authenticated user profile retrieval (/me) and password change.

Security controls:
- Structured error responses with standard error codes.
- Cryptographically secure OTP generation (secrets module).
- OTPs hashed at rest with constant-time verification.
- Maximum attempt limiting and expiration timeouts.
- No sensitive keys, passwords, or OTPs ever logged or returned in responses.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import auth as auth_utils
from app import config, database, models, schemas
from app.services import email_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def raise_auth_error(
    status_code: int,
    code: str,
    message: str,
    field: Optional[str] = None,
) -> None:
    """
    Raise a standardized structured authentication error.
    Ensures frontend and automated clients receive predictable error structures.
    """
    error_payload = {
        "error": {
            "code": code,
            "message": message,
            "field": field,
        }
    }
    raise HTTPException(
        status_code=status_code,
        detail=error_payload,
    )


def normalize_email(email: Optional[str]) -> str:
    """
    Canonical email normalization:
    - Strips surrounding whitespace
    - Normalizes case to lowercase
    """
    if not email:
        return ""
    return str(email).strip().lower()


def normalize_username(username: Optional[str]) -> str:
    """
    Canonical username normalization:
    - Strips surrounding whitespace
    - Preserves case for display
    """
    if not username:
        return ""
    return str(username).strip()


@router.post(
    "/register",
    response_model=schemas.AuthMessageResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_data: schemas.UserRegister,
    db: Session = Depends(database.get_db),
):
    """
    Register a new user account and initiate email OTP verification.

    Steps:
    1. Validate password complexity (min 8 chars, uppercase, lowercase, digit, special).
    2. Check for duplicate username or verified email.
    3. Create/update unverified user record with Argon2id password hash.
    4. Generate cryptographically secure 6-digit OTP and store HMAC hash with expiration.
    5. Deliver verification email via secure SMTP.
    6. Return pending_verification status (OTP is NEVER returned in response).
    """
    # 1. Validate password complexity
    is_valid_pw, pw_err = auth_utils.validate_password_strength(user_data.password)
    if not is_valid_pw:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PASSWORD_TOO_WEAK",
            message=pw_err,
            field="password",
        )

    # 2. Normalize inputs using canonical normalizers
    norm_username = normalize_username(user_data.username)
    norm_email = normalize_email(user_data.email)

    # 3. Check for existing username (case-insensitive)
    existing_username = (
        db.query(models.User)
        .filter(func.lower(models.User.username) == norm_username.lower())
        .first()
    )

    # 4. Check for existing email (case-insensitive)
    existing_email_user = (
        db.query(models.User)
        .filter(func.lower(models.User.email) == norm_email)
        .first()
    )

    if existing_username:
        raise_auth_error(
            status_code=status.HTTP_409_CONFLICT,
            code="USERNAME_ALREADY_REGISTERED",
            message="Username already registered.",
            field="username",
        )

    if existing_email_user:
        raise_auth_error(
            status_code=status.HTTP_409_CONFLICT,
            code="EMAIL_ALREADY_REGISTERED",
            message="Email already registered.",
            field="email",
        )

    # Create new unverified user
    password_hash = auth_utils.hash_password(user_data.password)
    db_user = models.User(
        username=norm_username,
        email=norm_email,
        password_hash=password_hash,
        is_active=True,
        is_verified=False,
    )
    db.add(db_user)

    try:
        db.commit()
        db.refresh(db_user)
        # Safe explicit persistence verification query
        persisted_user = db.query(models.User).filter(models.User.id == db_user.id).first()
        if not persisted_user:
            db.rollback()
            raise_auth_error(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                code="PERSISTENCE_FAILED",
                message="Failed to persist user in database.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise_auth_error(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="DATABASE_ERROR",
            message=f"Database transaction failure: {str(exc)}",
        )

    # 4. Generate 6-digit OTP and store hash
    otp = auth_utils.generate_otp()
    otp_hash = auth_utils.hash_otp(otp)
    expires_at = datetime.utcnow() + timedelta(minutes=config.OTP_EXPIRE_MINUTES)

    # Invalidate any previous OTP records for this user/email
    db.query(models.EmailVerificationOTP).filter(
        (func.lower(models.EmailVerificationOTP.email) == norm_email) |
        (models.EmailVerificationOTP.user_id == db_user.id)
    ).delete()

    otp_record = models.EmailVerificationOTP(
        user_id=db_user.id,
        email=norm_email,
        otp_hash=otp_hash,
        expires_at=expires_at,
        attempts_count=0,
        last_sent_at=datetime.utcnow(),
    )
    db.add(otp_record)
    db.commit()
    db.refresh(otp_record)

    # 5. Send verification email via SMTP
    email_sent = email_service.send_otp_email(norm_email, otp)
    if not email_sent:
        # Invalidate the newly created OTP record since delivery failed
        db.query(models.EmailVerificationOTP).filter(
            (func.lower(models.EmailVerificationOTP.email) == norm_email) |
            (models.EmailVerificationOTP.user_id == db_user.id)
        ).delete()
        db.commit()
        raise_auth_error(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="EMAIL_DELIVERY_FAILED",
            message="Failed to deliver the verification code via email. Please check your email configuration or try again later.",
            field="email",
        )

    return schemas.AuthMessageResponse(
        status="pending_verification",
        message="Account created. Please check your email for the 6-digit verification code.",
        email=norm_email,
    )


@router.post(
    "/verify-otp",
    response_model=schemas.AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
def verify_otp(
    payload: schemas.VerifyOTPRequest,
    db: Session = Depends(database.get_db),
):
    """
    Verify the 6-digit email OTP and activate the user account.

    Checks:
    - User exists in the database.
    - User is not already verified.
    - Active OTP record exists for email / user ID.
    - Expiration window has not passed.
    - Attempt limit has not been exceeded.
    - Constant-time verification of OTP hash against submission.
    """
    clean_email = normalize_email(payload.email)
    clean_otp = payload.otp.strip()

    # 1. Resolve registered user first
    user = (
        db.query(models.User)
        .filter(func.lower(models.User.email) == clean_email)
        .first()
    )

    if not user:
        raise_auth_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="USER_NOT_FOUND",
            message="No account found associated with this email address.",
            field="email",
        )

    if user.is_verified:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="EMAIL_ALREADY_VERIFIED",
            message="This account is already verified. Please sign in.",
            field="email",
        )

    # 2. Query active OTP record for user / email
    otp_record = (
        db.query(models.EmailVerificationOTP)
        .filter(
            (func.lower(models.EmailVerificationOTP.email) == clean_email) |
            (models.EmailVerificationOTP.user_id == user.id)
        )
        .order_by(models.EmailVerificationOTP.last_sent_at.desc())
        .first()
    )

    if not otp_record:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OTP",
            message="No active verification code found for this email. Please request a new code.",
            field="otp",
        )

    # 3. Check attempt limit
    if otp_record.attempts_count >= config.MAX_OTP_ATTEMPTS:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="OTP_TOO_MANY_ATTEMPTS",
            message="Too many incorrect attempts. Please request a new verification code.",
            field="otp",
        )

    # 4. Check expiration
    if datetime.utcnow() > otp_record.expires_at:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="OTP_EXPIRED",
            message="This verification code has expired. Please request a new code.",
            field="otp",
        )

    # 5. Verify constant-time hash
    if not auth_utils.verify_otp_hash(clean_otp, otp_record.otp_hash):
        otp_record.attempts_count += 1
        db.commit()
        remaining_attempts = max(0, config.MAX_OTP_ATTEMPTS - otp_record.attempts_count)
        if remaining_attempts > 0:
            msg = f"Invalid verification code. {remaining_attempts} {'attempt' if remaining_attempts == 1 else 'attempts'} remaining."
        else:
            msg = "Too many incorrect attempts. Please request a new verification code."
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OTP",
            message=msg,
            field="otp",
        )

    # 6. Correct OTP entered -> Activate user
    user.is_verified = True
    user.is_active = True

    # 7. Invalidate / delete all OTP records for this user
    db.query(models.EmailVerificationOTP).filter(
        (func.lower(models.EmailVerificationOTP.email) == clean_email) |
        (models.EmailVerificationOTP.user_id == user.id)
    ).delete()

    db.commit()

    return schemas.AuthMessageResponse(
        status="verified",
        message="Email verified successfully. You can now sign in.",
        email=clean_email,
    )


@router.post(
    "/resend-otp",
    response_model=schemas.AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
def resend_otp(
    payload: schemas.ResendOTPRequest,
    db: Session = Depends(database.get_db),
):
    """
    Generate and dispatch a new 6-digit email OTP with cooldown rate-limiting.

    Checks:
    - User exists and is not already verified.
    - Cooldown interval (default 30s) has elapsed since last dispatch.
    - Invalidates previous OTP and resets attempt counters.
    """
    clean_email = normalize_email(payload.email)

    user = (
        db.query(models.User)
        .filter(func.lower(models.User.email) == clean_email)
        .first()
    )
    if not user:
        raise_auth_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="USER_NOT_FOUND",
            message="No account found with this email address.",
            field="email",
        )

    if user.is_verified:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="EMAIL_ALREADY_VERIFIED",
            message="This account is already verified. Please sign in.",
            field="email",
        )

    # Check resend cooldown on existing OTP record
    otp_record = (
        db.query(models.EmailVerificationOTP)
        .filter(
            (func.lower(models.EmailVerificationOTP.email) == clean_email) |
            (models.EmailVerificationOTP.user_id == user.id)
        )
        .order_by(models.EmailVerificationOTP.last_sent_at.desc())
        .first()
    )

    if otp_record:
        elapsed = (datetime.utcnow() - otp_record.last_sent_at).total_seconds()
        if elapsed < config.OTP_RESEND_COOLDOWN_SECONDS:
            remaining = int(config.OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            raise_auth_error(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                code="OTP_RESEND_TOO_SOON",
                message=f"Please wait {remaining} seconds before requesting a new code.",
                field="otp",
            )

    # Invalidate existing OTPs and generate new one
    db.query(models.EmailVerificationOTP).filter(
        (func.lower(models.EmailVerificationOTP.email) == clean_email) |
        (models.EmailVerificationOTP.user_id == user.id)
    ).delete()

    otp = auth_utils.generate_otp()
    otp_hash = auth_utils.hash_otp(otp)
    expires_at = datetime.utcnow() + timedelta(minutes=config.OTP_EXPIRE_MINUTES)

    new_record = models.EmailVerificationOTP(
        user_id=user.id,
        email=clean_email,
        otp_hash=otp_hash,
        expires_at=expires_at,
        attempts_count=0,
        last_sent_at=datetime.utcnow(),
    )
    db.add(new_record)
    db.commit()
    db.refresh(new_record)

    email_sent = email_service.send_otp_email(clean_email, otp)
    if not email_sent:
        # Revert OTP creation on delivery failure
        db.query(models.EmailVerificationOTP).filter(
            (func.lower(models.EmailVerificationOTP.email) == clean_email) |
            (models.EmailVerificationOTP.user_id == user.id)
        ).delete()
        db.commit()
        raise_auth_error(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="EMAIL_DELIVERY_FAILED",
            message="Failed to deliver the verification code via email. Please check your email configuration or try again later.",
            field="email",
        )

    return schemas.AuthMessageResponse(
        status="resent",
        message="A new verification code has been sent to your email.",
        email=clean_email,
    )


@router.post(
    "/login",
    response_model=schemas.TokenResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    credentials: schemas.UserLogin,
    db: Session = Depends(database.get_db),
):
    """
    Authenticate a user with email/username and password.

    Requires:
    - User exists (checked case-insensitively for email or username with whitespace trimmed).
    - Password matches Argon2id hash.
    - User account is active (is_active=True).
    - User email has been verified (is_verified=True).
    """
    raw_ident = credentials.email_or_username.strip()
    norm_ident = normalize_email(raw_ident) if "@" in raw_ident else raw_ident.lower()

    user = (
        db.query(models.User)
        .filter(
            (func.lower(models.User.email) == norm_ident)
            | (func.lower(models.User.username) == norm_ident)
        )
        .first()
    )

    detailed_errors = config.AUTH_DETAILED_LOGIN_ERRORS

    if not user:
        if detailed_errors:
            raise_auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="USER_NOT_FOUND",
                message="Account not found. Please register.",
                field="email_or_username",
            )
        else:
            raise_auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="INVALID_CREDENTIALS",
                message="Incorrect email or password.",
            )

    if not user.is_active:
        raise_auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            message="User account is deactivated.",
        )

    if not user.is_verified:
        raise_auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="EMAIL_NOT_VERIFIED",
            message="Please verify your email before signing in.",
            field="email",
        )

    if not auth_utils.verify_password(credentials.password, user.password_hash):
        if detailed_errors:
            raise_auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="INVALID_PASSWORD",
                message="Incorrect password.",
                field="password",
            )
        else:
            raise_auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="INVALID_CREDENTIALS",
                message="Incorrect email or password.",
            )

    access_token = auth_utils.create_access_token(data={"sub": str(user.id)})
    return schemas.TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=schemas.UserResponse.model_validate(user),
    )


@router.get("/status/{identifier}")
def check_user_auth_status(
    identifier: str,
    db: Session = Depends(database.get_db),
):
    """
    Safe development diagnostic endpoint to check user account existence and verification state.
    Restricted to non-production environments to prevent account enumeration.
    NEVER exposes plaintext passwords, password hashes, OTPs, or secret tokens.
    """
    if os.getenv("ENVIRONMENT", config.ENVIRONMENT).lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Diagnostics endpoint is disabled in production environments.",
        )

    ident = identifier.strip().lower()
    user = (
        db.query(models.User)
        .filter(
            (func.lower(models.User.email) == ident)
            | (func.lower(models.User.username) == ident)
        )
        .first()
    )

    if not user:
        return {
            "exists": False,
            "identifier": identifier,
            "message": "No account found matching this username or email.",
        }

    return {
        "exists": True,
        "username": user.username,
        "email_masked": f"{user.email[:3]}***@{user.email.split('@')[-1]}" if "@" in user.email else user.email,
        "is_active": bool(user.is_active),
        "is_verified": bool(user.is_verified),
        "auth_algorithm": "argon2id",
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.get("/me", response_model=schemas.UserResponse)
def read_current_user(current_user: models.User = Depends(auth_utils.get_current_user)):
    """Return the authenticated user's profile information."""
    return schemas.UserResponse.model_validate(current_user)


@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    payload: schemas.PasswordChange,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth_utils.get_current_user),
):
    """
    Allow an authenticated user to change their account password.
    """
    if not auth_utils.verify_password(payload.current_password, current_user.password_hash):
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CURRENT_PASSWORD",
            message="Current password is incorrect.",
            field="current_password",
        )

    is_valid_pw, pw_err = auth_utils.validate_password_strength(payload.new_password)
    if not is_valid_pw:
        raise_auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PASSWORD_TOO_WEAK",
            message=pw_err,
            field="new_password",
        )

    new_hash = auth_utils.hash_password(payload.new_password)
    current_user.password_hash = new_hash
    db.add(current_user)
    db.commit()
    return {"detail": "Password changed successfully."}
