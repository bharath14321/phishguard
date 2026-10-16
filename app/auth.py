"""
Authentication, password security, and JWT management.

Uses Argon2id for secure one-way password hashing and PyJWT
for signed, stateless authentication tokens.
"""

from datetime import datetime
from datetime import timedelta
from typing import Optional

import argon2
from argon2.exceptions import InvalidHashError
from argon2.exceptions import VerificationError
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
import jwt
from sqlalchemy.orm import Session

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES
from app.config import JWT_ALGORITHM
from app.config import SECRET_KEY
from app.database import get_db
from app.models import User


# Initialize Argon2id password hasher
_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    type=argon2.Type.ID
)

# HTTP Bearer token extractor
security_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Securely verify a plaintext password against an Argon2id hash.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate that a password meets complexity requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*()_+-=[]{};':"\\|,.<>/?)
    """
    if not password or len(password) < 8:
        return False, "Password must contain at least 8 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    special_chars = set("!@#$%^&*()_+-=[]{};':\"\\|,.<>/?`~")
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character."
    return True, ""


import hashlib
import hmac
import secrets


def generate_otp() -> str:
    """
    Generate a cryptographically secure 6-digit numeric OTP (000000-999999) using secrets.
    """
    # Generate 6-digit number with leading zero padding
    number = secrets.randbelow(1_000_000)
    return f"{number:06d}"


def hash_otp(otp: str) -> str:
    """
    Create a cryptographic hash of an OTP using HMAC-SHA256 with config.SECRET_KEY.
    """
    if not otp:
        raise ValueError("OTP cannot be empty.")
    clean_otp = str(otp).strip()
    from app import config as _app_config
    secret = getattr(_app_config, "SECRET_KEY", SECRET_KEY)
    return hmac.new(
        secret.encode("utf-8"),
        clean_otp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_otp_hash(plain_otp: str, hashed_otp: str) -> bool:
    """
    Verify a plaintext OTP against a stored hash using constant-time comparison.
    """
    if not plain_otp or not hashed_otp:
        return False
    clean_plain = str(plain_otp).strip()
    clean_hashed = str(hashed_otp).strip()
    computed_hash = hash_otp(clean_plain)
    return hmac.compare_digest(computed_hash, clean_hashed)



def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a signed JWT access token with an expiration timestamp.
    """
    to_encode = data.copy()
    now = datetime.utcnow()
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({
        "exp": expire,
        "iat": now
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a signed JWT access token.
    Raises HTTPException(401) on invalid or expired tokens.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or token expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        return payload
    except jwt.PyJWTError:
        raise credentials_exception


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency to authenticate and resolve the current active user
    from the Authorization Bearer header.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required or token expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if credentials is None or not credentials.credentials:
        raise credentials_exception

    token = credentials.credentials
    payload = decode_access_token(token)
    
    user_id_str = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception
        
    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise credentials_exception
        
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )
        
    return user
