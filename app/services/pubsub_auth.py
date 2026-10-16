"""
app/services/pubsub_auth.py

Google Cloud Pub/Sub Push Authentication & OIDC JWT Verification.

Follows Google Cloud Pub/Sub Security Best Practices:
1. Extract Bearer token from the Authorization header or query parameter.
2. Verify RS256 signature against Google's public JSON Web Key Set (JWKS).
3. Validate Issuer ('iss' in ['https://accounts.google.com', 'accounts.google.com']).
4. Validate Audience ('aud' matches configured GOOGLE_PUBSUB_AUDIENCE).
5. Validate Service Account Identity ('email' matches GOOGLE_PUBSUB_SERVICE_ACCOUNT & 'email_verified' is True).
6. Support fallback shared verification token for lightweight or development environments.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
import jwt
from jwt import PyJWKClient, PyJWTError

from app import config

logger = logging.getLogger("phishguard.pubsub_auth")

# Google's official public certificate JWKS endpoint for Google service accounts
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_VALID_ISSUERS = ["https://accounts.google.com", "accounts.google.com"]

# Global cached JWKS client for efficient key retrieval and cache reuse
_jwks_client: Optional[PyJWKClient] = None


def get_jwks_client(jwks_url: str = GOOGLE_JWKS_URL) -> PyJWKClient:
    """
    Get or initialize the cached JWKS client for Google's public certs.
    """
    global _jwks_client
    if _jwks_client is None or _jwks_client.uri != jwks_url:
        _jwks_client = PyJWKClient(jwks_url, cache_keys=True, max_cached_keys=16, lifespan=3600)
    return _jwks_client


def validate_pubsub_jwt(
    token: str,
    expected_audience: Optional[str] = None,
    expected_service_account: Optional[str] = None,
    jwks_client: Optional[PyJWKClient] = None,
    allowed_issuers: Optional[List[str]] = None,
    algorithms: Optional[List[str]] = None,
    signing_key_override: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Strictly validate a Google Cloud Pub/Sub Push OIDC JWT:
    1. Validate signature using Google JWKS or key override.
    2. Validate issuer ('https://accounts.google.com' or 'accounts.google.com').
    3. Validate audience ('aud').
    4. Validate expiration ('exp').
    5. Validate service account identity ('email' and 'email_verified').

    Args:
        token: Raw JWT string from Authorization Bearer header.
        expected_audience: Expected audience string (defaults to config.GOOGLE_PUBSUB_AUDIENCE).
        expected_service_account: Expected service account email (defaults to config.GOOGLE_PUBSUB_SERVICE_ACCOUNT).
        jwks_client: Optional custom PyJWKClient for testing/mocking.
        allowed_issuers: List of allowed issuers.
        algorithms: List of allowed algorithms (defaults to ['RS256']).
        signing_key_override: Direct public key / secret for test fixtures.

    Returns:
        Decoded and fully verified JWT payload dictionary.

    Raises:
        HTTPException(401 / 403): If any cryptographic or claims verification check fails.
    """
    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Pub/Sub authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clean_token = token.strip()
    if expected_audience is not None:
        target_audience = expected_audience
    elif signing_key_override is not None:
        target_audience = None
    else:
        target_audience = config.GOOGLE_PUBSUB_AUDIENCE or None

    if expected_service_account is not None:
        target_sa = expected_service_account.strip().lower()
    elif signing_key_override is not None:
        target_sa = ""
    else:
        target_sa = (config.GOOGLE_PUBSUB_SERVICE_ACCOUNT or "").strip().lower()

    valid_issuers = allowed_issuers or GOOGLE_VALID_ISSUERS
    allowed_algs = algorithms or ["RS256"]

    # 1. Resolve signing key
    try:
        if signing_key_override is not None:
            signing_key = signing_key_override
        else:
            client = jwks_client or get_jwks_client()
            jwk = client.get_signing_key_from_jwt(clean_token)
            signing_key = jwk.key
    except Exception as exc:
        logger.warning("Pub/Sub JWT key resolution failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to verify Pub/Sub token signature: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Decode and validate signature, expiration, and issuer
    try:
        decode_options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": bool(target_audience),
            "verify_iss": False,  # Verified explicitly against valid_issuers list below
        }

        payload = jwt.decode(
            clean_token,
            signing_key,
            algorithms=allowed_algs,
            audience=target_audience if target_audience else None,
            options=decode_options,
        )
    except jwt.ExpiredSignatureError:
        logger.warning("Pub/Sub JWT expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Pub/Sub authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        logger.warning("Pub/Sub JWT audience mismatch. Expected: %s", target_audience)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pub/Sub authentication token audience mismatch.",
        )
    except PyJWTError as exc:
        logger.warning("Pub/Sub JWT verification error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Pub/Sub authentication token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Validate Issuer
    token_issuer = payload.get("iss")
    if token_issuer not in valid_issuers:
        logger.warning("Pub/Sub JWT invalid issuer: %s (expected %s)", token_issuer, valid_issuers)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token issuer '{token_issuer}'. Expected Google accounts issuer.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Validate Service Account Identity & Email Verification
    token_email = str(payload.get("email", "")).strip().lower()
    email_verified = payload.get("email_verified")

    # In Google OIDC tokens, email_verified is a boolean True
    if email_verified is False or (isinstance(email_verified, str) and email_verified.lower() == "false"):
        logger.warning("Pub/Sub JWT email is unverified: %s", token_email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pub/Sub service account email is unverified.",
        )

    if target_sa:
        if not token_email or token_email != target_sa:
            logger.warning(
                "Pub/Sub JWT service account mismatch: got '%s', expected '%s'",
                token_email,
                target_sa,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unauthorized Pub/Sub service account identity '{token_email}'.",
            )

    logger.info("Pub/Sub JWT verified successfully for service account: %s", token_email or "google-service-account")
    return payload


def authenticate_pubsub_request(
    authorization_header: Optional[str] = None,
    token_param: Optional[str] = None,
    expected_audience: Optional[str] = None,
    expected_service_account: Optional[str] = None,
    jwks_client: Optional[PyJWKClient] = None,
    signing_key_override: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Unified entrypoint to authenticate incoming Pub/Sub webhook requests.

    Supports:
    1. Google Cloud OIDC JWT (via Authorization: Bearer <jwt> or token=<jwt>).
    2. Shared secret verification token (via query param ?token=... or header).
    3. Unauthenticated pass-through with audit warning if no security controls are configured.

    Returns:
        Authentication metadata dict on success.

    Raises:
        HTTPException: On authentication or authorization failure.
    """
    raw_token = ""
    if authorization_header:
        if authorization_header.startswith("Bearer "):
            raw_token = authorization_header[7:].strip()
        else:
            raw_token = authorization_header.strip()
    elif token_param:
        raw_token = token_param.strip()

    expected_secret_token = config.GOOGLE_PUBSUB_VERIFICATION_TOKEN
    target_audience = expected_audience or config.GOOGLE_PUBSUB_AUDIENCE
    target_sa = expected_service_account or config.GOOGLE_PUBSUB_SERVICE_ACCOUNT

    # Case A: If no security is configured at all (dev mode) and no token supplied
    if not expected_secret_token and not target_audience and not target_sa and not raw_token:
        logger.debug("Pub/Sub push received in open development mode (no auth configured).")
        return {"auth_mode": "none", "status": "authenticated"}

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required Pub/Sub authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Case B: Shared secret token check (if configured and token is not a 3-part JWT)
    is_jwt_format = raw_token.count(".") == 2
    if expected_secret_token and not is_jwt_format:
        if raw_token != expected_secret_token:
            logger.warning("Pub/Sub shared verification token mismatch.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid Pub/Sub verification token.",
            )
        return {"auth_mode": "shared_token", "status": "authenticated"}

    # Case C: Google OIDC JWT verification
    if is_jwt_format:
        claims = validate_pubsub_jwt(
            token=raw_token,
            expected_audience=target_audience,
            expected_service_account=target_sa,
            jwks_client=jwks_client,
            signing_key_override=signing_key_override,
        )
        return {
            "auth_mode": "oidc_jwt",
            "status": "authenticated",
            "claims": claims,
            "service_account": claims.get("email"),
        }

    # Case D: Token provided is not JWT and didn't match shared secret
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid Pub/Sub authentication token format.",
        headers={"WWW-Authenticate": "Bearer"},
    )
