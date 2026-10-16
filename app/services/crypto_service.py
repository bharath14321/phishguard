"""
app/services/crypto_service.py

Symmetric encryption and credential protection service for PHISHGUARD mailbox tokens.
Protects stored OAuth credentials (access tokens, refresh tokens) at rest using AES-128-CBC
with HMAC-SHA256 authenticated encryption via cryptography.fernet.Fernet.

Security guarantees:
1. Tokens are encrypted immediately prior to database persistence.
2. Tokens are decrypted strictly in-memory during external provider API communication.
3. Plaintext tokens, refresh tokens, and encryption keys are never logged or returned over REST.
4. Key derivation uses PBKDF2 with SHA-256 over MAILBOX_TOKEN_ENCRYPTION_KEY or SECRET_KEY.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app import config

logger = logging.getLogger("phishguard.crypto")


def _get_fernet_cipher() -> Fernet:
    """
    Derive a deterministic 32-byte URL-safe base64 Fernet key from configuration.
    Prefers MAILBOX_TOKEN_ENCRYPTION_KEY if set, falling back to SECRET_KEY.
    """
    raw_key = config.MAILBOX_TOKEN_ENCRYPTION_KEY or config.SECRET_KEY
    if not raw_key:
        raw_key = "phishguard-default-dev-credential-encryption-seed"

    # Derive 32 bytes using PBKDF2HMAC with a static salt for persistent encryption
    salt = b"phishguard_mailbox_credential_v1"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(raw_key.encode("utf-8")))
    return Fernet(derived_key)


def encrypt_credentials(credentials: Dict[str, Any]) -> str:
    """
    Serialize and encrypt a dictionary of OAuth tokens/credentials into a Fernet ciphertext string.

    Args:
        credentials: Dictionary containing token data (e.g., access_token, refresh_token, expires_at).

    Returns:
        URL-safe string ciphertext suitable for database storage in MailAccount.encrypted_token.
    """
    if not credentials:
        return ""
    try:
        cipher = _get_fernet_cipher()
        payload_bytes = json.dumps(credentials).encode("utf-8")
        encrypted_bytes = cipher.encrypt(payload_bytes)
        return encrypted_bytes.decode("utf-8")
    except Exception as exc:
        logger.error("Failed to encrypt mailbox credentials: %s", type(exc).__name__)
        raise RuntimeError("Credential encryption failure") from exc


def decrypt_credentials(encrypted_ciphertext: Optional[str]) -> Dict[str, Any]:
    """
    Decrypt and deserialize stored ciphertext into the original dictionary of credentials.

    Args:
        encrypted_ciphertext: Fernet ciphertext string from database.

    Returns:
        Dictionary containing decrypted token data. Returns empty dict if None or invalid.
    """
    if not encrypted_ciphertext:
        return {}
    try:
        cipher = _get_fernet_cipher()
        decrypted_bytes = cipher.decrypt(encrypted_ciphertext.encode("utf-8"))
        return json.loads(decrypted_bytes.decode("utf-8"))
    except InvalidToken:
        logger.warning("Invalid or corrupted ciphertext token encountered during decryption.")
        return {}
    except Exception as exc:
        logger.error("Failed to decrypt mailbox credentials: %s", type(exc).__name__)
        return {}
