"""
app/services/gmail_service.py

Google OAuth 2.0 and Gmail API client for PHISHGUARD Mail Security.
Implements:
1. CSRF-protected OAuth 2.0 authorization URL generation and state validation.
2. Server-side authorization code exchange and token refresh.
3. User profile resolution (emailAddress, historyId).
4. Mailbox push watch setup (Gmail users.watch with Cloud Pub/Sub topic) and teardown.
5. Incremental history synchronization (users.history.list) with expired history recovery.
6. Full-fidelity raw RFC 822 email retrieval (users.messages.get with format=raw).

Security controls:
- Scopes restricted strictly to 'https://www.googleapis.com/auth/gmail.readonly'.
- All OAuth states are cryptographically signed with HMAC-SHA256 and expire in 10 minutes.
- Secrets, access tokens, and refresh tokens are NEVER logged.
- Network requests use bounded timeouts (15s) and catch specific HTTP status codes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx

from app import config
from app.services.crypto_service import decrypt_credentials, encrypt_credentials

logger = logging.getLogger("phishguard.gmail")

# Google API Endpoints
GOOGLE_OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE_URL = "https://gmail.googleapis.com/gmail/v1/users/me"


# ============================================================================
# 0. CUSTOM EXCEPTIONS
# ============================================================================

class GoogleAuthError(Exception):
    """Base exception for Google OAuth/Gmail API errors."""
    pass


class GoogleAuthRevokedError(GoogleAuthError):
    """Raised when Google OAuth credentials/refresh token are revoked, invalid, or expired beyond recovery."""
    pass


class GoogleAuthRefreshError(GoogleAuthError):
    """Raised when a transient error occurs while refreshing credentials."""
    pass


# ============================================================================
# 1. OAUTH STATE MANAGEMENT (CSRF & USER BINDING)
# ============================================================================

def generate_oauth_state(user_id: int) -> str:
    """
    Generate a tamper-proof, time-bound OAuth state string bound to the user ID.

    Format: base64url(json({user_id, timestamp, nonce})).signature

    Args:
        user_id: The authenticated PHISHGUARD user initiating OAuth.

    Returns:
        Signed state string for Google authorization URL.
    """
    payload = {
        "uid": user_id,
        "ts": int(time.time()),
        "rnd": base64.b64encode(hashlib.sha256(str(time.time()).encode()).digest()[:12]).decode(),
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    signature = hmac.new(
        config.SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def verify_oauth_state(state_str: str, max_age_seconds: int = 600) -> Optional[int]:
    """
    Verify signature and timestamp of an OAuth state string returned by Google callback.

    Args:
        state_str: The state query parameter from the callback.
        max_age_seconds: Maximum validity window (default 10 minutes).

    Returns:
        The bound user_id if valid, None if invalid or expired.
    """
    if not state_str or "." not in state_str:
        logger.warning("Invalid OAuth state format received.")
        return None

    try:
        payload_b64, signature = state_str.split(".", 1)
        expected_sig = hmac.new(
            config.SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            logger.warning("OAuth state HMAC signature verification failed.")
            return None

        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode())
        ts = payload.get("ts", 0)
        if time.time() - ts > max_age_seconds:
            logger.warning("OAuth state expired (age: %s seconds).", int(time.time() - ts))
            return None

        return int(payload.get("uid"))
    except Exception as exc:
        logger.warning("Error parsing OAuth state: %s", exc)
        return None


# ============================================================================
# 2. OAUTH AUTHORIZATION & TOKEN EXCHANGE
# ============================================================================

def get_gmail_authorization_url(user_id: int) -> str:
    """
    Construct the Google OAuth 2.0 authorization URL for connecting a Gmail account.

    Args:
        user_id: ID of the authenticating user.

    Returns:
        Full Google OAuth authorization redirect URL.
    """
    state = generate_oauth_state(user_id)
    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(config.GMAIL_OAUTH_SCOPES),
        "access_type": "offline",
        "prompt": "consent",  # Guarantees refresh_token is returned
        "state": state,
        "include_granted_scopes": "true",
    }
    return f"{GOOGLE_OAUTH_AUTH_URL}?{urlencode(params)}"


def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    """
    Exchange authorization code for access and refresh tokens via Google token endpoint.

    Args:
        code: Authorization code received in callback.

    Returns:
        Dictionary containing tokens and metadata:
        { "access_token": "...", "refresh_token": "...", "expires_in": 3599, "expires_at": 1700000000, "token_type": "Bearer" }

    Raises:
        RuntimeError: If Google token endpoint rejects the exchange.
    """
    payload = {
        "code": code,
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(GOOGLE_OAUTH_TOKEN_URL, data=payload)
            if resp.status_code != 200:
                logger.error("OAuth token exchange failed with status %s", resp.status_code)
                raise RuntimeError(f"Google token exchange failed (HTTP {resp.status_code})")
            data = resp.json()
            if "expires_in" in data and "expires_at" not in data:
                data["expires_at"] = int(time.time() + data["expires_in"])
            return data
    except httpx.RequestError as exc:
        logger.error("Network error during token exchange: %s", exc)
        raise RuntimeError("Unable to communicate with Google authentication server.") from exc


def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    """
    Obtain a fresh access token using a stored refresh token.

    Args:
        refresh_token: Stored provider refresh token.

    Returns:
        Dictionary containing new access_token, expires_in, and expires_at.

    Raises:
        GoogleAuthRevokedError: If Google token endpoint returns 400/401 (invalid_grant / revoked).
        GoogleAuthRefreshError: On network or server errors.
    """
    if not refresh_token or not str(refresh_token).strip():
        raise GoogleAuthRevokedError("Missing or empty refresh token. Re-authentication required.")

    payload = {
        "refresh_token": str(refresh_token).strip(),
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(GOOGLE_OAUTH_TOKEN_URL, data=payload)
            if resp.status_code == 200:
                data = resp.json()
                if "expires_in" in data and "expires_at" not in data:
                    data["expires_at"] = int(time.time() + data["expires_in"])
                return data
            elif resp.status_code in (400, 401):
                err_code = ""
                err_desc = ""
                try:
                    err_body = resp.json()
                    err_code = err_body.get("error", "")
                    err_desc = err_body.get("error_description", "")
                except Exception:
                    pass
                logger.warning("Token refresh rejected (HTTP %s, error=%s): %s", resp.status_code, err_code, err_desc)
                if err_code in ("invalid_grant", "unauthorized_client", "invalid_client"):
                    raise GoogleAuthRevokedError(f"Google authorization invalid or revoked ({err_code}). Please reconnect Gmail.")
                raise GoogleAuthRevokedError(f"Token refresh rejected (HTTP {resp.status_code}: {err_code or 'unauthorized'})")
            else:
                logger.error("Token refresh request failed with HTTP %s", resp.status_code)
                raise GoogleAuthRefreshError(f"Token refresh server error (HTTP {resp.status_code})")
    except (GoogleAuthRevokedError, GoogleAuthRefreshError):
        raise
    except httpx.RequestError as exc:
        logger.error("Network error during token refresh: %s", exc)
        raise GoogleAuthRefreshError("Failed to communicate with Google authentication server.") from exc


def get_valid_access_token(
    credentials: Any,
    force_refresh: bool = False,
    refresh_buffer_seconds: int = 300,
) -> Tuple[str, Dict[str, Any]]:
    """
    Extract and return an active access token from encrypted credential ciphertext or credentials dict.
    Refreshes the token automatically if near expiration or force_refresh is True.

    Args:
        credentials: Encrypted token payload ciphertext or credential dictionary.
        force_refresh: Force token refresh regardless of expiration timestamp.
        refresh_buffer_seconds: Time window before expiration to trigger refresh (default 300s = 5m).

    Returns:
        Tuple of (active_access_token, updated_credentials_dict).

    Raises:
        GoogleAuthRevokedError: If credentials cannot be decrypted, are invalid, or refresh token is revoked.
        GoogleAuthRefreshError: On transient network/server refresh failure.
    """
    if isinstance(credentials, str):
        creds = decrypt_credentials(credentials)
    elif isinstance(credentials, dict):
        creds = dict(credentials)
    else:
        creds = {}

    if not creds:
        raise GoogleAuthRevokedError("Missing or unreadable mailbox credentials. Re-authentication required.")

    access_token = creds.get("access_token", "")
    refresh_tok = creds.get("refresh_token", "")
    expires_at = creds.get("expires_at", 0)

    now = int(time.time())
    is_expired_or_expiring = force_refresh or (now + refresh_buffer_seconds >= expires_at) or not access_token

    if is_expired_or_expiring:
        if not refresh_tok:
            if not access_token or (expires_at and now >= expires_at):
                raise GoogleAuthRevokedError("Access token expired and no refresh token is present. Re-authentication required.")
            # If access token is still technically valid but within buffer without refresh token, return it
            return access_token, creds

        logger.info("Access token expired or near expiry (now=%s, expires_at=%s). Initiating automatic refresh...", now, expires_at)
        refreshed = refresh_access_token(refresh_tok)
        new_access_token = refreshed.get("access_token")
        if not new_access_token:
            raise GoogleAuthRevokedError("Token refresh did not return a valid access token.")

        creds["access_token"] = new_access_token
        expires_in = refreshed.get("expires_in", 3600)
        creds["expires_at"] = int(time.time() + expires_in)
        # Preserve existing refresh token if not replaced
        if refreshed.get("refresh_token"):
            creds["refresh_token"] = refreshed["refresh_token"]

        return new_access_token, creds

    return access_token, creds


# ============================================================================
# 3. GMAIL API ACTIONS (PROFILE, WATCH, SYNC, MESSAGE RETRIEVAL)
# ============================================================================

def get_gmail_profile(access_token: str) -> Dict[str, Any]:
    """
    Retrieve user profile information from Gmail API.

    Args:
        access_token: Active Google OAuth access token.

    Returns:
        Dictionary with emailAddress, messagesTotal, threadsTotal, historyId.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{GMAIL_API_BASE_URL}/profile", headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Gmail profile lookup failed with HTTP {resp.status_code}")
            return resp.json()
    except httpx.RequestError as exc:
        logger.error("Network error fetching Gmail profile: %s", exc)
        raise RuntimeError("Failed to contact Gmail API.") from exc


def setup_mailbox_watch(access_token: str, topic_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Enable push notifications for incoming Inbox messages via Google Cloud Pub/Sub.

    Args:
        access_token: Active Google OAuth access token.
        topic_name: Cloud Pub/Sub topic name (defaults to config.GOOGLE_PUBSUB_TOPIC).

    Returns:
        Dictionary containing { "historyId": "...", "expiration": "..." }.
    """
    target_topic = topic_name or config.GOOGLE_PUBSUB_TOPIC
    if not target_topic:
        logger.warning("GOOGLE_PUBSUB_TOPIC not configured. Watch setup returned mock response in dev.")
        return {
            "historyId": "1000",
            "expiration": str(int((time.time() + 7 * 86400) * 1000)),
        }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "topicName": target_topic,
        "labelIds": ["INBOX"],
        "labelFilterAction": "include",
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{GMAIL_API_BASE_URL}/watch", headers=headers, json=payload)
            if resp.status_code != 200:
                logger.error("Gmail users.watch returned HTTP %s: %s", resp.status_code, resp.text)
                raise RuntimeError(f"Gmail mailbox watch setup failed (HTTP {resp.status_code})")
            return resp.json()
    except httpx.RequestError as exc:
        logger.error("Network error setting up Gmail watch: %s", exc)
        raise RuntimeError("Failed to communicate with Gmail watch API.") from exc


def stop_mailbox_watch(access_token: str) -> bool:
    """
    Stop active push notifications for the Gmail account.

    Args:
        access_token: Active Google OAuth access token.

    Returns:
        True if stopped successfully, False otherwise.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(f"{GMAIL_API_BASE_URL}/stop", headers=headers)
            return resp.status_code in (200, 204)
    except Exception as exc:
        logger.warning("Failed to stop Gmail mailbox watch: %s", exc)
        return False


def fetch_history_changes(
    access_token: str,
    start_history_id: str,
) -> Tuple[List[str], str]:
    """
    Fetch message IDs added to INBOX since start_history_id using users.history.list.
    Handles expired historyId by falling back to listing recent INBOX messages.

    Args:
        access_token: Active access token.
        start_history_id: Previously recorded historyId.

    Returns:
        Tuple of ([new_message_ids], latest_history_id).
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        "startHistoryId": str(start_history_id),
        "historyTypes": "messageAdded",
        "labelId": "INBOX",
        "maxResults": 100,
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{GMAIL_API_BASE_URL}/history", headers=headers, params=params)

            # Handle history expiration (HTTP 404 / 410)
            if resp.status_code in (404, 410):
                logger.warning("History ID %s expired. Performing fallback sync on recent INBOX messages.", start_history_id)
                return fetch_recent_inbox_message_ids(access_token, max_results=20)

            if resp.status_code != 200:
                raise RuntimeError(f"Gmail history lookup failed with HTTP {resp.status_code}")

            data = resp.json()
            history_records = data.get("history", [])
            latest_history_id = str(data.get("historyId", start_history_id))

            message_ids = set()
            for h in history_records:
                messages_added = h.get("messagesAdded", [])
                for item in messages_added:
                    msg = item.get("message", {})
                    # Verify message is labeled INBOX
                    labels = msg.get("labelIds", [])
                    if not labels or "INBOX" in labels:
                        if msg.get("id"):
                            message_ids.add(msg.get("id"))

            return list(message_ids), latest_history_id

    except httpx.RequestError as exc:
        logger.error("Network error during Gmail history sync: %s", exc)
        raise RuntimeError("Failed to sync Gmail history.") from exc


def fetch_recent_inbox_message_ids(access_token: str, max_results: int = 20) -> Tuple[List[str], str]:
    """
    Fallback synchronization: fetch recent message IDs currently residing in the INBOX.

    Args:
        access_token: Active access token.
        max_results: Max messages to retrieve (default 20).

    Returns:
        Tuple of ([message_ids], current_history_id).
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        "q": "label:INBOX",
        "maxResults": max_results,
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{GMAIL_API_BASE_URL}/messages", headers=headers, params=params)
            if resp.status_code != 200:
                raise RuntimeError(f"Fallback message listing failed (HTTP {resp.status_code})")
            data = resp.json()
            msg_ids = [m["id"] for m in data.get("messages", []) if "id" in m]

            # Fetch current profile historyId
            profile = get_gmail_profile(access_token)
            current_history_id = str(profile.get("historyId", "1"))
            return msg_ids, current_history_id
    except Exception as exc:
        logger.error("Error during fallback inbox listing: %s", exc)
        return [], "1"


def fetch_raw_message_bytes(access_token: str, message_id: str) -> Optional[bytes]:
    """
    Retrieve full, unparsed RFC 822 email bytes for a specific message ID via Gmail API format=raw.

    Args:
        access_token: Active access token.
        message_id: Gmail message identifier string.

    Returns:
        Raw email message bytes if retrieved, None on failure.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"format": "raw"}

    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{GMAIL_API_BASE_URL}/messages/{message_id}", headers=headers, params=params)
            if resp.status_code == 404:
                logger.warning("Message %s not found in Gmail mailbox (may have been deleted).", message_id)
                return None
            if resp.status_code != 200:
                logger.error("Failed to fetch message %s (HTTP %s)", message_id, resp.status_code)
                return None

            data = resp.json()
            raw_b64 = data.get("raw")
            if not raw_b64:
                logger.warning("Message %s returned empty raw payload.", message_id)
                return None

            # Decode URL-safe base64
            return base64.urlsafe_b64decode(raw_b64.encode("utf-8"))

    except httpx.RequestError as exc:
        logger.error("Network error retrieving raw message %s: %s", message_id, exc)
        return None
    except Exception as exc:
        logger.error("Unexpected error decoding message %s: %s", message_id, exc)
        return None


def decode_pubsub_message_data(data_b64: str) -> Dict[str, Any]:
    """
    Decode Base64 / URL-safe Base64 Google Cloud Pub/Sub message data into dictionary.
    Expected decoded structure: { "emailAddress": "user@gmail.com", "historyId": "12345" }

    Args:
        data_b64: Base64 string from Pub/Sub message.data.

    Returns:
        Parsed dictionary or empty dict on decode error.
    """
    if not data_b64:
        return {}
    try:
        padded = data_b64 + "=" * ((4 - len(data_b64) % 4) % 4)
        try:
            decoded_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            decoded_bytes = base64.b64decode(padded)
        return json.loads(decoded_bytes.decode("utf-8"))
    except Exception as exc:
        logger.warning("Failed to decode Pub/Sub message data: %s", exc)
        return {}
