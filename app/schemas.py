"""
Pydantic schemas for request validation and response formatting.

Guarantees that sensitive data (passwords, hashes, secret keys)
are never exposed through API responses.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import EmailStr
from pydantic import Field
from pydantic import field_validator


# -------------------------------------------------------------------
# AUTHENTICATION SCHEMAS
# -------------------------------------------------------------------

class UserRegister(BaseModel):
    """
    User registration payload.
    """
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Alphanumeric username (allowed: letters, numbers, _, -, .)"
    )
    email: EmailStr = Field(
        ...,
        description="Valid email address"
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Account password (min 8 characters)"
    )

    @field_validator("username", mode="before")
    @classmethod
    def strip_username(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v

    @field_validator("email", mode="before")
    @classmethod
    def strip_email(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v


class UserLogin(BaseModel):
    """
    User login payload. Supports logging in with either username or email.
    """
    email_or_username: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Registered email address or username"
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Account password"
    )

    @field_validator("email_or_username", mode="before")
    @classmethod
    def strip_login_identifier(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v


class UserResponse(BaseModel):
    """
    Safe public user information (no password hash).
    """
    id: int
    username: str
    email: str
    is_active: bool
    is_verified: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """
    JWT authentication response payload.
    """
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class VerifyOTPRequest(BaseModel):
    """
    Email OTP verification request payload.
    """
    email: EmailStr = Field(..., description="Registered email address to verify")
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$", description="6-digit numeric OTP")


class ResendOTPRequest(BaseModel):
    """
    Request payload to resend email verification OTP.
    """
    email: EmailStr = Field(..., description="Registered email address requesting new OTP")


class AuthMessageResponse(BaseModel):
    """
    Standard message response for registration, OTP sending, and verification.
    """
    status: str
    message: str
    email: Optional[str] = None



class PasswordChange(BaseModel):
    """
    Password change request payload.
    """
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Current account password"
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New account password (min 8 characters)"
    )

# -------------------------------------------------------------------
# ANALYSIS SCHEMAS
# -------------------------------------------------------------------

from pydantic import HttpUrl, BaseModel, Field
from typing import List, Optional, Dict, Any

class URLInput(BaseModel):
    """Request payload for URL analysis."""
    url: HttpUrl = Field(..., description="HTTP or HTTPS URL to analyze")

class HashInput(BaseModel):
    """Request payload for hash analysis."""
    hash: str = Field(
        ..., min_length=32, max_length=64, description="MD5/SHA1/SHA256 hash string"
    )

class AnalysisResponse(BaseModel):
    """Unified response format for all analysis endpoints."""
    analysis_id: Optional[int] = None
    artifact_type: str
    risk: Dict[str, Any]
    summary: str = ""
    signals: List[Any] = []
    details: Dict[str, Any] = {}
    explanation: Dict[str, Any] = {}
    errors: List[str] = []

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------
# CHAT / AI SECURITY ANALYST SCHEMAS
# -------------------------------------------------------------------

class ChatRequest(BaseModel):
    """Payload for AI Security Analyst chat queries."""
    message: str = Field(..., min_length=1, max_length=2000, description="User question or analysis inquiry")
    analysis_id: Optional[int] = Field(None, description="Optional ID of saved analysis to load context from")
    analysis_context: Optional[Dict[str, Any]] = Field(None, description="Optional direct analysis result dictionary")


class ChatResponse(BaseModel):
    """Response format for AI Security Analyst chat."""
    response: str
    artifact_type: Optional[str] = None
    risk_level: Optional[str] = None
    provider: str = "security_analyst"
    timestamp: str
    analysis_id: Optional[int] = Field(None, description="Associated analysis ID if context was loaded")

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------
# MAIL SECURITY SCHEMAS
# -------------------------------------------------------------------

class MailAccountConnect(BaseModel):
    """Request payload to connect a mailbox provider."""
    provider: str = Field(..., pattern=r"^(gmail|outlook|google|microsoft)$", description="Mail provider: 'gmail' or 'outlook'")
    account_email: EmailStr = Field(..., description="Email address of the mailbox to connect")
    access_token: Optional[str] = Field(None, description="OAuth access token (encrypted at rest)")
    refresh_token: Optional[str] = Field(None, description="OAuth refresh token")


class MailAccountResponse(BaseModel):
    """Safe public representation of a connected mailbox account."""
    id: int
    provider: str
    account_email: str
    is_active: bool
    sync_status: str
    last_synced_at: Optional[datetime] = None
    watch_expiration: Optional[datetime] = None
    has_watch: Optional[bool] = False
    last_error: Optional[str] = None
    total_scanned: Optional[int] = 0
    threats_detected: Optional[int] = 0
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MailIngestRequest(BaseModel):
    """Webhook/API payload for ingesting an email from connected inbox."""
    provider: str = Field(..., description="Mail provider: 'gmail' or 'outlook'")
    provider_message_id: str = Field(..., min_length=1, max_length=255, description="Unique message ID in provider system")
    sender_email: str = Field(..., description="Sender email address")
    sender_name: Optional[str] = Field(None, description="Sender display name")
    recipient_email: Optional[str] = Field(None, description="Recipient email address")
    subject: Optional[str] = Field(None, description="Email subject line")
    body_text: Optional[str] = Field(None, description="Plain text email body")
    body_html: Optional[str] = Field(None, description="HTML formatted email body")
    raw_eml: Optional[str] = Field(None, description="Raw RFC 822 / MIME .eml content string")
    headers: Optional[Dict[str, str]] = Field(None, description="Dictionary of email headers")
    received_at: Optional[datetime] = Field(None, description="Timestamp when message was received")


class EmailURLResponse(BaseModel):
    """Extracted URL analysis metadata from an ingested email."""
    id: int
    url: str
    visible_text: Optional[str] = None
    domain_mismatch: bool = False
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EmailAttachmentResponse(BaseModel):
    """Extracted attachment static analysis metadata from an ingested email."""
    id: int
    filename: str
    content_type: Optional[str] = None
    size_bytes: int = 0
    sha256_hash: Optional[str] = None
    is_suspicious: bool = False
    has_macro: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestedEmailResponse(BaseModel):
    """Result and metadata of an ingested and analyzed mailbox email."""
    id: int
    provider: str
    provider_message_id: str
    sender_email: str
    sender_name: Optional[str] = None
    recipient_email: Optional[str] = None
    subject: Optional[str] = None
    received_at: datetime
    status: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    classification: Optional[str] = None
    summary: Optional[str] = None
    threat_signals: Optional[List[Dict[str, Any]]] = None
    evidence_classes: Optional[List[str]] = None
    correlation_patterns: Optional[List[Dict[str, Any]]] = None
    url_count: int = 0
    attachment_count: int = 0
    has_quishing: bool = False
    analysis_id: Optional[int] = None
    urls: Optional[List[EmailURLResponse]] = None
    attachments: Optional[List[EmailAttachmentResponse]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestedEmailListResponse(BaseModel):
    """Paginated list of ingested emails."""
    total: int
    count: int
    items: List[IngestedEmailResponse]


class MailSecurityStats(BaseModel):
    """Aggregate statistics for Mail Security monitoring."""
    total_scanned: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    phishing_count: int = 0
    quishing_count: int = 0
    threats_detected: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    safe_count: int = 0
    connected_mailboxes: int = 0
    last_sync: Optional[datetime] = None


class MailSecuritySettings(BaseModel):
    """Server-side persisted settings for automated mail security scanning."""
    scan_enabled: bool = True
    attachment_scan_enabled: bool = True
    qr_scan_enabled: bool = True
    ai_analysis_enabled: bool = True
    retention_days: int = Field(90, ge=1, le=3650)

    model_config = ConfigDict(from_attributes=True)
