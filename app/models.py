"""
Database models for users and security analysis results.
"""

from datetime import datetime

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    """
    Application user for authentication and isolated threat analysis history.
    """

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = Column(
        String(255),
        nullable=False
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    is_verified = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Relationships
    analyses = relationship(
        "AnalysisResult",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    mail_accounts = relationship(
        "MailAccount",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    ingested_emails = relationship(
        "IngestedEmail",
        back_populates="user",
        cascade="all, delete-orphan"
    )


class EmailVerificationOTP(Base):
    """
    Stores secure hashed OTPs and metadata for email verification.
    """

    __tablename__ = "email_verification_otps"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )

    email = Column(
        String(255),
        index=True,
        nullable=False
    )

    otp_hash = Column(
        String(255),
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    attempts_count = Column(
        Integer,
        default=0,
        nullable=False
    )

    last_sent_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )


class AnalysisResult(Base):
    """
    Stores one artifact/URL analysis result with optional user ownership.
    """

    __tablename__ = "analysis_results"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )

    url = Column(
        String(2048),
        nullable=False
    )

    risk_score = Column(
        Float,
        nullable=False
    )

    risk_level = Column(
        String(20),
        nullable=False
    )

    artifact_type = Column(
        String(50),
        nullable=False,
        default="unknown"
    )

    details = Column(
        Text,
        nullable=True
    )

    explanation = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Relationships
    user = relationship(
        "User",
        back_populates="analyses"
    )


class MailAccount(Base):
    """
    Connected mailbox provider for automated inbox threat ingestion (e.g. Gmail, Microsoft 365).
    """
    __tablename__ = "mail_accounts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    provider = Column(
        String(50),
        nullable=False
    )  # 'gmail' or 'outlook'

    provider_account_id = Column(
        String(255),
        nullable=True
    )

    account_email = Column(
        String(255),
        nullable=False
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    sync_status = Column(
        String(50),
        default="connected",
        nullable=False
    )  # 'not_connected', 'connected', 'syncing', 'error', 'disconnected'

    last_synced_at = Column(
        DateTime,
        nullable=True
    )

    token_expires_at = Column(
        DateTime,
        nullable=True
    )

    encrypted_token = Column(
        Text,
        nullable=True
    )  # Encrypted OAuth token / credential reference at rest

    encrypted_credentials = Column(
        Text,
        nullable=True
    )  # Encrypted OAuth credentials JSON at rest (Fernet)

    history_id = Column(
        String(255),
        nullable=True
    )  # Latest Gmail/provider mailbox sync history identifier

    watch_expiration = Column(
        DateTime,
        nullable=True
    )  # Expiration timestamp for provider mailbox push watch

    last_successful_notification_at = Column(
        DateTime,
        nullable=True
    )  # Last time a push notification was verified and processed

    last_error = Column(
        Text,
        nullable=True
    )  # Diagnostic error string on sync or watch failure

    scan_enabled = Column(
        Boolean,
        default=True,
        nullable=False
    )

    attachment_scan_enabled = Column(
        Boolean,
        default=True,
        nullable=False
    )

    qr_scan_enabled = Column(
        Boolean,
        default=True,
        nullable=False
    )

    ai_analysis_enabled = Column(
        Boolean,
        default=True,
        nullable=False
    )

    retention_days = Column(
        Integer,
        default=90,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="mail_accounts")
    ingested_emails = relationship("IngestedEmail", back_populates="mail_account", cascade="all, delete-orphan")


class IngestedEmail(Base):
    """
    Metadata and threat analysis result for an email ingested from a connected mailbox.
    Enforces idempotency on (user_id, provider, provider_message_id).
    """
    __tablename__ = "ingested_emails"
    __table_args__ = (
        UniqueConstraint("user_id", "provider", "provider_message_id", name="uq_user_provider_msgid"),
    )

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    mail_account_id = Column(
        Integer,
        ForeignKey("mail_accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )

    provider = Column(
        String(50),
        nullable=False
    )  # 'gmail' or 'outlook'

    provider_message_id = Column(
        String(255),
        nullable=False,
        index=True
    )

    sender_email = Column(
        String(255),
        nullable=False
    )

    sender_name = Column(
        String(255),
        nullable=True
    )

    recipient_email = Column(
        String(255),
        nullable=True
    )

    subject = Column(
        String(512),
        nullable=True
    )

    received_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    status = Column(
        String(50),
        default="pending",
        nullable=False
    )  # 'pending', 'processing', 'analyzed', 'failed'

    risk_score = Column(
        Float,
        nullable=True
    )

    risk_level = Column(
        String(20),
        nullable=True
    )  # 'SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    classification = Column(
        String(50),
        nullable=True
    )  # 'phishing', 'clean', 'suspicious', 'quishing'

    summary = Column(
        Text,
        nullable=True
    )

    threat_signals = Column(
        Text,
        nullable=True
    )  # JSON serialized

    evidence_classes = Column(
        Text,
        nullable=True
    )  # JSON serialized

    correlation_patterns = Column(
        Text,
        nullable=True
    )  # JSON serialized

    url_count = Column(
        Integer,
        default=0,
        nullable=False
    )

    attachment_count = Column(
        Integer,
        default=0,
        nullable=False
    )

    has_quishing = Column(
        Boolean,
        default=False,
        nullable=False
    )

    raw_eml_path = Column(
        String(1024),
        nullable=True
    )

    analysis_id = Column(
        Integer,
        ForeignKey("analysis_results.id", ondelete="SET NULL"),
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="ingested_emails")
    mail_account = relationship("MailAccount", back_populates="ingested_emails")
    analysis_result = relationship("AnalysisResult")
    urls = relationship("EmailURL", back_populates="ingested_email", cascade="all, delete-orphan")
    attachments = relationship("EmailAttachment", back_populates="ingested_email", cascade="all, delete-orphan")


class EmailURL(Base):
    """
    Extracted URL entity associated with an ingested mailbox email.
    """
    __tablename__ = "email_urls"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    ingested_email_id = Column(
        Integer,
        ForeignKey("ingested_emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    url = Column(
        String(2048),
        nullable=False
    )

    visible_text = Column(
        String(1024),
        nullable=True
    )

    domain_mismatch = Column(
        Boolean,
        default=False,
        nullable=False
    )

    risk_score = Column(
        Float,
        default=0.0,
        nullable=False
    )

    risk_level = Column(
        String(20),
        default="UNKNOWN",
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Relationships
    ingested_email = relationship("IngestedEmail", back_populates="urls")


class EmailAttachment(Base):
    """
    Extracted and quarantined attachment entity associated with an ingested mailbox email.
    """
    __tablename__ = "email_attachments"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    ingested_email_id = Column(
        Integer,
        ForeignKey("ingested_emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    filename = Column(
        String(255),
        nullable=False
    )

    content_type = Column(
        String(128),
        nullable=True
    )

    size_bytes = Column(
        Integer,
        default=0,
        nullable=False
    )

    sha256_hash = Column(
        String(64),
        nullable=True,
        index=True
    )

    is_suspicious = Column(
        Boolean,
        default=False,
        nullable=False
    )

    has_macro = Column(
        Boolean,
        default=False,
        nullable=False
    )

    quarantine_path = Column(
        String(1024),
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Relationships
    ingested_email = relationship("IngestedEmail", back_populates="attachments")
