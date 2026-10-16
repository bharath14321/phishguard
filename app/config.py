"""
Application configuration management.

Loads settings from environment variables with safe development defaults.
Enforces strict secret validation for production environments.
"""

import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from the project root .env file if present
_BASE_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _BASE_DIR / ".env"
if _ENV_FILE.exists():
    load_dotenv(dotenv_path=_ENV_FILE)
else:
    load_dotenv()

import shutil

# Environment mode: 'development', 'testing', or 'production'
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()

# Deterministic absolute Database configuration
_RAW_DB_URL = os.getenv("DATABASE_URL")
if not _RAW_DB_URL:
    _DATA_DIR = (_BASE_DIR / "data").resolve()
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _DEFAULT_DB_PATH = (_DATA_DIR / "phishguard.db").resolve()

    # Migrate legacy database if present and target does not exist yet
    _LEGACY_DB = (_BASE_DIR / "phishing_analysis.db").resolve()
    if _LEGACY_DB.exists() and not _DEFAULT_DB_PATH.exists():
        try:
            shutil.copy2(_LEGACY_DB, _DEFAULT_DB_PATH)
        except Exception:
            pass

    DATABASE_URL = f"sqlite:///{_DEFAULT_DB_PATH}"
else:
    # Resolve relative sqlite paths deterministically against _BASE_DIR
    if _RAW_DB_URL.startswith("sqlite:///") and not _RAW_DB_URL.startswith("sqlite:////") and ":memory:" not in _RAW_DB_URL:
        rel_path = _RAW_DB_URL.replace("sqlite:///", "")
        if rel_path.startswith("./") or rel_path.startswith("../") or not os.path.isabs(rel_path):
            abs_db_path = (_BASE_DIR / rel_path).resolve()
            abs_db_path.parent.mkdir(parents=True, exist_ok=True)
            DATABASE_URL = f"sqlite:///{abs_db_path}"
        else:
            DATABASE_URL = _RAW_DB_URL
    else:
        DATABASE_URL = _RAW_DB_URL

# Security / JWT settings
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))  # 30 days

# Secret key resolution
_SECRET_KEY = os.getenv("SECRET_KEY")

if not _SECRET_KEY:
    if ENVIRONMENT == "production":
        raise ValueError(
            "CRITICAL CONFIGURATION ERROR: 'SECRET_KEY' environment variable "
            "must be explicitly set in production mode."
        )
    # Safe development default (never used in production)
    _SECRET_KEY = "phishguard-dev-only-secret-key-not-for-production-use"

SECRET_KEY = _SECRET_KEY

# -------------------------------------------------------------------
# SMTP / EMAIL CONFIGURATION (for OTP Verification)
# -------------------------------------------------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "") or os.getenv("SMTP_USERNAME", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

# -------------------------------------------------------------------
# OTP SECURITY SETTINGS
# -------------------------------------------------------------------
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "30"))
MAX_OTP_ATTEMPTS = int(os.getenv("MAX_OTP_ATTEMPTS", "5"))

# -------------------------------------------------------------------
# GOOGLE CLOUD & GMAIL OAUTH 2.0 / PUB/SUB CONFIGURATION
# -------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:8000/api/v1/mail-security/gmail/callback"
)
GOOGLE_PROJECT_ID = os.getenv("GOOGLE_PROJECT_ID", "")
GOOGLE_PUBSUB_TOPIC = os.getenv(
    "GOOGLE_PUBSUB_TOPIC",
    f"projects/{GOOGLE_PROJECT_ID}/topics/gmail-inbox-watch" if GOOGLE_PROJECT_ID else ""
)
GOOGLE_PUBSUB_VERIFICATION_TOKEN = os.getenv("GOOGLE_PUBSUB_VERIFICATION_TOKEN", "")
GOOGLE_PUBSUB_AUDIENCE = os.getenv("GOOGLE_PUBSUB_AUDIENCE", "")
GOOGLE_PUBSUB_SERVICE_ACCOUNT = os.getenv("GOOGLE_PUBSUB_SERVICE_ACCOUNT", "")
MAILBOX_TOKEN_ENCRYPTION_KEY = os.getenv("MAILBOX_TOKEN_ENCRYPTION_KEY", "")

# Minimum required Gmail OAuth Scope for read-only inbox security ingestion
GMAIL_OAUTH_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Frontend Application Base URL
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

# Security & Development Flags
AUTH_DETAILED_LOGIN_ERRORS = os.getenv("AUTH_DETAILED_LOGIN_ERRORS", "true").lower() in ("true", "1", "yes")
ALLOW_MANUAL_MAILBOX_CONNECT = os.getenv("ALLOW_MANUAL_MAILBOX_CONNECT", "false").lower() in ("true", "1", "yes")

