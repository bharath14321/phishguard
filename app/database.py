"""
Database configuration and session management.

Supports SQLite for local development and testing, and PostgreSQL
or other relational engines via DATABASE_URL.
"""

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session

from app.config import DATABASE_URL, _BASE_DIR
from sqlalchemy import event


# Configure SQLite connection arguments if running on SQLite
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=10000")
        except Exception:
            pass
        finally:
            cursor.close()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session.
    Automatically closes the session after the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_sqlite_schema(target_engine=engine) -> None:
    """
    Ensure all expected columns exist across SQLite tables, adding any missing columns.
    Enables smooth migrations without requiring drop_all in development environments.
    """
    if not target_engine.dialect.name.startswith("sqlite"):
        return

    from sqlalchemy import text
    try:
        with target_engine.connect() as conn:
            # Check users
            res = conn.execute(text("PRAGMA table_info(users)")).fetchall()
            cols = [r[1] for r in res]
            if cols and "is_verified" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0 NOT NULL"))

            # Check mail_accounts
            res_ma = conn.execute(text("PRAGMA table_info(mail_accounts)")).fetchall()
            cols_ma = [r[1] for r in res_ma]
            if cols_ma:
                if "provider_account_id" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN provider_account_id VARCHAR(255)"))
                if "scan_enabled" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN scan_enabled BOOLEAN DEFAULT 1 NOT NULL"))
                if "attachment_scan_enabled" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN attachment_scan_enabled BOOLEAN DEFAULT 1 NOT NULL"))
                if "qr_scan_enabled" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN qr_scan_enabled BOOLEAN DEFAULT 1 NOT NULL"))
                if "ai_analysis_enabled" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN ai_analysis_enabled BOOLEAN DEFAULT 1 NOT NULL"))
                if "retention_days" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN retention_days INTEGER DEFAULT 90 NOT NULL"))
                if "token_expires_at" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN token_expires_at DATETIME"))
                if "encrypted_token" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN encrypted_token VARCHAR(1024)"))
                if "encrypted_credentials" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN encrypted_credentials TEXT"))
                if "history_id" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN history_id VARCHAR(255)"))
                if "watch_expiration" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN watch_expiration DATETIME"))
                if "last_successful_notification_at" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN last_successful_notification_at DATETIME"))
                if "last_error" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN last_error TEXT"))
                if "updated_at" not in cols_ma:
                    conn.execute(text("ALTER TABLE mail_accounts ADD COLUMN updated_at DATETIME"))

            # Check ingested_emails
            res_ie = conn.execute(text("PRAGMA table_info(ingested_emails)")).fetchall()
            cols_ie = [r[1] for r in res_ie]
            if cols_ie:
                if "raw_eml_path" not in cols_ie:
                    conn.execute(text("ALTER TABLE ingested_emails ADD COLUMN raw_eml_path VARCHAR(1024)"))
                if "updated_at" not in cols_ie:
                    conn.execute(text("ALTER TABLE ingested_emails ADD COLUMN updated_at DATETIME"))
                # Deduplicate any pre-existing legacy duplicates before applying unique constraint index
                conn.execute(text("""
                    DELETE FROM ingested_emails
                    WHERE id NOT IN (
                        SELECT MIN(id) FROM ingested_emails GROUP BY user_id, provider, provider_message_id
                    )
                """))
                conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_user_provider_msgid ON ingested_emails (user_id, provider, provider_message_id)"))

            # Check email_verification_otps
            res_evo = conn.execute(text("PRAGMA table_info(email_verification_otps)")).fetchall()
            cols_evo = [r[1] for r in res_evo]
            if cols_evo and "user_id" not in cols_evo:
                conn.execute(text("ALTER TABLE email_verification_otps ADD COLUMN user_id INTEGER"))

            # Migrate legacy users from phishing_analysis.db if present (skip for isolated test databases)
            try:
                db_url_repr = str(target_engine.url)
                is_isolated_test_db = ":memory:" in db_url_repr or "test" in db_url_repr.lower()
                if not is_isolated_test_db:
                    import sqlite3
                    legacy_db_file = (_BASE_DIR / "phishing_analysis.db").resolve()
                    if legacy_db_file.exists():
                        leg_conn = sqlite3.connect(legacy_db_file)
                        leg_cur = leg_conn.cursor()
                        # Check if users table exists in legacy db
                        leg_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                        if leg_cur.fetchone():
                            leg_cur.execute("SELECT username, email, password_hash, is_active, is_verified, created_at FROM users")
                            legacy_users = leg_cur.fetchall()
                            for u_name, u_email, u_pwd, u_act, u_ver, u_created in legacy_users:
                                norm_u_email = (u_email or "").strip().lower()
                                norm_u_name = (u_name or "").strip()
                                # Check if user or email already exists in target
                                existing = conn.execute(
                                    text("SELECT id FROM users WHERE LOWER(email) = LOWER(:em) OR LOWER(username) = LOWER(:un)"),
                                    {"em": norm_u_email, "un": norm_u_name}
                                ).fetchone()
                                if not existing:
                                    conn.execute(
                                        text("INSERT INTO users (username, email, password_hash, is_active, is_verified, created_at) VALUES (:un, :em, :pwd, :act, :ver, :created)"),
                                        {"un": norm_u_name, "em": norm_u_email, "pwd": u_pwd, "act": u_act, "ver": u_ver, "created": u_created}
                                    )
                        leg_conn.close()
            except Exception:
                pass

            conn.commit()
    except Exception:
        pass


def reconcile_stored_analyses(target_engine=engine) -> int:
    """
    Audit and reconcile legacy AnalysisResult records to enforce strict canonical
    agreement between numerical risk_score and categorical risk_level.
    Canonical thresholds:
    0-24 -> LOW
    25-49 -> MEDIUM
    50-74 -> HIGH
    75-100 -> CRITICAL
    """
    from sqlalchemy import text
    updated_count = 0
    try:
        with target_engine.connect() as conn:
            # Check if table exists
            table_check = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='analysis_results'")).fetchone()
            if not table_check:
                return 0

            # 1. Low risk: 0 <= score < 25
            r1 = conn.execute(text("UPDATE analysis_results SET risk_level = 'LOW' WHERE risk_score < 25 AND (risk_level != 'LOW' OR risk_level IS NULL)"))
            # 2. Medium risk: 25 <= score < 50
            r2 = conn.execute(text("UPDATE analysis_results SET risk_level = 'MEDIUM' WHERE risk_score >= 25 AND risk_score < 50 AND (risk_level != 'MEDIUM' OR risk_level IS NULL)"))
            # 3. High risk: 50 <= score < 75
            r3 = conn.execute(text("UPDATE analysis_results SET risk_level = 'HIGH' WHERE risk_score >= 50 AND risk_score < 75 AND (risk_level != 'HIGH' OR risk_level IS NULL)"))
            # 4. Critical risk: score >= 75
            r4 = conn.execute(text("UPDATE analysis_results SET risk_level = 'CRITICAL' WHERE risk_score >= 75 AND (risk_level != 'CRITICAL' OR risk_level IS NULL)"))

            conn.commit()
            updated_count = (r1.rowcount or 0) + (r2.rowcount or 0) + (r3.rowcount or 0) + (r4.rowcount or 0)
    except Exception:
        pass
    return updated_count


def log_database_startup_diagnostic() -> dict:
    """
    Safe startup diagnostic that inspects the active database connection.
    NEVER logs or exposes passwords, password hashes, secrets, or user credentials.
    """
    from sqlalchemy import inspect, text
    ensure_sqlite_schema(engine)
    reconcile_stored_analyses(engine)
    inspector = inspect(engine)
    has_users = inspector.has_table("users")
    user_count = 0

    if has_users:
        try:
            with engine.connect() as conn:
                res = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
                user_count = int(res or 0)
        except Exception:
            user_count = 0

    # Sanitize URL to remove credentials if non-sqlite
    url_repr = str(engine.url)
    if engine.url.password:
        url_repr = engine.url.render_as_string(hide_password=True)

    diagnostic = {
        "engine": engine.dialect.name,
        "database_url": url_repr,
        "sqlite_path": url_repr.replace("sqlite:///", "") if engine.dialect.name == "sqlite" else None,
        "users_table_exists": has_users,
        "user_count": user_count,
    }
    return diagnostic
