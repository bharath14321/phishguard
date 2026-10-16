"""
app/services/email_service.py

Email delivery service for PHISHGUARD.
Handles secure transactional email delivery (OTP verification, security notices)
via SMTP with TLS encryption.

Security rules:
- Credentials loaded only from server-side configuration.
- Never log SMTP passwords, API keys, or raw OTP values.
- Gracefully handle network/SMTP failures without exposing stack traces.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app import config

logger = logging.getLogger("phishguard.email")


def send_otp_email(recipient_email: str, otp: str) -> bool:
    """
    Send a 6-digit email verification OTP code to a user via SMTP over TLS.

    Implementation steps:
    1. Validate recipient email address and ensure SMTP settings are available.
    2. Compose clean plain-text and HTML MIME multipart email bodies.
    3. Connect to the configured SMTP server (e.g., smtp.gmail.com:587) and initiate TLS.
    4. Authenticate using SMTP credentials if provided.
    5. Dispatch the message and close connection.
    6. Catch and safely handle any SMTP exceptions without logging the OTP or credentials.

    Args:
        recipient_email: Destination email address.
        otp: 6-digit verification code string.

    Returns:
        bool: True if delivered successfully, False on failure.
    """
    if not recipient_email or not otp:
        return False

    smtp_host = config.SMTP_HOST
    smtp_port = config.SMTP_PORT
    smtp_user = config.SMTP_USERNAME
    smtp_pass = config.SMTP_PASSWORD
    from_email = config.SMTP_FROM_EMAIL or smtp_user or "noreply@phishguard.local"
    use_tls = config.SMTP_USE_TLS
    expire_minutes = config.OTP_EXPIRE_MINUTES

    # Create MIME container
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "PHISHGUARD — Verify your email address"
    msg["From"] = f"PHISHGUARD Security <{from_email}>"
    msg["To"] = recipient_email

    # Plain-text version
    text_content = (
        "PHISHGUARD Security\n\n"
        "Verify your email address\n\n"
        f"Your PHISHGUARD verification code is: {otp}\n\n"
        f"This code expires in {expire_minutes} minutes.\n\n"
        "If you did not create this account, you can safely ignore this email.\n"
    )

    # HTML version (styled enterprise cybersecurity template)
    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Verify your email address</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 40px 20px;">
  <div style="max-width: 520px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; padding: 36px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
    <div style="font-size: 18px; font-weight: 800; letter-spacing: -0.02em; color: #0f172a; margin-bottom: 24px; text-transform: uppercase;">
      &#x1F6E1;&#xFE0F; PHISHGUARD
    </div>
    <h2 style="font-size: 20px; font-weight: 700; color: #0f172a; margin: 0 0 12px;">Verify your email address</h2>
    <p style="font-size: 14px; line-height: 1.6; color: #475569; margin: 0 0 24px;">
      Thank you for registering for PHISHGUARD. Please use the following 6-digit verification code to complete your account setup:
    </p>
    <div style="background-color: #f1f5f9; border-radius: 8px; border: 1px solid #cbd5e1; padding: 18px; text-align: center; margin: 0 0 24px;">
      <span style="font-family: 'SF Mono', Consolas, Monaco, monospace; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #0284c7;">
        {otp}
      </span>
    </div>
    <p style="font-size: 13px; color: #64748b; line-height: 1.5; margin: 0 0 16px;">
      This verification code expires in <strong>{expire_minutes} minutes</strong>. For security reasons, never share this code with anyone.
    </p>
    <p style="font-size: 12px; color: #94a3b8; line-height: 1.4; margin: 0; border-top: 1px solid #e2e8f0; padding-top: 16px;">
      If you did not request this verification, please disregard this email.
    </p>
  </div>
</body>
</html>"""

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    # Connect and transmit
    try:
        if not smtp_host:
            logger.warning("SMTP_HOST not configured. Email skipped.")
            return False

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.ehlo()

        if use_tls:
            server.starttls()
            server.ehlo()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(from_email, [recipient_email], msg.as_string())
        server.quit()
        logger.info("OTP verification email delivered successfully.")
        return True

    except Exception as exc:
        # SECURITY: Log failure without exposing sensitive credentials or the OTP
        logger.error("Failed to send OTP verification email: %s", type(exc).__name__)
        return False
