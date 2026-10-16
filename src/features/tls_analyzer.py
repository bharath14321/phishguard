"""
src/features/tls_analyzer.py

Secure TLS/HTTPS Certificate Intelligence Analyzer.
Performs passive, secure TLS handshake inspection and X.509 certificate validation.

Security & Integrity Guarantees:
1. Strict certificate verification using trusted CA roots (verify_mode=CERT_REQUIRED).
2. Hostname verification enabled (check_hostname=True).
3. NEVER uses ssl.CERT_NONE.
4. Enforces SSRF destination validation prior to any network socket initiation.
5. Passive inspection only: reads peer certificate metadata and connection parameters.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.features.safe_fetcher import validate_url

logger = logging.getLogger("phishguard.tls_analyzer")

# Default network timeout for TLS handshakes
TLS_SOCKET_TIMEOUT = 5.0


def _parse_cert_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse certificate dates in OpenSSL format (e.g. 'May 12 00:00:00 2024 GMT')."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            # Fallback format if needed
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def analyze_tls_certificate(
    url_or_host: str,
    port: int = 443,
    timeout: float = TLS_SOCKET_TIMEOUT,
    custom_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """
    Perform secure TLS certificate analysis for a given URL or hostname.

    Strictly enforces CA validation and hostname checking using standard Python TLS.
    Certificate validity does NOT imply domain trustworthiness.

    Parameters:
        url_or_host: Full URL (e.g. 'https://example.com/path') or hostname ('example.com').
        port: TCP port to connect to (defaults to 443).
        timeout: Socket timeout in seconds.
        custom_context: Optional SSL context for testing (e.g. mock CA bundles).

    Returns:
        Structured TLS intelligence dict containing connection status, certificate details,
        validity window, issuer, SANs, and security interpretations.
    """
    raw_input = (url_or_host or "").strip()
    if not raw_input:
        return {
            "status": "UNAVAILABLE",
            "is_https": False,
            "is_valid": False,
            "connection_successful": False,
            "message": "Empty URL or hostname provided for TLS inspection.",
            "security_interpretation": "No TLS target specified.",
        }

    # 1. Parse URL / Hostname
    if "://" in raw_input:
        parsed = urlparse(raw_input)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").strip()
        port = parsed.port or port
        if scheme == "http":
            return {
                "status": "NOT_APPLICABLE",
                "is_https": False,
                "is_valid": False,
                "connection_successful": False,
                "hostname": hostname,
                "message": "HTTPS certificate analysis not applicable because the URL uses HTTP.",
                "security_interpretation": "Insecure unencrypted HTTP transport in use. No TLS certificate presented.",
            }
        test_url = raw_input
    else:
        hostname = raw_input.split(":")[0].strip()
        test_url = f"https://{raw_input}"

    if not hostname:
        return {
            "status": "UNAVAILABLE",
            "is_https": False,
            "is_valid": False,
            "connection_successful": False,
            "message": "Missing valid hostname for TLS inspection.",
            "security_interpretation": "Hostname missing.",
        }

    # 2. Enforce SSRF Security Controls
    url_validation = validate_url(test_url)
    if not url_validation.get("safe", False):
        return {
            "status": "BLOCKED",
            "is_https": True,
            "is_valid": False,
            "connection_successful": False,
            "hostname": hostname,
            "message": "TLS analysis unavailable because network access was blocked by security policy.",
            "security_interpretation": "Destination hostname or resolved IP is forbidden by SSRF controls.",
        }

    # 3. Create strictly validated SSL Context
    # Enforces trusted roots and hostname identity check
    if custom_context is not None:
        context = custom_context
    else:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

    # 4. Perform Passive TLS Connection Handshake
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                # Parse Subject and Issuer
                subject_dict = {}
                for rdn in cert.get("subject", ()):
                    for key, val in rdn:
                        subject_dict[key] = val

                issuer_dict = {}
                for rdn in cert.get("issuer", ()):
                    for key, val in rdn:
                        issuer_dict[key] = val

                issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"
                subject_cn = subject_dict.get("commonName", "")

                # Parse Subject Alternative Names (SANs)
                sans = []
                for san_type, san_val in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        sans.append(san_val)

                # Date parsing
                not_before_dt = _parse_cert_date(cert.get("notBefore"))
                not_after_dt = _parse_cert_date(cert.get("notAfter"))
                now = datetime.now(timezone.utc)

                is_expired = False
                days_until_expiry = None
                if not_after_dt:
                    delta = not_after_dt - now
                    days_until_expiry = delta.days
                    if days_until_expiry < 0:
                        is_expired = True

                is_not_yet_valid = False
                if not_before_dt and now < not_before_dt:
                    is_not_yet_valid = True

                is_valid = not is_expired and not is_not_yet_valid

                # Check if self-signed
                is_self_signed = (subject_dict == issuer_dict and bool(subject_dict))

                return {
                    "status": "VALID" if is_valid else ("EXPIRED" if is_expired else "INVALID"),
                    "is_https": True,
                    "connection_successful": True,
                    "hostname": hostname,
                    "chain_trusted": True,
                    "hostname_matches": True,
                    "is_valid": is_valid,
                    "is_expired": is_expired,
                    "not_before": not_before_dt.isoformat() if not_before_dt else cert.get("notBefore"),
                    "not_after": not_after_dt.isoformat() if not_after_dt else cert.get("notAfter"),
                    "days_until_expiry": days_until_expiry,
                    "issuer": issuer_org,
                    "issuer_details": issuer_dict,
                    "subject": subject_cn,
                    "subject_details": subject_dict,
                    "sans": sans,
                    "tls_version": tls_version,
                    "cipher_suite": cipher_info[0] if cipher_info else None,
                    "self_signed": is_self_signed,
                    "verification_error": None,
                    "security_interpretation": "TLS is correctly configured, but certificate validity does not establish that the domain itself is trustworthy.",
                }

    except ssl.CertificateError as cert_err:
        # Hostname mismatch caught by ssl module
        return {
            "status": "HOSTNAME_MISMATCH",
            "is_https": True,
            "connection_successful": True,
            "hostname": hostname,
            "chain_trusted": False,
            "hostname_matches": False,
            "is_valid": False,
            "verification_error": str(cert_err),
            "message": f"Certificate hostname mismatch — the presented certificate does not identify this domain ({cert_err}).",
            "security_interpretation": "Certificate hostname mismatch — the presented certificate does not identify this domain.",
        }

    except ssl.SSLCertVerificationError as ssl_err:
        err_str = str(ssl_err).lower()
        if "hostname" in err_str or "doesn't match" in err_str:
            status = "HOSTNAME_MISMATCH"
            msg = "Certificate hostname mismatch — the presented certificate does not identify this domain."
        elif "has expired" in err_str or "certificate expired" in err_str:
            status = "EXPIRED"
            msg = f"Certificate has expired: {ssl_err}"
        elif "self-signed" in err_str or "self signed" in err_str:
            status = "UNTRUSTED"
            msg = "Certificate is self-signed and not trusted by standard root CAs."
        else:
            status = "UNTRUSTED"
            msg = "Certificate chain could not be validated against trusted CA roots."

        return {
            "status": status,
            "is_https": True,
            "connection_successful": True,
            "hostname": hostname,
            "chain_trusted": False,
            "hostname_matches": status != "HOSTNAME_MISMATCH",
            "is_valid": False,
            "verification_error": str(ssl_err),
            "message": msg,
            "security_interpretation": msg,
        }

    except (socket.timeout, TimeoutError):
        return {
            "status": "TIMEOUT",
            "is_https": True,
            "connection_successful": False,
            "hostname": hostname,
            "message": f"TLS handshake timed out after {timeout} seconds.",
            "security_interpretation": "Network timeout during TLS negotiation.",
        }

    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "is_https": True,
            "connection_successful": False,
            "hostname": hostname,
            "verification_error": str(exc),
            "message": f"TLS connection inspection failed: {exc}",
            "security_interpretation": "Unable to establish TLS connection or verify certificate.",
        }
