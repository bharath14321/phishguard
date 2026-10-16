"""Comprehensive regression test suite for Email Analysis Hardening and Threat Intelligence & ML Integration.

Tests cover:
1. Local Threat Intelligence aggregation contracts (MATCH, NO_MATCH, NOT_EVALUATED, ERROR).
2. Attachment extraction and embedded URL parsing (Fixture 08).
3. Tracking pixel and remote HTML resource detection (Fixture 09).
4. Full complex phishing case with headers, URLs, attachments, and tracking pixel (Fixture 12).
5. Secure TLS certificate analysis and SSRF prevention.
6. AI Analyst context grounding and security question responses.
"""

import os
import pytest

from src.features.local_ti import aggregate_local_ti_results
from src.features.tls_analyzer import analyze_tls_certificate
from src.features.tracking_pixel_detector import detect_tracking_pixels
from src.analysis.unified_analyzer import analyze_email
from src.analysis.security_chat import FallbackRuleBasedProvider, process_chat_message


# ---------------------------------------------------------------------------
# 1. Local TI Aggregation Contract Tests
# ---------------------------------------------------------------------------

def test_aggregate_local_ti_match():
    """Verify that a single MATCH promotes the aggregated result to MATCH."""
    evals = [
        {"status": "NO_MATCH", "found": False, "evaluated_count": 91190},
        {
            "status": "MATCH",
            "found": True,
            "threat_type": "phishing",
            "source": "PhishTank",
            "matched_indicator": "https://phish.example.com/",
            "evaluated_count": 91190,
        },
    ]
    res = aggregate_local_ti_results(evals, evaluated_count=91190)
    assert res["status"] == "MATCH"
    assert res["found"] is True
    assert res["source"] == "PhishTank"
    assert res["threat_type"] == "phishing"
    assert len(res["matches"]) == 1


def test_aggregate_local_ti_no_match():
    """Verify clean evaluation results in NO_MATCH."""
    evals = [
        {"status": "NO_MATCH", "found": False, "evaluated_count": 91190},
        {"status": "NO_MATCH", "found": False, "evaluated_count": 91190},
    ]
    res = aggregate_local_ti_results(evals, evaluated_count=91190)
    assert res["status"] == "NO_MATCH"
    assert res["found"] is False
    assert res["evaluated_count"] == 91190


def test_aggregate_local_ti_not_evaluated():
    """Verify empty indicator sets yield NOT_EVALUATED rather than false clean NO_MATCH."""
    res = aggregate_local_ti_results([], evaluated_count=0)
    assert res["status"] == "NOT_EVALUATED"
    assert res["found"] is False


def test_aggregate_local_ti_error():
    """Verify error propagation without claiming clean."""
    res = aggregate_local_ti_results([], evaluated_count=0, error="Database lock failure")
    assert res["status"] == "ERROR"
    assert res["found"] is False
    assert "Database lock failure" in res["error"]


# ---------------------------------------------------------------------------
# 2. Tracking Pixel Detection Tests (HTML vs MIME)
# ---------------------------------------------------------------------------

def test_tracking_pixel_detector_finds_1x1_pixel():
    """Detects 1x1 hidden image while ignoring MIME image counts."""
    html = """
    <html><body>
      <p>Hello world</p>
      <img src="https://tracking.beacon.io/pixel.gif" width="1" height="1" alt="" />
    </body></html>
    """
    res = detect_tracking_pixels(html, mime_image_count=2)
    assert res["detected"] is True
    assert res["status"] in ("DETECTED", "SUSPECTED")
    assert res["html_image_resources_count"] == 1
    assert res["mime_image_count"] == 2
    assert res["tracking_pixels_count"] == 1
    assert "https://tracking.beacon.io/pixel.gif" in res["suspected_tracking_pixels"][0]["src"]


def test_tracking_pixel_detector_clean_html():
    """Standard decorative image is not marked as a tracking pixel."""
    html = """
    <html><body>
      <p>Company header</p>
      <img src="https://example.com/logo.png" width="400" height="100" alt="Company Logo" />
    </body></html>
    """
    res = detect_tracking_pixels(html, mime_image_count=0)
    assert res["detected"] is False
    assert res["status"] == "NOT_DETECTED"
    assert res["html_image_resources_count"] == 1
    assert res["tracking_pixels_count"] == 0


# ---------------------------------------------------------------------------
# 3. TLS Certificate Analysis Tests
# ---------------------------------------------------------------------------

def test_tls_analyzer_plain_http():
    """Plain HTTP is flagged without attempting TLS handshake."""
    res = analyze_tls_certificate("http://example.com/login")
    assert res["is_https"] is False
    assert res["is_valid"] is False
    assert res["status"] in ("NOT_APPLICABLE", "NOT_APPLICABLE_HTTP")
    assert "Plain HTTP" in res["security_interpretation"] or "HTTP" in res["message"]


def test_tls_analyzer_blocks_ssrf_private_ip():
    """SSRF private/loopback targets are blocked before any socket creation."""
    res = analyze_tls_certificate("https://127.0.0.1:8443/secret")
    assert res["is_valid"] is False
    assert res["status"] in ("BLOCKED", "BLOCKED_SSRF")


# ---------------------------------------------------------------------------
# 4. Email Fixture 08: Attachment with Embedded URL
# ---------------------------------------------------------------------------

def test_fixture_08_attachment_with_url():
    """Test case 08: invoice.txt extracted with non-zero size, MIME, and embedded URL routed."""
    fixture_path = os.path.join(
        os.path.dirname(__file__), "fixtures", "validation", "emails", "08_attachment_with_url.eml"
    )

    res = analyze_email(fixture_path, user_id=1)

    # Verify attachment was discovered
    attachments = res.get("details", {}).get("attachments", [])
    assert len(attachments) >= 1
    att = attachments[0]
    assert att["filename"] == "invoice.txt"
    assert att["size_bytes"] > 0
    assert att["mime_type"] in ("text/plain", "plain") or att["extension"] == ".txt"

    # Verify embedded URL was extracted and analyzed
    embedded_urls = att.get("embedded_urls", [])
    assert any("https://example.com/invoice/verify" in u for u in embedded_urls)

    # Verify URL analyses includes the attachment URL
    all_urls = res.get("details", {}).get("url_analyses", [])
    assert any("https://example.com/invoice/verify" in u["url"] for u in all_urls)


# ---------------------------------------------------------------------------
# 5. Email Fixture 09: Tracking Pixel in HTML
# ---------------------------------------------------------------------------

def test_fixture_09_tracking_pixel_html():
    """Test case 09: HTML remote image 1x1 tracking pixel detected."""
    fixture_path = os.path.join(
        os.path.dirname(__file__), "fixtures", "validation", "emails", "09_tracking_pixel_html.eml"
    )

    res = analyze_email(fixture_path, user_id=1)

    details = res.get("details", {})
    tracking = details.get("tracking_analysis", {})
    assert tracking.get("detected") is True
    assert tracking.get("tracking_pixels_count", 0) >= 1

    # Verify signal generated
    signals = res.get("signals", [])
    sig_names = [s.get("name") if isinstance(s, dict) else str(s) for s in signals]
    assert any("Tracking Pixel" in name for name in sig_names)


# ---------------------------------------------------------------------------
# 6. Email Fixture 12: Full Phishing Case (Auth Fail, TI URL, Attachment, Pixel)
# ---------------------------------------------------------------------------

def test_fixture_12_full_phishing_case():
    """Test case 12: Comprehensive multi-vector attack."""
    fixture_path = os.path.join(
        os.path.dirname(__file__), "fixtures", "validation", "emails", "12_full_phishing_case.eml"
    )

    res = analyze_email(fixture_path, user_id=1)

    # High risk score
    assert res["risk_score"] >= 60
    assert res["risk_level"] in ("HIGH", "CRITICAL")

    # Authentication failure
    auth = res.get("details", {}).get("email_authentication", {})
    spf_status = str(auth.get("status", {}).get("spf", "")).upper()
    dkim_status = str(auth.get("status", {}).get("dkim", "")).upper()
    assert spf_status == "FAIL" or dkim_status == "FAIL"

    # Local TI match (PhishTank known URL)
    local_ti = res.get("details", {}).get("local_ti", {})
    assert local_ti.get("found") is True or local_ti.get("status") == "MATCH"

    # Attachment extracted
    attachments = res.get("details", {}).get("attachments", [])
    assert len(attachments) >= 1
    assert attachments[0]["filename"] == "security_audit.txt"

    # Tracking pixel detected
    tracking = res.get("details", {}).get("tracking_analysis", {})
    assert tracking.get("detected") is True


# ---------------------------------------------------------------------------
# 7. AI Security Analyst Fallback & Prompt Grounding Tests
# ---------------------------------------------------------------------------

def test_ai_analyst_answers_email_specific_questions():
    """Verify rule-based fallback answers specific forensic questions about emails."""
    provider = FallbackRuleBasedProvider()

    context = {
        "artifact_type": "email",
        "risk_score": 85,
        "risk_level": "CRITICAL",
        "url_analyses": [
            {
                "url": "https://login-outlook365.yzz.me/",
                "local_ti": {"found": True, "source": "PhishTank"},
                "tls": {"is_valid": True, "status": "VALID"},
            }
        ],
        "attachments": [
            {
                "filename": "invoice.txt",
                "size_bytes": 176,
                "mime_type": "text/plain",
                "embedded_urls": ["https://example.com/invoice/verify"],
            }
        ],
        "tracking_info": {
            "detected": True,
            "tracking_pixels_count": 1,
            "suspected_tracking_pixels": [{"src": "https://example.com/pixel.gif"}],
        },
        "signals": [
            {"name": "Local Threat Feed Match", "reason": "PhishTank match", "weight": 40}
        ],
    }

    # Test URL query
    ans_urls = provider.generate_response("", "What URLs were found?", context)
    assert "login-outlook365.yzz.me" in ans_urls

    # Test Local TI query
    ans_ti = provider.generate_response("", "Which URL caused the local threat-intelligence match?", context)
    assert "PhishTank" in ans_ti or "login-outlook365.yzz.me" in ans_ti

    # Test TLS query
    ans_tls = provider.generate_response("", "Did any URL have a valid TLS certificate?", context)
    assert "TLS" in ans_tls and "valid" in ans_tls.lower()

    # Test Tracking pixel query
    ans_track = provider.generate_response("", "Was a tracking pixel detected?", context)
    assert "tracking pixel" in ans_track.lower()
    assert "https://example.com/pixel.gif" in ans_track

    # Test Attachment query
    ans_att = provider.generate_response("", "Was the attachment analyzed?", context)
    assert "invoice.txt" in ans_att
