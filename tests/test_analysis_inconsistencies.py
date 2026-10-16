"""
Regression test suite for email, URL, QR, and hash analysis consistency.

Covers:
- Issue 1: Benign email baseline, tracking pixel accuracy, risk score calibration,
           and evidence sufficiency bounds.
- Issue 2: Attachment macro inspection differentiating NOT_APPLICABLE, NO_MACROS_FOUND,
           MACROS_DETECTED, and SHA-256 calculation.
- Issue 3: URL & QR analysis alignment with supervised ML and threat intelligence.
- Issue 4: QR code payload routing to central URL pipeline with webpage DOM telemetry.
- Issue 5: File & hash analysis with Local TI precedence and policy-driven VirusTotal querying.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from src.analysis.unified_analyzer import (
    analyze_email,
    analyze_url,
    analyze_qr,
    analyze_file,
    analyze_hash,
)
from src.features.attachment_analyzer import (
    analyze_attachment,
    inspect_macro_status,
)
from src.features.tracking_pixel_detector import detect_tracking_pixels
from src.analysis.evidence_sufficiency import compute_evidence_sufficiency


# ============================================================================
# ISSUE 1: BENIGN EMAIL BASELINE, TRACKING PIXELS & RISK CALIBRATION
# ============================================================================

def test_benign_email_baseline():
    """Verify that a legitimate benign email with passing SPF/DKIM/DMARC and standard
    visible images receives a LOW risk verdict without false phishing signals.
    """
    eml_path = "tests/fixtures/validation/emails/01_benign_baseline.eml"
    assert os.path.exists(eml_path), f"Missing fixture: {eml_path}"

    result = analyze_email(eml_path, user_id=1)

    # 1. Structure and status
    assert result["artifact_type"] == "email"
    assert "risk" in result
    score = result["risk"]["score"]
    level = result["risk"]["level"]

    # 2. Score must be in the clean/low range (score <= 25)
    assert score <= 25.0, f"Expected low risk score for benign email, got {score}"
    assert level in ("LOW", "NONE"), f"Expected LOW/NONE risk level, got {level}"

    # 3. Visible images (width=240, height=60) should not be flagged as tracking pixels
    tracking = result["details"].get("tracking_analysis", {})
    assert tracking.get("tracking_pixels_count", 0) == 0, (
        f"Normal visible logo was falsely classified as a tracking pixel: {tracking}"
    )

    # 4. Evidence sufficiency should not be artificially inflated to 100% without authoritative feeds
    suff = result.get("evidence_sufficiency") or {}
    if suff:
        assert suff.get("score", 0.0) <= 75.0, (
            f"Evidence sufficiency should be capped at <= 75.0% for heuristic-only email scans, got {suff.get('score')}"
        )


def test_tracking_pixel_detector_visible_images_excluded():
    """Verify that images with explicit display dimensions (> 1x1) are not suspected
    as hidden tracking pixels, while 1x1 or hidden web beacons are accurately identified.
    """
    html_with_normal_image = """
    <html>
      <body>
        <h1>Newsletter</h1>
        <img src="https://example.com/banner.png" width="600" height="150" alt="Banner" />
        <img src="https://example.com/logo.jpg" style="width: 200px; height: 50px;" alt="Logo" />
      </body>
    </html>
    """
    res_normal = detect_tracking_pixels(html_with_normal_image, mime_image_count=0)
    assert res_normal["detected"] is False
    assert res_normal["tracking_pixels_count"] == 0

    html_with_beacon = """
    <html>
      <body>
        <h1>Newsletter</h1>
        <img src="https://tracking.example/pixel.gif?uid=12345" width="1" height="1" alt="" />
      </body>
    </html>
    """
    res_beacon = detect_tracking_pixels(html_with_beacon, mime_image_count=0)
    assert res_beacon["detected"] is True
    assert res_beacon["tracking_pixels_count"] == 1
    assert res_beacon["suspected_tracking_pixels"][0]["is_suspected"] is True


# ============================================================================
# ISSUE 2: ATTACHMENT MACRO INSPECTION & HASHING
# ============================================================================

def test_plain_text_attachment_macro_status():
    """Verify that plain-text files return macro_status='NOT_APPLICABLE' and
    appropriate macro_details rather than claiming 'Clean (No Macros)'.
    """
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w", encoding="utf-8") as f:
        f.write("Line 1: Plain text audit log.\nLine 2: Safe configuration parameters.\n")
        txt_path = f.name

    try:
        # Test inspect_macro_status directly
        status, details, has_macros = inspect_macro_status(txt_path)
        assert status == "NOT_APPLICABLE"
        assert "plain-text" in details.lower()
        assert has_macros is False

        # Test analyze_attachment wrapper
        att_res = analyze_attachment(txt_path)
        assert att_res["macro_status"] == "NOT_APPLICABLE"
        assert att_res["has_vba_macros"] is False
        assert len(att_res["sha256"]) == 64
        assert att_res["sha256"] == att_res["sha256"].lower()
    finally:
        if os.path.exists(txt_path):
            os.unlink(txt_path)


def test_email_with_plain_text_attachment_fixture():
    """Verify that an email with a safe_sample.txt attachment records macro_status
    as NOT_APPLICABLE in the attachments list.
    """
    eml_path = "tests/fixtures/validation/emails/04_attachment_and_urls.eml"
    assert os.path.exists(eml_path), f"Missing fixture: {eml_path}"

    result = analyze_email(eml_path, user_id=1)
    attachments = result["details"].get("attachments", [])
    assert len(attachments) >= 1

    sample_att = attachments[0]
    assert sample_att["filename"] == "safe_sample.txt"
    assert sample_att["macro_status"] == "NOT_APPLICABLE"
    assert "plain-text" in sample_att["macro_details"].lower()
    assert sample_att["has_vba_macros"] is False
    assert len(sample_att["sha256"]) == 64


# ============================================================================
# ISSUE 3: URL & QR ANALYSIS ALIGNMENT WITH ML AND THREAT INTEL
# ============================================================================

def test_analyze_url_response_contract():
    """Verify that analyze_url returns top-level ml, local_ti, virustotal, and url,
    and that ML assessment contributes to the risk score before explanation generation.
    """
    target_url = "https://safe-domain.internal/welcome"
    with patch("src.analysis.unified_analyzer.get_url_reputation") as mock_vt:
        mock_vt.return_value = {"malicious": 0, "total": 70, "status": "SUCCESS"}
        res = analyze_url(target_url, user_id=1)

    # Top-level fields
    assert "ml" in res
    assert "local_ti" in res
    assert "virustotal" in res
    assert res["url"] == target_url
    assert "risk_score" in res
    assert "risk_level" in res
    assert "risk" in res
    assert res["risk_score"] == res["risk"]["score"]
    assert res["risk_level"] == res["risk"]["level"]


def test_analyze_qr_url_payload_top_level_propagation():
    """Verify that analyze_qr for a URL barcode propagates the risk score, risk level,
    ml, local_ti, and virustotal from the child URL analysis to the top level.
    """
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        qr_file = f.name

    try:
        mock_qr_res = {
            "success": True,
            "decode_status": "SUCCESS",
            "decoded_data": "https://company-portal.internal/login",
            "decoded_payload": "https://company-portal.internal/login",
            "payload_type": "URL",
            "is_url": True,
        }

        with patch("src.analysis.unified_analyzer.qr_analyzer", return_value=mock_qr_res):
            with patch("src.analysis.unified_analyzer.analyze_url") as mock_url_fn:
                mock_url_fn.return_value = {
                    "analysis_id": None,
                    "artifact_type": "url",
                    "details": {
                        "url": "https://company-portal.internal/login",
                        "ml": {"model_available": True, "probability": 0.15},
                        "local_ti": {"found": False, "status": "CLEAN"},
                        "virustotal": {"status": "SUCCESS", "is_clean": True, "malicious": 0, "total": 70},
                        "webpage_analysis": {"form_count": 1, "script_count": 3, "title": "Login Portal"},
                    },
                    "risk": {"score": 10.0, "level": "LOW"},
                    "risk_score": 10.0,
                    "risk_level": "LOW",
                    "summary": "Low-risk scan completed.",
                    "explanation": {"summary": "Low-risk scan completed.", "key_reasons": []},
                    "signals": [],
                    "errors": [],
                    "ml": {"model_available": True, "probability": 0.15},
                    "local_ti": {"found": False, "status": "CLEAN"},
                    "virustotal": {"status": "SUCCESS", "is_clean": True, "malicious": 0, "total": 70},
                    "url": "https://company-portal.internal/login",
                }

                res = analyze_qr(qr_file, user_id=1)

                assert res["artifact_type"] == "qr"
                assert res["risk_score"] == 10.0
                assert res["risk_level"] == "LOW"
                assert res["risk"]["score"] == 10.0
                assert "ml" in res
                assert res["ml"]["probability"] == 0.15
                assert "local_ti" in res
                assert "virustotal" in res
                assert res["details"]["qr"]["decode_status"] == "SUCCESS"
                assert res["details"]["qr"]["is_url"] is True
    finally:
        if os.path.exists(qr_file):
            os.unlink(qr_file)


# ============================================================================
# ISSUE 4: QR CODE WEBPAGE / DOM TELEMETRY
# ============================================================================

def test_qr_webpage_dom_telemetry_passthrough():
    """Verify that when a QR code contains a URL, the downstream webpage findings
    (title, forms, form_count, script_count) are preserved in details.
    """
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        qr_file = f.name

    try:
        mock_qr_res = {
            "success": True,
            "decode_status": "SUCCESS",
            "decoded_data": "https://auth.sample-service.internal/",
            "decoded_payload": "https://auth.sample-service.internal/",
            "payload_type": "URL",
            "is_url": True,
        }

        webpage_telemetry = {
            "title": "Corporate Single Sign-On",
            "form_count": 2,
            "password_field_count": 1,
            "has_password_field": True,
            "has_login_form": True,
            "has_cross_domain_submission": False,
            "script_count": 5,
            "link_count": 12,
            "forms": [
                {"action": "/auth/login", "method": "post", "has_password": True, "cross_domain": False}
            ],
        }

        with patch("src.analysis.unified_analyzer.qr_analyzer", return_value=mock_qr_res):
            with patch("src.analysis.unified_analyzer.analyze_url") as mock_url_fn:
                mock_url_fn.return_value = {
                    "artifact_type": "url",
                    "details": {
                        "url": "https://auth.sample-service.internal/",
                        "webpage_analysis": webpage_telemetry,
                        "ml": {"model_available": True, "probability": 0.05},
                        "local_ti": {"found": False},
                        "virustotal": {"status": "SUCCESS", "is_clean": True},
                    },
                    "risk": {"score": 10.0, "level": "LOW"},
                    "risk_score": 10.0,
                    "risk_level": "LOW",
                    "explanation": {"summary": "Safe authentication page.", "key_reasons": []},
                    "signals": [],
                    "errors": [],
                    "ml": {"model_available": True, "probability": 0.05},
                    "local_ti": {"found": False},
                    "virustotal": {"status": "SUCCESS", "is_clean": True},
                    "url": "https://auth.sample-service.internal/",
                }

                res = analyze_qr(qr_file, user_id=1)
                wp = res["details"].get("webpage_analysis") or {}

                assert wp.get("title") == "Corporate Single Sign-On"
                assert wp.get("form_count") == 2
                assert wp.get("script_count") == 5
                assert len(wp.get("forms", [])) == 1
                assert wp["forms"][0]["action"] == "/auth/login"
    finally:
        if os.path.exists(qr_file):
            os.unlink(qr_file)


# ============================================================================
# ISSUE 5: HASH ANALYSIS, LOCAL TI FIRST & POLICY-BASED VT SKIPPING
# ============================================================================

def test_hash_analysis_local_match_skips_virustotal_by_policy():
    """Verify that when a hash matches Local Threat Intelligence, VirusTotal is skipped
    by policy with status='NOT_QUERIED' and policy_reason='SKIPPED_BY_POLICY_LOCAL_MATCH'.
    """
    known_malicious_hash = "a" * 64

    mock_local_match = {
        "found": True,
        "source": "MalwareBazaar",
        "threat_type": "malware",
        "confidence": 95,
        "matched_indicator": known_malicious_hash,
    }

    with patch("src.analysis.unified_analyzer.query_local_threat_intelligence", return_value=mock_local_match):
        with patch("src.analysis.unified_analyzer.get_hash_reputation") as mock_vt_call:
            res = analyze_hash(known_malicious_hash, user_id=1)

            # VT should NEVER be queried when local TI establishes a confirmed match
            mock_vt_call.assert_not_called()

            assert res["risk_score"] >= 85.0
            assert res["risk_level"] in ("HIGH", "CRITICAL")
            assert res["local_ti"]["found"] is True
            assert res["local_ti"]["source"] == "MalwareBazaar"

            vt = res["virustotal"]
            assert vt["status"] == "NOT_QUERIED"
            assert "skipped by policy" in vt["message"].lower()


def test_file_analysis_computes_sha256_and_checks_local_first():
    """Verify that analyze_file computes SHA-256 strictly from uploaded bytes and
    consults Local Threat Intelligence before any external lookup.
    """
    file_bytes = b"Suspicious binary content for test."
    import hashlib
    expected_hash = hashlib.sha256(file_bytes).hexdigest().lower()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(file_bytes)
        bin_path = f.name

    try:
        mock_local_match = {
            "found": True,
            "source": "LocalThreatFeed",
            "threat_type": "trojan",
            "matched_indicator": expected_hash,
        }

        with patch("src.analysis.unified_analyzer.query_local_threat_intelligence", return_value=mock_local_match):
            with patch("src.analysis.unified_analyzer.get_hash_reputation") as mock_vt_call:
                res = analyze_file(bin_path, user_id=1)

                mock_vt_call.assert_not_called()
                assert res["details"]["sha256"] == expected_hash
                assert res["risk_score"] >= 85.0
                assert res["virustotal"]["status"] == "NOT_QUERIED"
                assert "skipped by policy" in res["virustotal"]["message"].lower()
    finally:
        if os.path.exists(bin_path):
            os.unlink(bin_path)


def test_hash_analysis_unconfigured_virustotal_returns_unavailable():
    """Verify that when VirusTotal API key is not configured and Local TI has no match,
    VirusTotal status is UNAVAILABLE and not claimed as clean.
    """
    unobserved_hash = "b" * 64
    mock_local_miss = {"found": False, "status": "CLEAN"}

    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=False):
        with patch("src.analysis.unified_analyzer.query_local_threat_intelligence", return_value=mock_local_miss):
            res = analyze_hash(unobserved_hash, user_id=1)

            vt = res["virustotal"]
            assert vt["status"] == "UNAVAILABLE"
            assert vt.get("is_clean") is False
            assert "not configured" in vt.get("message", "").lower()
