"""
Tests for Email Embedded QR Code Extraction and Pipeline Integration
"""

import io
import os
import glob
import tempfile
from email.message import EmailMessage
from unittest.mock import patch, MagicMock

import pytest

from src.features.email_qr_extractor import (
    extract_candidate_images_from_email,
    extract_qr_from_email,
)
from src.analysis.unified_analyzer import analyze_email


def _create_mock_eml(
    subject: str = "Test Email",
    body: str = "Here is the email text",
    images: list = None,
) -> str:
    """Helper to create a temporary .eml file on disk with optional image MIME parts."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg.set_content(body)

    if images:
        for idx, img in enumerate(images):
            img_data = img.get("data", b"fake_image_bytes")
            subtype = img.get("subtype", "png")
            filename = img.get("filename", f"image_{idx}.{subtype}")
            msg.add_attachment(
                img_data,
                maintype="image",
                subtype=subtype,
                filename=filename,
            )

    tmp = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    tmp.write(msg.as_bytes())
    tmp.close()
    return tmp.name


class TestEmailQrExtraction:

    def test_email_with_no_image_parts(self):
        """1. Email with no image parts returns empty QR findings."""
        eml_path = _create_mock_eml(body="Plain text with no images.")
        try:
            res = extract_qr_from_email(eml_path)
            assert res["detected"] is False
            assert res["image_count"] == 0
            assert res["qr_count"] == 0
            assert len(res["findings"]) == 0
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_email_with_normal_logo_image(self, mock_analyze_qr):
        """2. Email with normal logo image (no QR) records image inspection without QR detection."""
        mock_analyze_qr.return_value = {
            "success": False,
            "decoded_data": None,
            "is_url": False,
        }
        eml_path = _create_mock_eml(images=[{"data": b"logo_bytes_123", "subtype": "png", "filename": "logo.png"}])
        try:
            res = extract_qr_from_email(eml_path)
            assert res["detected"] is False
            assert res["image_count"] == 1
            assert res["qr_count"] == 0
            assert len(res["findings"]) == 0
            assert mock_analyze_qr.called
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.features.email_qr_extractor.analyze_url")
    @patch("src.features.email_qr_extractor.analyze_url_risk")
    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_email_with_qr_image_http_url(self, mock_analyze_qr, mock_url_risk, mock_analyze_url):
        """3. Email with QR image containing HTTP URL invokes URL pipeline."""
        mock_analyze_qr.return_value = {
            "success": True,
            "decoded_data": "http://suspicious-qr-login.com/session",
            "is_url": True,
        }
        mock_analyze_url.return_value = {
            "url": "http://suspicious-qr-login.com/session",
            "url_features": {"has_ip_address": False},
        }
        mock_url_risk.return_value = MagicMock(score=75, level="HIGH", signals=["Suspicious QR Destination"])

        eml_path = _create_mock_eml(images=[{"data": b"qr_code_image_bytes", "subtype": "png", "filename": "qr_code.png"}])
        try:
            res = extract_qr_from_email(eml_path)
            assert res["detected"] is True
            assert res["qr_count"] == 1
            finding = res["findings"][0]
            assert finding["decoded_data"] == "http://suspicious-qr-login.com/session"
            assert finding["is_url"] is True
            assert finding["url_risk"]["level"] == "HIGH"
            assert mock_analyze_url.called
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.features.email_qr_extractor.analyze_url")
    @patch("src.features.email_qr_extractor.analyze_url_risk")
    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_email_with_qr_image_https_url(self, mock_analyze_qr, mock_url_risk, mock_analyze_url):
        """4. Email with QR image containing HTTPS URL invokes URL pipeline."""
        mock_analyze_qr.return_value = {
            "success": True,
            "decoded_data": "https://secure-portal.target.com/auth",
            "is_url": True,
        }
        mock_analyze_url.return_value = {"url": "https://secure-portal.target.com/auth"}
        mock_url_risk.return_value = MagicMock(score=10, level="LOW", signals=[])

        eml_path = _create_mock_eml(images=[{"data": b"https_qr_bytes", "subtype": "jpeg", "filename": "auth_qr.jpg"}])
        try:
            res = extract_qr_from_email(eml_path)
            assert res["detected"] is True
            assert res["findings"][0]["is_url"] is True
            assert res["findings"][0]["decoded_data"] == "https://secure-portal.target.com/auth"
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.features.email_qr_extractor.analyze_url")
    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_email_with_qr_non_url_text(self, mock_analyze_qr, mock_analyze_url):
        """5. Email with QR image containing non-URL text does NOT invoke URL analyzer."""
        mock_analyze_qr.return_value = {
            "success": True,
            "decoded_data": "WIFI:S:OfficeNetwork;T:WPA;P:SecretPassword123;;",
            "is_url": False,
        }
        eml_path = _create_mock_eml(images=[{"data": b"wifi_qr_bytes", "subtype": "png", "filename": "wifi.png"}])
        try:
            res = extract_qr_from_email(eml_path)
            assert res["detected"] is True
            assert res["qr_count"] == 1
            assert res["findings"][0]["is_url"] is False
            assert "WIFI:S:OfficeNetwork" in res["findings"][0]["decoded_data"]
            # Verify URL analyzer was NOT invoked
            assert not mock_analyze_url.called
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_multiple_qr_images_checked(self, mock_analyze_qr):
        """6. Multiple QR images in email are all processed."""
        def mock_qr_side_effect(path):
            if "img1" in path or "0" in path:
                return {"success": True, "decoded_data": "https://site1.com", "is_url": True}
            return {"success": True, "decoded_data": "https://site2.com", "is_url": True}

        mock_analyze_qr.side_effect = mock_qr_side_effect

        eml_path = _create_mock_eml(images=[
            {"data": b"unique_qr_bytes_1", "subtype": "png", "filename": "img1.png"},
            {"data": b"unique_qr_bytes_2", "subtype": "png", "filename": "img2.png"},
        ])
        try:
            with patch("src.features.email_qr_extractor.analyze_url") as mock_url:
                mock_url.return_value = {}
                with patch("src.features.email_qr_extractor.analyze_url_risk") as mock_risk:
                    mock_risk.return_value = MagicMock(score=0, level="LOW", signals=[])
                    res = extract_qr_from_email(eml_path)
                    assert res["image_count"] == 2
                    assert res["qr_count"] == 2
                    assert len(res["findings"]) == 2
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.features.email_qr_extractor.analyze_url")
    @patch("src.features.email_qr_extractor.analyze_url_risk")
    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_duplicate_decoded_urls_cached(self, mock_analyze_qr, mock_url_risk, mock_analyze_url):
        """7. Duplicate decoded URLs across distinct images reuse cached URL analysis."""
        mock_analyze_qr.return_value = {
            "success": True,
            "decoded_data": "https://repeated-target.com/page",
            "is_url": True,
        }
        mock_analyze_url.return_value = {"url": "https://repeated-target.com/page"}
        mock_url_risk.return_value = MagicMock(score=50, level="MEDIUM", signals=[])

        eml_path = _create_mock_eml(images=[
            {"data": b"image_payload_A", "subtype": "png", "filename": "qrA.png"},
            {"data": b"image_payload_B", "subtype": "png", "filename": "qrB.png"},
        ])
        try:
            res = extract_qr_from_email(eml_path)
            assert res["qr_count"] == 2
            # URL analyzer should only be invoked once due to caching
            assert mock_analyze_url.call_count == 1
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    def test_oversized_image_part_skipped(self):
        """8. Oversized image part (> max_bytes) is safely skipped."""
        oversized_bytes = b"X" * 2000
        candidates = extract_candidate_images_from_email(
            _create_mock_eml(images=[{"data": oversized_bytes, "subtype": "png"}]),
            max_bytes=1000,  # lower threshold for test
        )
        assert len(candidates) == 0

    @patch("src.features.email_qr_extractor.analyze_qr_code")
    def test_temporary_files_cleaned_up(self, mock_analyze_qr):
        """9. Temporary files created during QR decoding are guaranteed to be unlinked."""
        mock_analyze_qr.return_value = {"success": False, "decoded_data": None, "is_url": False}

        eml_path = _create_mock_eml(images=[{"data": b"cleanup_test_bytes", "subtype": "png"}])
        try:
            temp_dir = tempfile.gettempdir()
            before_files = set(glob.glob(os.path.join(temp_dir, "phishguard_qr_email_*")))
            extract_qr_from_email(eml_path)
            after_files = set(glob.glob(os.path.join(temp_dir, "phishguard_qr_email_*")))
            # No new leftover temp files matching our prefix
            new_leftovers = after_files - before_files
            assert len(new_leftovers) == 0
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)

    @patch("src.analysis.unified_analyzer.extract_qr_from_email")
    def test_unified_analyzer_email_integration(self, mock_extract_qr):
        """10. Unified analyzer email pipeline integrates QR findings into details and risk."""
        mock_extract_qr.return_value = {
            "detected": True,
            "image_count": 1,
            "qr_count": 1,
            "findings": [
                {
                    "source_part": "login_qr.png",
                    "decoded_data": "https://phish-login.com",
                    "is_url": True,
                    "url_analysis": {"url": "https://phish-login.com"},
                    "url_risk": {"score": 90, "level": "HIGH", "signals": ["Phishing domain"]},
                }
            ],
            "errors": [],
        }

        eml_path = _create_mock_eml(
            body="Check out https://normal-link.com and scan the QR below.",
            images=[{"data": b"qr_bytes", "subtype": "png", "filename": "login_qr.png"}],
        )
        try:
            res = analyze_email(eml_path, user_id=1)
            assert res["artifact_type"] == "email"
            details = res["details"]
            assert "qr_analysis" in details
            assert res["risk"]["level"] in ("HIGH", "CRITICAL")
            assert res["risk"]["score"] >= 90
            assert any("QR" in s.get("name", "") for s in res.get("signals", []))
        finally:
            if os.path.exists(eml_path):
                os.unlink(eml_path)
