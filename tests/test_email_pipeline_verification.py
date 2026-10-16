"""
tests/test_email_pipeline_verification.py

Comprehensive integration and regression tests for Phase 2:
Complete Email End-to-End Verification.
"""

from pathlib import Path
import pytest
from src.analysis.unified_analyzer import analyze_email
from src.features.email_analyzer import parse_email_file, analyze_email_headers, extract_email_body
from src.features.email_authentication import analyze_email_authentication
from src.features.email_nlp import analyze_email_subject_and_body
from src.features.email_url_extractor import analyze_email_urls
from src.features.attachment_analyzer import analyze_attachment
from src.features.attachment_url_extractor import extract_embedded_urls

TEST_EML_PATH = Path("data/raw/test_full_email.eml")


class TestEmailPipelineVerification:

    def test_test_full_email_exists(self):
        """Verify the test email file exists on disk."""
        assert TEST_EML_PATH.exists(), f"Test email file not found at {TEST_EML_PATH}"

    def test_email_parsing_and_headers(self):
        """Verify email parsing and header deception detection."""
        msg = parse_email_file(str(TEST_EML_PATH))
        headers = analyze_email_headers(msg)
        assert "Microsoft Security" in headers["from"]
        assert "support@fake-example.com" in headers["from"]
        assert headers["reply_to"] == "attacker@evil-example.com"
        assert headers["return_path"] == "bounce@evil-example.com"
        assert headers["reply_to_domain_mismatch"] is True
        assert headers["display_name_analysis"]["possible_mismatch"] is True

    def test_email_authentication_parsing(self):
        """Verify SPF, DKIM, and DMARC message authentication and published DNS separation."""
        msg = parse_email_file(str(TEST_EML_PATH))
        auth = analyze_email_authentication(msg)
        assert auth["message_authentication"]["spf"] == "fail"
        assert auth["message_authentication"]["dkim"] == "fail"
        assert auth["message_authentication"]["dmarc"] == "fail"
        assert auth["signals"]["spf_fail"] is True
        assert auth["signals"]["dkim_fail"] is True
        assert auth["signals"]["dmarc_fail"] is True
        assert "published_dns_policy" in auth
        assert auth["published_dns_policy"]["published_spf"] == "unknown"

    def test_email_nlp_social_engineering(self):
        """Verify NLP detection of urgency and credential harvesting language."""
        msg = parse_email_file(str(TEST_EML_PATH))
        headers = analyze_email_headers(msg)
        body = extract_email_body(msg)
        combined = body["plain_text"] + " " + body["html"]
        nlp = analyze_email_subject_and_body(headers["subject"], combined)
        assert nlp["urgency_count"] >= 2
        assert nlp["credential_count"] >= 1
        assert "\\burgent\\b" in nlp["matched_categories"]["urgency"]
        assert "\\bverify your account\\b" in nlp["matched_categories"]["credentials"]

    def test_email_body_url_extraction_and_mismatch(self):
        """Verify plain text and HTML URL extraction, plus visible link text mismatch."""
        msg = parse_email_file(str(TEST_EML_PATH))
        body = extract_email_body(msg)
        urls = analyze_email_urls(body["plain_text"], body["html"])
        assert len(urls) >= 2
        urls_by_src = {u["source"]: u for u in urls}
        assert "plain_text" in urls_by_src
        assert "html" in urls_by_src
        html_item = urls_by_src["html"]
        assert html_item["url"] == "https://example.com/verify"
        assert html_item["visible_text"] == "https://microsoft.com/account/verify"
        assert html_item["domain_mismatch"] is True

    def test_attachment_extraction_and_url_fanout(self):
        """Verify attachment static analysis and embedded URL fan-out to central URL pipeline."""
        res = analyze_email(str(TEST_EML_PATH), user_id=1)
        details = res["details"]
        attachments = details["attachments"]
        assert len(attachments) == 1
        att = attachments[0]
        assert att["filename"] == "invoice.txt"
        assert att["static_analysis"]["sha256"] == "256f711a6c92579258f27d826f8e9fa25b9d2cfafe3c2a9754b6ec842b69e28f"
        assert "https://example.com/invoice/verify" in att["embedded_urls"]

        # Check attachment URL reached central analyzer
        att_url_analyses = details["attachment_url_analyses"]
        assert len(att_url_analyses) == 1
        assert att_url_analyses[0]["url"] == "https://example.com/invoice/verify"
        assert att_url_analyses[0]["source"] == "attachment:invoice.txt"
        assert "url_analysis" in att_url_analyses[0]

    def test_full_email_analysis_and_risk_scoring(self):
        """Verify full multi-layer risk scoring, evidence sufficiency, and correlations."""
        res = analyze_email(str(TEST_EML_PATH), user_id=1)
        assert res["artifact_type"] == "email"
        assert res["risk"]["score"] >= 75.0
        assert res["risk"]["level"] == "CRITICAL"

        # Check evidence sufficiency
        suff = res["evidence_sufficiency"]
        assert suff is not None
        assert suff["score"] >= 80.0
        assert suff["level"] == "VERY_STRONG"
        assert "EMAIL_AUTH" in suff["evidence_classes_present"]
        assert "CONTENT" in suff["evidence_classes_present"]

        # Check evidence correlation
        corr = res["evidence_correlation"]
        assert corr is not None
        corr_names = [c["name"] for c in corr["correlations"]]
        assert "sender_identity_deception" in corr_names
        assert "auth_failure_plus_sender" in corr_names
        assert "social_engineering" in corr_names
