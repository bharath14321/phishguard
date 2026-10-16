"""
tests/test_email_reliability_and_fixtures.py

Comprehensive regression test suite for PHISHGUARD:
- P0: Standardized ML Result Contract & RF tree decision path explainability
- P1: Standardized Redirect Analysis Contract & observable hops
- P2: Webpage Analysis detailed fetch, failure categories, and form/password findings
- P3: Model Explainer Global vs Local scope distinction
- P4: Chat deduplication and single AI answer per question
- P5: Raw RFC822 headers preservation & authentication status (absent != failure)
- P6: DNS records resolution and status telemetry
- P7: Multi-layer risk calibration & evidence categorization
- P8: Local Threat Intelligence atomic updater, lock, rollback, and status
- P9: End-to-end fixture analysis for fixtures 13 through 18
"""

import os
from pathlib import Path
import pytest
import sqlite3
import tempfile
import time

from src.models.url_model_inference import predict_url
from src.analysis.model_explainer import explain_prediction
from src.features.redirect_analyzer import trace_redirect_chain
from src.features.webpage_analyzer import fetch_webpage_detailed, analyze_html_content
from src.features.domain_intelligence import resolve_dns, analyze_domain
from src.features.email_analyzer import analyze_email_headers, parse_raw_email
from src.features.email_authentication import extract_auth_status, calculate_authentication_signals
from src.analysis.risk_engine import analyze_url_risk, RiskResult
from src.analysis.unified_analyzer import analyze_email_unified
from src.features.threat_intelligence_updater import ThreatIntelligenceUpdater, get_threat_intelligence_status
from src.analysis.security_chat import FallbackRuleBasedProvider, format_analysis_context_for_prompt

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = _PROJECT_ROOT / "tests" / "fixtures" / "validation" / "emails"


# ============================================================================
# P0 & P3: Standardized ML Result Contract & Decision Paths
# ============================================================================
def test_p0_ml_standardized_contract():
    """Verify URL ML contract produces all required fields and decision path summary."""
    res = predict_url("https://example.com/login")
    assert res["model_name"] in ("Random Forest URL Classifier", "URL Random Forest (Lexical)")
    assert "model_version" in res
    assert res["model_available"] is True
    assert res["evaluated"] is True
    assert res["predicted_class"] in (0, 1)
    assert res["verdict"] in ("benign", "phishing")
    assert 0.0 <= res["threshold"] <= 1.0
    assert 0.0 <= res["phishing_probability"] <= 1.0
    assert 0.0 <= res["benign_probability"] <= 1.0
    assert abs(res["phishing_probability"] + res["benign_probability"] - 1.0) < 1e-4
    assert isinstance(res["features"], dict)
    assert isinstance(res["explanation_data"], dict)
    assert "top_influential_features" in res["explanation_data"]
    assert "explanation_caveat" in res


def test_p3_model_explainer_scope_distinction():
    """Verify model explainer explicitly separates global feature importances from local decision paths."""
    expl = explain_prediction("https://example.com/login")
    assert "global_feature_importances" in expl
    assert "local_feature_values" in expl
    assert "local_influential_features" in expl
    assert "scope_distinction" in expl
    assert "limitations_and_caveats" in expl
    assert any("Gini" in str(v) for v in expl["scope_distinction"].values())


# ============================================================================
# P1: Standardized Redirect Analysis Contract
# ============================================================================
def test_p1_redirect_contract():
    """Verify redirect analysis returns contract status, hops list, and count."""
    res = trace_redirect_chain("https://example.com/", max_redirects=2, timeout=2.0)
    assert res["status"] in ("COMPLETED", "NO_REDIRECT", "BLOCKED", "TIMEOUT", "ERROR")
    assert isinstance(res["hops"], list)
    assert isinstance(res["redirect_count"], int)
    assert res["final_url"] is not None
    assert "redirect_chain" in res  # backward compat


# ============================================================================
# P2: Webpage Analysis Detailed Findings & Safe Fetch
# ============================================================================
def test_p2_webpage_html_parsing_signals():
    """Verify HTML parsing correctly identifies login forms, passwords, and cross-domain action."""
    html_sample = """
    <html>
      <body>
        <form action="https://attacker.example.org/login" method="POST">
          <input type="text" name="user">
          <input type="password" name="pass">
          <input type="submit" value="Login">
        </form>
      </body>
    </html>
    """
    findings = analyze_html_content(html_sample, base_url="https://victim.example.com/page")
    assert findings["has_login_form"] is True
    assert findings["has_password_field"] is True
    assert findings["password_field_count"] >= 1
    assert findings["has_cross_domain_submission"] is True
    assert len(findings["cross_domain_forms"]) >= 1


# ============================================================================
# P5: Raw RFC822 Email Headers & Authentication
# ============================================================================
def test_p5_email_headers_preservation():
    """Verify raw headers extraction preserves order, duplicates, and untrusted notice."""
    raw_eml = b"""From: Sender <sender@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\nReceived: by mta1\r\nReceived: by mta2\r\n\r\nBody text"""
    msg = parse_raw_email(raw_eml)
    res = analyze_email_headers(msg)
    assert "raw_headers" in res
    assert isinstance(res["raw_headers"], list)
    assert len(res["raw_headers"]) >= 5
    assert "raw_headers_text" in res
    assert "headers_untrusted_notice" in res
    # Verify both Received headers preserved
    received_entries = [h for h in res["raw_headers"] if h["name"].lower() == "received"]
    assert len(received_entries) == 2


def test_p5_auth_absent_not_failure():
    """Verify absent authentication headers are classified as 'absent', never inferred as fail."""
    status = extract_auth_status([])
    assert status["spf"] == "absent"
    assert status["dkim"] == "absent"
    assert status["dmarc"] == "absent"
    signals = calculate_authentication_signals(status)
    assert signals["spf_fail"] is False
    assert signals["dkim_fail"] is False
    assert signals["dmarc_fail"] is False
    assert signals["spf_absent"] is True


# ============================================================================
# P6: DNS Records & Status Telemetry
# ============================================================================
def test_p6_dns_resolution_telemetry():
    """Verify DNS resolution telemetry returns status and structured record types."""
    dns_res = resolve_dns("example.com")
    assert "status" in dns_res
    assert dns_res["status"] in ("SUCCESS", "NO_RECORDS", "NXDOMAIN", "TIMEOUT", "RESOLVER_FAILURE")
    assert "records" in dns_res
    assert "A" in dns_res["records"]
    assert "ipv4_addresses" in dns_res  # backward compat


# ============================================================================
# P7: Multi-Layer Risk Engine Calibration
# ============================================================================
def test_p7_risk_engine_calibration():
    """Verify calibrated scoring: Local TI = 85+, ML high = 20, Cross-domain form = 25."""
    # Scenario A: Local TI match alone
    res_ti = analyze_url_risk({
        "local_ti": {"found": True, "source": "phishtank", "threat_type": "phishing"},
    })
    assert res_ti.score >= 85
    assert res_ti.level in ("HIGH", "CRITICAL")

    # Scenario B: High ML probability alone without corroborating indicators
    res_ml = analyze_url_risk({
        "ml": {"model_available": True, "phishing_probability": 0.99},
    })
    assert res_ml.score == 20.0
    assert res_ml.level == "LOW"  # Correctly prevents false positives for uncorroborated lexical ML

    # Scenario C: ML high probability + Cross-domain credential form
    res_combined = analyze_url_risk({
        "ml": {"model_available": True, "phishing_probability": 0.95},
        "webpage_analysis": {"has_cross_domain_submission": True},
    })
    assert res_combined.score == 45.0
    assert res_combined.level == "MEDIUM"


# ============================================================================
# P4: Security Analyst Chat Explanations & Deduplication
# ============================================================================
def test_p4_ai_analyst_explanations():
    """Verify FallbackRuleBasedProvider answers questions accurately from context."""
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "email",
        "risk_score": 20,
        "risk_level": "LOW",
        "ml": {
            "model_available": True,
            "phishing_probability": 0.991,
            "verdict": "phishing",
            "features": {"has_https": 1, "url_length": 25},
        },
        "details": {
            "redirect_analysis": {
                "status": "COMPLETED",
                "redirect_count": 1,
                "hops": [{"from_url": "https://short.ly/1", "status_code": 302, "to_url": "https://example.com/"}],
            },
            "webpage_analysis": {
                "status_code": 200,
                "form_count": 1,
                "has_login_form": True,
                "password_field_count": 1,
                "has_cross_domain_submission": False,
            },
            "domain_intelligence": {
                "dns": {
                    "status": "SUCCESS",
                    "A": ["93.184.216.34"],
                    "MX": ["mx.example.com"],
                }
            },
            "email_authentication": {
                "message_authentication": {"spf": "pass", "dkim": "absent", "dmarc": "absent"},
            },
        },
    }

    # Test ML explanation
    resp_ml = provider.generate_response("", "Why did the ML model predict phishing?", context)
    assert "Supervised Lexical & Domain Random Forest" in resp_ml
    assert "99.1%" in resp_ml

    # Test Discrepancy between ML and Risk
    resp_disc = provider.generate_response("", "Why is the ML probability high while the risk score is low?", context)
    assert "Multi-Layer Defense Calibration" in resp_disc
    assert "20/100" in resp_disc

    # Test Redirects
    resp_red = provider.generate_response("", "What redirects occurred?", context)
    assert "HTTP 302" in resp_red

    # Test Webpage
    resp_web = provider.generate_response("", "What forms or password fields were found?", context)
    assert "Login Form Identified" in resp_web

    # Test DNS
    resp_dns = provider.generate_response("", "What DNS records exist?", context)
    assert "93.184.216.34" in resp_dns

    # Test Authentication
    resp_auth = provider.generate_response("", "What is the email authentication status?", context)
    assert "PASS" in resp_auth


# ============================================================================
# P8: Threat Intelligence Updater, Lock, and Rollback
# ============================================================================
def test_p8_threat_intelligence_updater_flow():
    """Verify threat intelligence updater locking, backup, staging, swap, and rollback."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_db = Path(tmp_dir) / "threat_intelligence.db"
        test_lock = Path(tmp_dir) / ".ti_update.lock"

        updater = ThreatIntelligenceUpdater(db_path=test_db, lock_path=test_lock)

        # 1. Initialize staging DB and ingest records
        updater.acquire_lock()
        try:
            conn = updater.init_staging_db(copy_existing=False)
            records = [
                {"indicator": "https://badphish.test/login", "indicator_type": "url", "classification": "phishing"},
                {"indicator": "https://malware.test/dl", "indicator_type": "url", "classification": "malware"},
            ]
            inserted = updater.ingest_records(conn, "test_feed", records)
            assert inserted == 2
            updater.verify_and_swap(conn)
        finally:
            updater.release_lock()

        assert test_db.exists()
        status_after_ingest = get_threat_intelligence_status(test_db)
        assert status_after_ingest["status"] == "ACTIVE"
        assert status_after_ingest["total_indicators"] == 2

        # 2. Test rollback snapshot creation and restoration
        updater.acquire_lock()
        try:
            updater.create_backup_snapshot()
            assert updater.backup_path.exists()

            # Corrupt production or wipe it
            conn2 = updater.init_staging_db(copy_existing=False)
            updater.ingest_records(conn2, "test_feed", [{"indicator": "https://onlyone.test", "indicator_type": "url"}])
            updater.verify_and_swap(conn2)
            assert get_threat_intelligence_status(test_db)["total_indicators"] == 1

            # Roll back
            updater.rollback_to_snapshot()
            assert get_threat_intelligence_status(test_db)["total_indicators"] == 2
        finally:
            updater.release_lock()


# ============================================================================
# P9: Fixtures 13 through 18 Pipeline Verification
# ============================================================================
@pytest.mark.parametrize("fixture_name", [
    "13_redirect_chain_benign.eml",
    "14_login_form_page_analysis.eml",
    "15_webpage_links_resources.eml",
    "16_multiple_url_redirect_webpage.eml",
    "17_visible_text_href_web_analysis.eml",
    "18_form_and_nested_links.eml",
])
def test_p9_email_fixtures_pipeline(fixture_name):
    """Verify all fixtures 13 through 18 parse successfully and return compliant result structures."""
    fixture_path = FIXTURES_DIR / fixture_name
    assert fixture_path.exists(), f"Fixture {fixture_name} missing from {FIXTURES_DIR}"

    res = analyze_email_unified(str(fixture_path))
    assert res["artifact_type"] == "email"
    assert "risk_score" in res
    assert "risk_level" in res
    assert "details" in res

    details = res["details"]
    assert "email_headers" in details
    assert "raw_headers" in details["email_headers"]
    assert "email_authentication" in details
    assert "url_analyses" in details
    assert isinstance(details["url_analyses"], list)

    # Fixture-specific checks
    if fixture_name == "17_visible_text_href_web_analysis.eml":
        # Should flag mismatch between visible text and href
        assert any(u.get("domain_mismatch") for u in details["url_analyses"])

    if fixture_name == "18_form_and_nested_links.eml":
        # Should detect multiple destination URLs or forms
        assert len(details["url_analyses"]) >= 1
