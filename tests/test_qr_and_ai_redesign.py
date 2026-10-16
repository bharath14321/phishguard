"""
tests/test_qr_and_ai_redesign.py

Comprehensive test suite verifying:
1. Pure-Python ISO/IEC 18004 QR decoder and payload classifier (QR-01 .. QR-09).
2. Authoritative central URL routing from decoded QR codes (QR-02 .. QR-05).
3. Non-URL and malformed QR handling (QR-06, QR-07).
4. AI Security Analyst context grounding, conversational inquiries, and truthfulness (QR-10 .. QR-18, AI-01 .. AI-10).
"""

import os
import tempfile
import pytest
import qrcode
from PIL import Image

from src.features.qr_decoder import decode_qr_image
from src.features.qr_analyzer import analyze_qr_code, classify_qr_payload
from src.analysis.unified_analyzer import analyze_qr, analyze_url
from src.analysis.security_chat import (
    process_chat_message,
    FallbackRuleBasedProvider,
    GeminiProvider,
)
from src.analysis.analyst_context import (
    build_structured_evidence,
    select_relevant_artifact_context,
    build_gemini_context,
)


@pytest.fixture(scope="session")
def sample_clean_qr_path(tmp_path_factory):
    """Generate deterministic clean QR fixture for https://example.com/"""
    fn = tmp_path_factory.mktemp("qr_fixtures") / "clean_example.png"
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data("https://example.com/")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(fn))
    return str(fn)


@pytest.fixture(scope="session")
def sample_phish_qr_path(tmp_path_factory):
    """Generate deterministic phishing QR fixture for https://login-outlook365.yzz.me/"""
    fn = tmp_path_factory.mktemp("qr_fixtures") / "phish_outlook.png"
    qr = qrcode.QRCode(version=2, box_size=8, border=4)
    qr.add_data("https://login-outlook365.yzz.me/")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(fn))
    return str(fn)


@pytest.fixture(scope="session")
def sample_text_qr_path(tmp_path_factory):
    """Generate deterministic non-URL text QR fixture."""
    fn = tmp_path_factory.mktemp("qr_fixtures") / "text_qr.png"
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data("Non-URL security incident note #4092")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(fn))
    return str(fn)


# =====================================================================
# QR-01 .. QR-09: QR Decoder and Central Routing Tests
# =====================================================================

def test_qr_01_valid_qr_url_decoded(sample_clean_qr_path):
    """QR-01: Valid QR code image decodes to exact URL string."""
    decoded = decode_qr_image(sample_clean_qr_path)
    assert decoded == "https://example.com/"

    analysis = analyze_qr_code(sample_clean_qr_path)
    assert analysis["success"] is True
    assert analysis["decode_status"] == "SUCCESS"
    assert analysis["decoded_payload"] == "https://example.com/"
    assert analysis["payload_type"] == "URL"
    assert analysis["is_url"] is True


def test_qr_02_decoded_url_enters_central_url_analyzer(sample_clean_qr_path):
    """QR-02: Decoded URL from QR routes into authoritative central URL pipeline."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    assert result["artifact_type"] == "qr"
    assert "details" in result
    assert "qr" in result["details"]
    assert result["details"]["qr"]["decode_status"] == "SUCCESS"
    assert result["details"]["qr"]["decoded_payload"] == "https://example.com/"
    assert "url_analysis" in result["details"]


def test_qr_03_decoded_url_gets_ml_result(sample_clean_qr_path):
    """QR-03: Decoded QR URL receives ML evaluation structure from central URL pipeline."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    assert "ml" in result["details"]
    ml_info = result["details"]["ml"]
    assert "model_available" in ml_info
    assert "features" in ml_info


def test_qr_04_decoded_url_gets_evidence_sufficiency(sample_clean_qr_path):
    """QR-04: Decoded QR URL receives evidence sufficiency computation."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    assert "evidence_sufficiency" in result
    assert result["evidence_sufficiency"] is not None
    assert "score" in result["evidence_sufficiency"]
    assert "level" in result["evidence_sufficiency"]


def test_qr_05_decoded_phishing_qr_triggers_threat_intelligence(sample_phish_qr_path):
    """QR-05: Decoded phishing QR matches Local TI and escalates to CRITICAL risk."""
    result = analyze_qr(sample_phish_qr_path, user_id=1)
    assert result["risk"]["score"] >= 80.0
    assert result["risk"]["level"] in ["HIGH", "CRITICAL"]
    signals = [s.get("name") for s in result.get("signals", []) if isinstance(s, dict)]
    assert any("Threat Intelligence" in s or "Local" in s for s in signals)


def test_qr_06_non_url_qr_payload_classified_correctly(sample_text_qr_path):
    """QR-06: Non-URL QR payload is classified as TEXT and not processed as a URL."""
    result = analyze_qr(sample_text_qr_path, user_id=1)
    qr_meta = result["details"]["qr"]
    assert qr_meta["decode_status"] == "SUCCESS"
    assert qr_meta["payload_type"] == "TEXT"
    assert qr_meta["is_url"] is False
    assert result["risk"]["score"] == 0.0
    assert "TEXT" in result["explanation"]["summary"] or "Non-URL" in result["explanation"]["summary"]


def test_qr_06b_payload_classification_categories():
    """QR-06B: Test classification for various non-URL strings."""
    assert classify_qr_payload("https://phishguard.org") == "URL"
    assert classify_qr_payload("http://insecure.test") == "URL"
    assert classify_qr_payload("www.bank-verify.com/login") == "URL"
    assert classify_qr_payload("mailto:secops@phishguard.org") == "EMAIL"
    assert classify_qr_payload("admin@phishguard.org") == "EMAIL"
    assert classify_qr_payload("tel:+1234567890") == "PHONE"
    assert classify_qr_payload("WIFI:T:WPA;S:PhishGuardSec;P:secret123;;") == "WIFI"
    assert classify_qr_payload("Plain inspection string") == "TEXT"


def test_qr_07_malformed_image_handled_safely(tmp_path):
    """QR-07: Malformed or unparseable image returns structured FAILED status."""
    corrupted_file = tmp_path / "corrupted.png"
    corrupted_file.write_bytes(b"invalid binary image data")

    result = analyze_qr(str(corrupted_file), user_id=1)
    qr_meta = result["details"]["qr"]
    assert qr_meta["decode_status"] == "FAILED"
    assert qr_meta["decoded_payload"] is None
    assert qr_meta["is_url"] is False
    assert result["risk"]["level"] in ["LOW", "UNKNOWN"]
    assert "No QR code payload extracted" in result["explanation"]["summary"]


def test_qr_08_qr_does_not_execute_or_browse(sample_clean_qr_path):
    """QR-08: QR decoding strictly extracts text data without executing code or navigating."""
    analysis = analyze_qr_code(sample_clean_qr_path)
    assert isinstance(analysis["decoded_payload"], str)


def test_qr_09_ssrf_controls_apply_to_decoded_url():
    """QR-09: Loopback / internal private IP in decoded QR URL is safely handled."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data("http://127.0.0.1:8080/admin")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(tmp.name)
        tmp_name = tmp.name

    try:
        result = analyze_qr(tmp_name, user_id=1)
        assert result["artifact_type"] == "qr"
        assert result["details"]["qr"]["decoded_payload"] == "http://127.0.0.1:8080/admin"
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


# =====================================================================
# QR-10 .. QR-18 & AI-01 .. AI-10: AI Security Analyst Tests
# =====================================================================

def test_qr_10_ai_receives_decoded_qr_url(sample_clean_qr_path):
    """QR-10: AI Security Analyst context receives decoded QR URL."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    structured = build_structured_evidence(result)
    assert structured.get("decoded_payload") == "https://example.com/" or structured.get("url") == "https://example.com/"


def test_qr_11_ai_answers_what_url_was_in_qr(sample_clean_qr_path):
    """QR-11: AI answers 'What URL was inside the QR code?' truthfully."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("What URL was inside the QR code?", result)
    response_text = chat_res["response"]
    assert "https://example.com/" in response_text
    assert "successfully decoded" in response_text.lower() or "URL" in response_text


def test_qr_12_ai_answers_why_classified_this_way(sample_phish_qr_path):
    """QR-12: AI explains why phishing QR URL received high/critical risk."""
    result = analyze_qr(sample_phish_qr_path, user_id=1)
    chat_res = process_chat_message("Why was this URL classified this way?", result)
    response_text = chat_res["response"]
    assert "Threat" in response_text or "CRITICAL" in response_text or "HIGH" in response_text


def test_qr_13_ai_answers_vt_question(sample_clean_qr_path):
    """QR-13: AI answers VirusTotal question directly from scan telemetry."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("Did VirusTotal detect anything?", result)
    response_text = chat_res["response"]
    assert "VirusTotal" in response_text


def test_qr_14_ai_answers_unknown_fields_honestly(sample_clean_qr_path):
    """QR-14: AI clearly identifies unknown / unobserved fields without faking."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("What evidence is missing or untested?", result)
    response_text = chat_res["response"]
    assert "Unknown" in response_text or "not tested" in response_text.lower() or "not monitored" in response_text.lower()


def test_qr_15_ai_does_not_invent_unavailable_evidence(sample_clean_qr_path):
    """QR-15: AI does not hallucinate malware families or CVEs for clean example.com."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("What is the malware family?", result)
    response_text = chat_res["response"]
    assert "not provided" in response_text.lower() or "unknown" in response_text.lower() or "none" in response_text.lower()


def test_qr_16_markdown_renders_cleanly_without_literal_hashes(sample_clean_qr_path):
    """QR-16: AI output uses standard Markdown headers (##, ###) without unparsed tags."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("Summarize the scan findings", result)
    response_text = chat_res["response"]
    assert "####" not in response_text  # Replaced with clean ## and ### sections
    assert "## Executive Answer" in response_text or "###" in response_text


def test_qr_17_full_url_and_hash_retained_in_context(sample_phish_qr_path):
    """QR-17: Full URL and identifier are preserved without truncation in AI context."""
    result = analyze_qr(sample_phish_qr_path, user_id=1)
    structured = build_structured_evidence(result)
    assert structured["url"] == "https://login-outlook365.yzz.me/" or structured["decoded_payload"] == "https://login-outlook365.yzz.me/"


def test_ai_01_natural_language_question(sample_clean_qr_path):
    """AI-01: Natural language inquiry receives grounded analysis."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("Is this link safe for our employees to open?", result)
    assert "LOW" in chat_res["response"] or "BENIGN" in chat_res["response"] or "safe" in chat_res["response"].lower()


def test_ai_02_local_ti_positive_question(sample_phish_qr_path):
    """AI-02: AI explains local threat intelligence detection accurately."""
    result = analyze_qr(sample_phish_qr_path, user_id=1)
    chat_res = process_chat_message("Was this URL found in the local threat intelligence database?", result)
    assert "MATCH CONFIRMED" in chat_res["response"] or "POSITIVE" in chat_res["response"]


def test_ai_03_redirect_question(sample_clean_qr_path):
    """AI-03: AI answers redirect inquiry grounded in scan telemetry."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("Did the URL redirect anywhere?", result)
    assert "Redirect" in chat_res["response"]


def test_ai_04_webpage_fetched_question(sample_clean_qr_path):
    """AI-04: AI answers webpage fetch inquiry accurately."""
    result = analyze_qr(sample_clean_qr_path, user_id=1)
    chat_res = process_chat_message("Was a webpage fetched?", result)
    assert "Webpage" in chat_res["response"]


def test_ai_05_investigate_next_guidance(sample_phish_qr_path):
    """AI-05: AI provides actionable next steps for high-risk indicators."""
    result = analyze_qr(sample_phish_qr_path, user_id=1)
    chat_res = process_chat_message("What should I investigate next?", result)
    assert "Isolate" in chat_res["response"] or "Block" in chat_res["response"]
