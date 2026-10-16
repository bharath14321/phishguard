"""
tests/test_scan_consistency_and_ai.py

Comprehensive regression validation suite for:
1. VirusTotal Result Normalization & Consistency (TEST-01 to TEST-04)
2. Structured Evidence & Signal Serialization (TEST-05 to TEST-06)
3. Multi-Artifact Evidence Sufficiency in Details (TEST-07 to TEST-12)
4. AI Security Analyst Telemetry Grounding & Context (TEST-13 to TEST-18)
5. Conditional Threat Intel & End-to-End Persistence (TEST-19 to TEST-20)
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from src.features.reputation import normalize_vt_result
from src.analysis.risk_engine import RiskSignal, analyze_url_risk
from src.features.url_analyzer import analyze_url as extract_url_features
from src.analysis.unified_analyzer import (
    analyze_url,
    analyze_hash,
    analyze_email,
    analyze_qr,
    analyze_file,
)
from src.analysis.analyst_context import (
    build_structured_evidence,
    build_gemini_context,
)
from src.analysis.security_chat import (
    FallbackRuleBasedProvider,
    process_chat_message,
)


# ===========================================================================
# 1. VIRUSTOTAL RESULT NORMALIZATION & CONSISTENCY (TEST-01 to TEST-04)
# ===========================================================================

def test_01_virustotal_normalization_canonical_schema():
    """TEST-01: Verify normalize_vt_result produces canonical schema with all expected keys and integer counts."""
    raw_data = {
        "positives": 14,
        "total": 72,
        "permalink": "https://virustotal.com/gui/url/sample",
    }
    normalized = normalize_vt_result(raw_data, "https://example.com")
    
    assert normalized["status"] == "SUCCESS"
    assert normalized["malicious"] == 14
    assert normalized["total"] == 72
    assert normalized["provider"] == "VirusTotal"
    assert normalized["is_clean"] is False
    assert normalized["is_unknown"] is False
    assert "14" in normalized["message"]


def test_02_local_ti_match_sets_vt_not_required():
    """TEST-02: Verify Local Threat Intelligence match bypasses eager VT and sets virustotal status NOT_REQUIRED."""
    with patch("src.analysis.unified_analyzer.query_local_threat_intelligence") as mock_ti:
        mock_ti.return_value = {
            "found": True,
            "source": "PhishTank",
            "threat_type": "phishing",
            "severity": "CRITICAL",
        }
        res = analyze_url("https://known-phish.local/login", user_id=1)
        
        assert res["risk"]["score"] >= 85.0
        assert res["risk"]["level"] in ["CRITICAL", "HIGH"]
        
        # Verify VT in details is NOT_REQUIRED
        vt = res["details"]["virustotal"]
        assert vt["status"] == "NOT_REQUIRED"
        assert vt["malicious"] == 0
        assert "PhishTank" in vt["message"] or "local" in vt["message"].lower()


def test_03_vt_unavailable_when_no_api_key(monkeypatch):
    """TEST-03: Verify when VIRUSTOTAL_API_KEY is unset and no local TI match, status is UNAVAILABLE without error."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    with patch("src.analysis.unified_analyzer.query_local_threat_intelligence") as mock_ti:
        mock_ti.return_value = {"found": False}
        res = analyze_url("https://some-unknown-domain-test123.com", user_id=1)
        
        vt = res["details"]["virustotal"]
        assert vt["status"] in ["UNAVAILABLE", "NOT_REQUIRED"]
        assert vt["malicious"] == 0
        assert vt["is_unknown"] is True or vt["status"] == "NOT_REQUIRED"


def test_04_vt_clean_or_not_found_does_not_fabricate():
    """TEST-04: Verify clean/not-found VT lookup sets status properly with 0 detections."""
    clean_raw = {"positives": 0, "total": 70, "status": "SUCCESS"}
    norm = normalize_vt_result(clean_raw, "https://clean-site.org")
    
    assert norm["malicious"] == 0
    assert norm["total"] == 70
    assert norm["is_clean"] is True
    assert norm["status"] == "SUCCESS"


# ===========================================================================
# 2. STRUCTURED EVIDENCE & SIGNAL SERIALIZATION (TEST-05 to TEST-06)
# ===========================================================================

def test_05_risk_signal_to_dict():
    """TEST-05: Verify RiskSignal.to_dict() returns structured dictionary without dataclass repr string."""
    sig = RiskSignal(
        name="Phishing Keyword in Path",
        weight=25.0,
        reason="Path contains high-risk authentication keyword: login",
        source="url_features",
        finding="Phishing Keyword in Path",
        severity="MEDIUM",
    )
    sig_dict = sig.to_dict()
    
    assert isinstance(sig_dict, dict)
    assert sig_dict["name"] == "Phishing Keyword in Path"
    assert sig_dict["weight"] == 25.0
    assert sig_dict["reason"] == "Path contains high-risk authentication keyword: login"
    assert sig_dict["source"] == "url_features"
    assert sig_dict["severity"] == "MEDIUM"
    assert "RiskSignal(" not in str(sig_dict["name"])


def test_06_unified_url_analysis_signals_are_clean_dicts():
    """TEST-06: Verify analyze_url produces signals as a list of clean dictionaries in both root and details."""
    res = analyze_url("http://paypal-security-verification.com/login", user_id=1)
    
    signals = res.get("signals", [])
    assert isinstance(signals, list)
    assert len(signals) > 0
    for s in signals:
        assert isinstance(s, dict)
        assert "name" in s
        assert "weight" in s
        assert "reason" in s
        assert not str(s["name"]).startswith("RiskSignal(")
        
    details_signals = res["details"].get("signals", [])
    assert isinstance(details_signals, list)
    assert len(details_signals) == len(signals)


# ===========================================================================
# 3. EVIDENCE SUFFICIENCY IN DETAILS (TEST-07 to TEST-12)
# ===========================================================================

def test_07_url_analysis_contains_evidence_sufficiency_in_details():
    """TEST-07: Verify URL analysis contains evidence_sufficiency in root and details."""
    res = analyze_url("https://google.com", user_id=1)
    
    assert "evidence_sufficiency" in res
    assert "evidence_sufficiency" in res["details"]
    suff = res["details"]["evidence_sufficiency"]
    assert "score" in suff
    assert "level" in suff
    assert "evidence_classes" in suff or "evidence_classes_present" in suff


def test_08_hash_analysis_contains_evidence_sufficiency_in_details():
    """TEST-08: Verify Hash analysis contains evidence_sufficiency in root and details."""
    sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = analyze_hash(sample_hash, user_id=1)
    
    assert "evidence_sufficiency" in res
    assert "evidence_sufficiency" in res["details"]
    suff = res["details"]["evidence_sufficiency"]
    assert "score" in suff
    assert "level" in suff


def test_09_email_analysis_contains_evidence_sufficiency_in_details(tmp_path):
    """TEST-09: Verify Email analysis contains evidence_sufficiency in root and details."""
    eml_file = tmp_path / "test.eml"
    eml_file.write_text(
        "From: security@paypal.com\n"
        "To: user@example.com\n"
        "Subject: Urgent Account Verification\n"
        "\n"
        "Please click http://phish-update.com/login to verify your account immediately.\n"
    )
    res = analyze_email(str(eml_file), user_id=1)
    
    assert "evidence_sufficiency" in res
    assert "evidence_sufficiency" in res["details"]
    suff = res["details"]["evidence_sufficiency"]
    assert isinstance(suff, dict)
    assert "level" in suff


def test_10_qr_analysis_contains_evidence_sufficiency_in_details(tmp_path):
    """TEST-10: Verify QR analysis contains evidence_sufficiency in root and details."""
    qr_file = tmp_path / "dummy_qr.png"
    qr_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82")
    
    res = analyze_qr(str(qr_file), user_id=1)
    assert "evidence_sufficiency" in res
    assert "evidence_sufficiency" in res["details"]


def test_11_file_analysis_contains_evidence_sufficiency_in_details(tmp_path):
    """TEST-11: Verify File analysis contains evidence_sufficiency in root and details."""
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Hello security analysis")
    
    res = analyze_file(str(test_file), user_id=1)
    assert "evidence_sufficiency" in res
    assert "evidence_sufficiency" in res["details"]


def test_12_legacy_record_evidence_sufficiency_reconstruction():
    """TEST-12: Verify get_single_analysis endpoint logic reconstructs evidence sufficiency for legacy database records."""
    from src.analysis.evidence_sufficiency import compute_evidence_sufficiency
    
    legacy_record = {
        "artifact_type": "url",
        "url": "https://suspicious-login.com",
        "risk": {"score": 75.0, "level": "HIGH"},
        "signals": [{"name": "Suspicious TLD", "weight": 35.0, "reason": "High risk TLD"}],
        "details": {"url": "https://suspicious-login.com"},
        "explanation": {"summary": "Suspicious login page"},
    }
    
    suff = compute_evidence_sufficiency(legacy_record)
    assert suff is not None
    assert suff.score > 0
    assert suff.level.value in ["INSUFFICIENT", "LIMITED", "STRONG", "VERY_STRONG"]


# ===========================================================================
# 4. AI SECURITY ANALYST TELEMETRY GROUNDING (TEST-13 to TEST-18)
# ===========================================================================

def test_13_analyst_context_extracts_local_ti_and_evidence_sufficiency():
    """TEST-13: Verify build_structured_evidence extracts local_threat_intelligence and evidence_sufficiency."""
    analysis_record = {
        "analysis_id": 5,
        "artifact_type": "url",
        "url": "https://login-outlook365.yzz.me/",
        "risk": {"score": 85.0, "level": "CRITICAL"},
        "local_ti": {
            "found": True,
            "source": "PhishTank",
            "threat_type": "phishing",
            "severity": "CRITICAL",
        },
        "evidence_sufficiency": {
            "score": 90.0,
            "level": "VERY_STRONG",
            "evidence_classes_present": ["LOCAL_THREAT_INTEL", "URL_LEXICAL"],
        },
        "details": {
            "virustotal": {
                "status": "NOT_REQUIRED",
                "message": "Local threat intelligence match confirmed; external lookup skipped.",
            }
        },
    }
    evidence = build_structured_evidence(analysis_record)
    
    assert "local_threat_intelligence" in evidence
    assert evidence["local_threat_intelligence"]["source"] == "PhishTank"
    assert "evidence_sufficiency" in evidence
    assert evidence["evidence_sufficiency"]["score"] == 90.0
    assert "threat_intel" in evidence
    assert evidence["threat_intel"]["status"] == "NOT_REQUIRED"


def test_14_build_gemini_context_labeled_sections_and_bounds():
    """TEST-14: Verify build_gemini_context formats labeled sections with proper delimiters."""
    evidence = {
        "analysis_id": 5,
        "artifact_type": "url",
        "risk_score": 85.0,
        "risk_level": "CRITICAL",
        "local_threat_intelligence": {"found": True, "source": "PhishTank"},
        "evidence_sufficiency": {"score": 85.0, "level": "STRONG"},
    }
    context_str = build_gemini_context(evidence)
    
    assert "=== AUTHORITATIVE PHISHGUARD ANALYSIS EVIDENCE ===" in context_str
    assert "--- LOCAL THREAT INTELLIGENCE ---" in context_str
    assert "--- EVIDENCE SUFFICIENCY ---" in context_str
    assert "PhishTank" in context_str


def test_15_fallback_provider_grounded_section_headers():
    """TEST-15: Verify FallbackRuleBasedProvider includes grounded sections."""
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "url",
        "url": "http://paypal-secure.com",
        "risk": {"score": 85.0, "level": "CRITICAL"},
        "summary": "High risk PayPal credential harvester",
        "signals": [
            {"name": "Brand Impersonation", "weight": 50, "reason": "Impersonating PayPal brand"},
        ],
        "details": {
            "virustotal": {"status": "UNAVAILABLE", "malicious": 0, "total": 0},
        },
    }
    resp = provider.generate_response("", "Why was this classified as risky?", context)
    
    assert "PHISHGUARD Observed" in resp or "[PHISHGUARD OBSERVED]" in resp
    assert "Threat Intelligence" in resp or "[THREAT INTELLIGENCE]" in resp
    assert "Machine Learning" in resp or "[MODEL INFERENCE]" in resp
    assert "PayPal" in resp


def test_16_fallback_provider_investigation_5_local_ti_explanation():
    """TEST-16: Verify FallbackRuleBasedProvider explains Investigation #5 (PhishTank match with VT NOT_REQUIRED)."""
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "url",
        "url": "https://login-outlook365.yzz.me/",
        "risk": {"score": 85.0, "level": "CRITICAL"},
        "summary": "Known phishing page matched in PhishTank database",
        "local_ti": {
            "found": True,
            "source": "PhishTank",
            "threat_type": "phishing",
            "severity": "CRITICAL",
        },
        "details": {
            "local_ti": {
                "found": True,
                "source": "PhishTank",
                "threat_type": "phishing",
            },
            "virustotal": {
                "status": "NOT_REQUIRED",
                "message": "Local threat intelligence match confirmed; external lookup skipped.",
            },
        },
    }
    resp = provider.generate_response("", "Why was this flagged and what did threat intelligence find?", context)
    
    assert "PhishTank" in resp
    assert "85" in resp
    assert "CRITICAL" in resp
    assert "NOT_REQUIRED" in resp or "skipped" in resp.lower()


def test_17_fallback_provider_evidence_sufficiency_query():
    """TEST-17: Verify FallbackRuleBasedProvider responds to evidence sufficiency questions accurately."""
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "url",
        "url": "https://test-bank-portal.xyz",
        "risk": {"score": 60.0, "level": "HIGH"},
        "evidence_sufficiency": {
            "score": 75.0,
            "level": "STRONG",
            "evidence_classes_present": ["URL_LEXICAL", "BRAND_INTEL"],
            "has_contradiction": False,
        },
    }
    resp = provider.generate_response("", "What is the evidence sufficiency score?", context)
    
    assert "75%" in resp
    assert "STRONG" in resp
    assert "URL_LEXICAL" in resp or "BRAND_INTEL" in resp


def test_18_fallback_provider_virustotal_accuracy_without_fake_zero():
    """TEST-18: Verify FallbackRuleBasedProvider accurately explains VT when unavailable vs when detected."""
    provider = FallbackRuleBasedProvider()
    context_unavail = {
        "artifact_type": "url",
        "url": "https://unknown.com",
        "details": {
            "virustotal": {"status": "UNAVAILABLE", "message": "API key not configured."}
        },
    }
    resp = provider.generate_response("", "What did VirusTotal find?", context_unavail)
    assert "UNAVAILABLE" in resp

    context_detected = {
        "artifact_type": "url",
        "url": "https://malicious.com",
        "details": {
            "virustotal": {"status": "SUCCESS", "malicious": 21, "total": 70}
        },
    }
    resp2 = provider.generate_response("", "What did VirusTotal find?", context_detected)
    assert "21 / 70" in resp2


# ===========================================================================
# 5. CONDITIONAL THREAT INTEL & END-TO-END (TEST-19 to TEST-20)
# ===========================================================================

def test_19_url_analyzer_conditional_vt_execution():
    """TEST-19: Verify extract_url_features(url, check_vt=False) does not trigger get_url_reputation."""
    with patch("src.features.url_analyzer.get_url_reputation") as mock_vt:
        details = extract_url_features("https://secure-login.test", check_vt=False)
        assert mock_vt.call_count == 0
        assert "url" in details


def test_20_process_chat_message_with_full_context():
    """TEST-20: Verify process_chat_message executes smoothly and returns standardized response object."""
    context = {
        "artifact_type": "url",
        "url": "https://login.microsoftonline.com.phish-portal.cc",
        "risk": {"score": 85.0, "level": "CRITICAL"},
        "summary": "Microsoft brand impersonation with deceptive subdomain structure.",
        "signals": [
            {"name": "Brand Impersonation", "weight": 50, "reason": "Microsoft brand in subdomain"},
            {"name": "Suspicious TLD", "weight": 35, "reason": ".cc ccTLD abuse"},
        ],
        "evidence_sufficiency": {"score": 80.0, "level": "STRONG"},
        "details": {
            "virustotal": {"status": "NOT_REQUIRED", "message": "High-confidence heuristic trigger"},
        },
    }
    
    result = process_chat_message("Provide an executive summary of this threat.", analysis_context=context)
    
    assert isinstance(result, dict)
    assert "response" in result
    assert result["artifact_type"] == "url"
    assert result["risk_level"] == "CRITICAL"
    assert len(result["response"]) > 50
    assert "Microsoft" in result["response"]
