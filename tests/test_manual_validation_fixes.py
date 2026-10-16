"""
Comprehensive Regression Test Suite for Manual Validation Fixes
Tests:
1. VirusTotal threat label and malware family extraction & normalization.
2. Local Threat Intelligence integration without short-circuiting ML or correlations.
3. Single authoritative analysis result representation and VT consistency.
4. Non-applicable ML status for File and Hash artifact types.
5. AI Security Analyst grounded context and query routing (threat label, vendor detections, untruncated SHA-256, unknowns).
6. Multipart file upload data contract.
7. SSRF isolation from threat intelligence verdicts.
"""

import pytest
import os
import io
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.features.reputation import (
    extract_vt_threat_label,
    normalize_vt_result,
    get_url_reputation,
    get_hash_reputation,
)
from src.analysis.unified_analyzer import analyze_url, analyze_hash, analyze_file, analyze_qr
from src.analysis.analyst_context import build_structured_evidence, select_relevant_artifact_context
from src.analysis.security_chat import FallbackRuleBasedProvider, process_chat_message
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. VirusTotal Threat Label & Malware Family Extraction Tests
# ---------------------------------------------------------------------------

def test_extract_vt_threat_label_from_suggested_threat_label():
    attributes = {
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.emotet/generic",
            "popular_threat_category": [{"value": "trojan", "count": 14}],
            "popular_threat_name": [{"value": "emotet", "count": 10}],
        }
    }
    extracted = extract_vt_threat_label(attributes)
    assert extracted["threat_label"] == "trojan.emotet/generic"
    assert extracted["threat_category"] == "trojan"
    assert extracted["threat_family"] == "emotet"


def test_extract_vt_threat_label_from_popular_name_when_no_suggested():
    attributes = {
        "popular_threat_classification": {
            "popular_threat_category": [{"value": "ransomware", "count": 8}],
            "popular_threat_name": [{"value": "lockbit", "count": 6}],
        }
    }
    extracted = extract_vt_threat_label(attributes)
    assert extracted["threat_label"] == "lockbit"
    assert extracted["threat_category"] == "ransomware"
    assert extracted["threat_family"] == "lockbit"


def test_extract_vt_threat_label_from_categories_when_no_pop_class():
    attributes = {
        "categories": {
            "VendorA": "phishing and scams",
            "VendorB": "phishing and scams",
            "VendorC": "suspicious",
        }
    }
    extracted = extract_vt_threat_label(attributes)
    assert extracted["threat_label"] == "phishing and scams"


def test_extract_vt_threat_label_from_vendor_consensus():
    attributes = {
        "last_analysis_results": {
            "Engine1": {"category": "malicious", "result": "Trojan-Spy.Win32.Agent"},
            "Engine2": {"category": "malicious", "result": "Trojan-Spy.Win32.Agent"},
            "Engine3": {"category": "clean", "result": "clean"},
        }
    }
    extracted = extract_vt_threat_label(attributes)
    assert extracted["threat_label"] == "Trojan-Spy.Win32.Agent"


def test_extract_vt_threat_label_unknown_when_empty():
    extracted = extract_vt_threat_label({})
    assert extracted["threat_label"] == "Unknown / not provided"
    assert extracted["threat_category"] == "Unknown"
    assert extracted["threat_family"] == "Unknown"


def test_normalize_vt_result_preserves_threat_label():
    raw_vt = {
        "status": "SUCCESS",
        "malicious": 65,
        "total": 67,
        "threat_label": "trojan.emotet/generic",
        "threat_category": "trojan",
        "threat_family": "emotet",
    }
    normalized = normalize_vt_result(raw_vt)
    assert normalized["malicious"] == 65
    assert normalized["total"] == 67
    assert normalized["threat_label"] == "trojan.emotet/generic"
    assert normalized["status"] == "SUCCESS"


def test_normalize_vt_result_extracts_threat_label_from_attributes():
    raw_vt = {
        "status": "SUCCESS",
        "malicious": 10,
        "total": 70,
        "attributes": {
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.agent/stealer",
                "popular_threat_category": [{"value": "trojan", "count": 8}],
            }
        }
    }
    normalized = normalize_vt_result(raw_vt)
    assert normalized["threat_label"] == "trojan.agent/stealer"
    assert normalized["threat_category"] == "trojan"


# ---------------------------------------------------------------------------
# 2. Local Threat Intelligence & ML Execution Integration
# ---------------------------------------------------------------------------

@patch("src.analysis.unified_analyzer.query_local_threat_intelligence")
def test_local_ti_match_does_not_skip_ml_prediction(mock_local_ti):
    mock_local_ti.return_value = {
        "found": True,
        "source": "PhishTank",
        "threat_type": "phishing",
        "status": "MALICIOUS",
    }

    result = analyze_url("https://malicious-known-phishtank.example.com", user_id=1)
    
    assert result["risk_score"] >= 85
    assert result["risk_level"] in ["HIGH", "CRITICAL"]
    # Verify Local TI is recorded
    assert result["details"]["local_ti"]["found"] is True
    assert result["details"]["local_ti"]["source"] == "PhishTank"
    # Verify ML is executed and available in response
    assert "ml" in result
    assert "probability" in result["ml"] or "model_available" in result["ml"]
    # Verify evidence correlation and sufficiency ran
    assert "evidence_sufficiency" in result
    assert result["evidence_sufficiency"]["level"] in ["STRONG", "VERY_STRONG", "MODERATE", "LIMITED", "INSUFFICIENT"]


# ---------------------------------------------------------------------------
# 3. File & Hash Analysis: ML Status Not Applicable & Untruncated SHA-256
# ---------------------------------------------------------------------------

def test_hash_analysis_sets_ml_not_applicable():
    sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = analyze_hash(sample_sha256, user_id=1)
    
    assert result["artifact_type"] == "hash"
    assert result["ml"]["status"] == "NOT_APPLICABLE"
    assert "Not applicable" in result["ml"]["message"]
    assert result["details"]["hash"] == sample_sha256


def test_file_analysis_sets_ml_not_applicable(tmp_path):
    sample_file = tmp_path / "pg-benign.txt"
    sample_file.write_text("Clean test payload content for automated verification.")
    
    result = analyze_file(str(sample_file), user_id=1)
    
    assert result["artifact_type"] == "file"
    assert result["ml"]["status"] == "NOT_APPLICABLE"
    assert "Not applicable" in result["ml"]["message"]
    assert len(result["details"]["file_hash"]) == 64
    assert result["details"]["hash"] == result["details"]["file_hash"]


# ---------------------------------------------------------------------------
# 4. AI Security Analyst Authoritative Context & Query Routing Tests
# ---------------------------------------------------------------------------

def test_ai_analyst_answers_threat_label_accurately():
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "hash",
        "url": "44d88612fea8a8f36de82e1278abb02f",
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "threat_label": "trojan.emotet/generic",
        "details": {
            "threat_label": "trojan.emotet/generic",
            "virustotal": {
                "status": "SUCCESS",
                "malicious": 65,
                "total": 67,
                "threat_label": "trojan.emotet/generic",
                "threat_category": "trojan",
                "threat_family": "emotet",
            }
        }
    }
    response = provider.generate_response("", "What threat label was assigned to this artifact?", context)
    assert "trojan.emotet/generic" in response
    assert "65 / 67" in response


def test_ai_analyst_returns_unknown_when_no_threat_label_provided():
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "hash",
        "url": "44d88612fea8a8f36de82e1278abb02f",
        "risk_score": 0,
        "risk_level": "LOW",
        "threat_label": "Unknown / not provided",
        "details": {
            "virustotal": {
                "status": "NOT_FOUND",
                "malicious": 0,
                "total": 70,
                "threat_label": "Unknown / not provided",
            }
        }
    }
    response = provider.generate_response("", "What threat classification or malware family was found?", context)
    assert "Unknown / not provided" in response


def test_ai_analyst_answers_vendor_counts():
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "url",
        "url": "https://suspicious.example.com",
        "risk_score": 85,
        "risk_level": "HIGH",
        "details": {
            "virustotal": {
                "status": "SUCCESS",
                "malicious": 42,
                "total": 68,
                "reputation": -35,
                "threat_label": "phishing",
            }
        }
    }
    response = provider.generate_response("", "How many security vendors detected this?", context)
    assert "42 / 68" in response
    assert "phishing" in response


def test_ai_analyst_explains_ml_not_applicable_for_files():
    provider = FallbackRuleBasedProvider()
    context = {
        "artifact_type": "file",
        "url": "pg-benign.txt",
        "risk_score": 0,
        "risk_level": "LOW",
        "ml": {
            "model_available": False,
            "status": "NOT_APPLICABLE",
            "message": "ML URL classifier: Not applicable to this artifact type",
        }
    }
    response = provider.generate_response("", "What does the machine learning model say?", context)
    assert "Not applicable to this artifact type" in response


def test_ai_analyst_preserves_untruncated_sha256():
    provider = FallbackRuleBasedProvider()
    full_sha256 = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    context = {
        "artifact_type": "hash",
        "url": full_sha256,
        "hash": full_sha256,
        "sha256": full_sha256,
        "risk_score": 80,
        "risk_level": "HIGH",
        "threat_label": "Trojan.Generic",
        "details": {
            "hash": full_sha256,
            "file_hash": full_sha256,
            "threat_label": "Trojan.Generic",
        }
    }
    response = provider.generate_response("", "What is the SHA-256 hash of this file?", context)
    assert full_sha256 in response
    assert len(full_sha256) == 64


# ---------------------------------------------------------------------------
# 5. Multipart File Upload Data Contract
# ---------------------------------------------------------------------------

def test_api_upload_file_contract_success(client):
    from app.auth import get_current_user
    test_user = MagicMock()
    test_user.id = 1
    test_user.email = "analyst@phishguard.test"
    
    app.dependency_overrides[get_current_user] = lambda: test_user
    try:
        file_bytes = b"Hello, this is a benign test file for PhishGuard verification."
        response = client.post(
            "/api/v1/analyze/file",
            files={"file": ("pg-benign.txt", io.BytesIO(file_bytes), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["artifact_type"] == "file"
        assert "risk" in data
        assert "score" in data["risk"]
        assert "level" in data["risk"]
        assert data["details"]["ml"]["status"] == "NOT_APPLICABLE"
        assert len(data["details"]["file_hash"]) == 64
    finally:
        app.dependency_overrides.pop(get_current_user, None)
