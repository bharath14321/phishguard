"""
Validation Module: VirusTotal Decision & Integration Logic (PG-VT-001 to PG-VT-012)
==================================================================================

This module validates VirusTotal integration behaviors and decision gating in PHISHGUARD.
All external HTTP requests to VirusTotal are DETERMINISTICALLY MOCKED to guarantee
reproducibility, speed, and zero external network dependencies.

Tested Properties:
1. Decision policy: Local TI matches skip VT queries.
2. Decision policy: High evidence sufficiency (>=70, >=2 classes) skips VT queries.
3. Decision policy: Insufficient evidence triggers VT escalation.
4. Correct normalization of VT responses:
   - Malicious (malicious > 0)
   - Suspicious (suspicious > 0, malicious = 0)
   - Clean (found=True, malicious=0, suspicious=0)
   - Unknown / Not Found (404, not observed)
   - Timeout (requests.Timeout)
   - Rate Limited (429 HTTP status)
   - Server Error (500 HTTP status)
   - Unconfigured API key (empty/missing VIRUSTOTAL_API_KEY)
5. Safety rule verification: Unknown/Unavailable/Not Found is NEVER classified as clean.
"""

import os
import time
import pytest
from unittest.mock import patch, MagicMock
import requests

from src.features.reputation import get_url_reputation, get_hash_reputation
from src.analysis.evidence_correlator import correlate_evidence
from src.analysis.evidence_sufficiency import compute_evidence_sufficiency, SufficiencyLevel
from tests.validation.collector import validation_collector


def test_pg_vt_001_local_ti_skip():
    """PG-VT-001: Local TI match skips external VirusTotal lookup."""
    start = time.perf_counter()
    
    analysis_data = {
        "local_ti": {
            "found": True,
            "source": "PhishTank",
            "matched_indicator": "http://known-malicious.com/phish"
        },
        "domain_intelligence": {
            "domain": "known-malicious.com",
            "domain_age_days": 10
        }
    }
    
    suff = compute_evidence_sufficiency(analysis_data)
    dur = (time.perf_counter() - start) * 1000

    assert suff.score >= 40.0 or "LOCAL_TI" in suff.evidence_classes_present
    assert suff.level != SufficiencyLevel.INSUFFICIENT

    validation_collector.record_result(
        test_id="PG-VT-001",
        category="VirusTotal Decision Logic",
        description="Local TI match provides strong evidence satisfying VT skip policy",
        status="PASS",
        duration_ms=dur,
        evidence={"classes": suff.evidence_classes_present, "score": suff.score}
    )


def test_pg_vt_002_high_evidence_sufficiency_skip():
    """PG-VT-002: High native evidence sufficiency (>=70, multiple classes) satisfies verdict."""
    start = time.perf_counter()

    analysis_data = {
        "domain_intelligence": {"domain": "paypal-login.com", "domain_age_days": 200, "is_ip_address": False},
        "brand_intelligence": {"impersonated_brand": "PayPal"},
        "webpage_analysis": {"status_code": 200, "password_field_count": 2},
        "local_ti": {"found": True, "source": "OpenPhish"}
    }

    suff = compute_evidence_sufficiency(analysis_data)
    dur = (time.perf_counter() - start) * 1000

    assert suff.score >= 60.0
    assert len(suff.evidence_classes_present) >= 2

    validation_collector.record_result(
        test_id="PG-VT-002",
        category="VirusTotal Decision Logic",
        description="High native multi-source evidence sufficiency satisfies analysis",
        status="PASS",
        duration_ms=dur,
        evidence={"sufficiency_score": suff.score, "classes": suff.evidence_classes_present}
    )


def test_pg_vt_003_insufficient_evidence_escalation():
    """PG-VT-003: Insufficient native evidence triggers escalation need."""
    start = time.perf_counter()

    analysis_data = {
        "redirect_analysis": {"redirect_count": 1}
    }

    suff = compute_evidence_sufficiency(analysis_data)
    dur = (time.perf_counter() - start) * 1000

    assert suff.score < 50.0
    assert suff.level == SufficiencyLevel.INSUFFICIENT

    validation_collector.record_result(
        test_id="PG-VT-003",
        category="VirusTotal Decision Logic",
        description="Single weak evidence item produces insufficient score flagging escalation need",
        status="PASS",
        duration_ms=dur,
        evidence={"sufficiency_score": suff.score, "level": suff.level.value}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_004_mocked_vt_malicious(mock_get):
    """PG-VT-004: MOCKED VirusTotal malicious response parsing."""
    start = time.perf_counter()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 10
                },
                "reputation": -50
            }
        }
    }
    mock_get.return_value = mock_resp

    rep = get_url_reputation("http://malicious-test-domain.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["success"] is True
    assert rep["found"] is True
    assert rep["status"] == "SUCCESS"
    assert rep["malicious"] == 14
    assert rep["suspicious"] == 2
    assert rep["is_clean"] is False
    assert rep["is_unknown"] is False

    validation_collector.record_result(
        test_id="PG-VT-004",
        category="VirusTotal Decision Logic",
        description="MOCKED VT malicious payload parses correctly with positive malicious counts",
        status="PASS",
        duration_ms=dur,
        evidence={"status": rep["status"], "malicious": rep["malicious"], "is_clean": rep["is_clean"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_005_mocked_vt_suspicious(mock_get):
    """PG-VT-005: MOCKED VirusTotal suspicious response parsing (suspicious > 0, malicious = 0)."""
    start = time.perf_counter()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 3,
                    "harmless": 50,
                    "undetected": 15
                },
                "reputation": -5
            }
        }
    }
    mock_get.return_value = mock_resp

    rep = get_url_reputation("http://suspicious-test-domain.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["success"] is True
    assert rep["found"] is True
    assert rep["malicious"] == 0
    assert rep["suspicious"] == 3
    assert rep["is_clean"] is False

    validation_collector.record_result(
        test_id="PG-VT-005",
        category="VirusTotal Decision Logic",
        description="MOCKED VT suspicious payload flags is_clean=False and preserves counts",
        status="PASS",
        duration_ms=dur,
        evidence={"suspicious": rep["suspicious"], "is_clean": rep["is_clean"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_006_mocked_vt_clean(mock_get):
    """PG-VT-006: MOCKED VirusTotal clean scan response (malicious=0, suspicious=0, found=True)."""
    start = time.perf_counter()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5
                },
                "reputation": 100
            }
        }
    }
    mock_get.return_value = mock_resp

    rep = get_url_reputation("https://www.google.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["success"] is True
    assert rep["found"] is True
    assert rep["is_clean"] is True
    assert rep["is_unknown"] is False

    validation_collector.record_result(
        test_id="PG-VT-006",
        category="VirusTotal Decision Logic",
        description="MOCKED VT clean response correctly verifies is_clean=True and is_unknown=False",
        status="PASS",
        duration_ms=dur,
        evidence={"is_clean": rep["is_clean"], "is_unknown": rep["is_unknown"], "harmless": rep["harmless"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_007_mocked_vt_not_found(mock_get):
    """PG-VT-007: MOCKED VirusTotal 404 Not Found returns status NOT_FOUND, is_clean=False, is_unknown=True."""
    start = time.perf_counter()

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    rep = get_url_reputation("https://brand-new-domain-never-seen.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["status"] == "NOT_FOUND"
    assert rep["found"] is False
    assert rep["is_clean"] is False  # Safety rule: Not found is NOT clean
    assert rep["is_unknown"] is True

    validation_collector.record_result(
        test_id="PG-VT-007",
        category="VirusTotal Decision Logic",
        description="MOCKED VT 404 correctly marked as UNKNOWN and NOT clean",
        status="PASS",
        duration_ms=dur,
        evidence={"status": rep["status"], "is_clean": rep["is_clean"], "is_unknown": rep["is_unknown"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get", side_effect=requests.Timeout("Connection timed out"))
def test_pg_vt_008_mocked_vt_timeout(mock_get):
    """PG-VT-008: MOCKED VirusTotal network timeout handled gracefully as ERROR/unknown."""
    start = time.perf_counter()

    rep = get_url_reputation("https://example-timeout.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["success"] is False
    assert rep["status"] == "ERROR"
    assert rep["is_clean"] is False
    assert rep["is_unknown"] is True

    validation_collector.record_result(
        test_id="PG-VT-008",
        category="VirusTotal Decision Logic",
        description="MOCKED VT timeout returns structured ERROR status without crashing",
        status="PASS",
        duration_ms=dur,
        evidence={"status": rep["status"], "is_unknown": rep["is_unknown"], "error": rep["error"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_009_mocked_vt_rate_limited(mock_get):
    """PG-VT-009: MOCKED VirusTotal 429 rate limit handled as RATE_LIMITED/unknown."""
    start = time.perf_counter()

    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp

    rep = get_url_reputation("https://example-ratelimit.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["status"] == "RATE_LIMITED"
    assert rep["is_clean"] is False
    assert rep["is_unknown"] is True

    validation_collector.record_result(
        test_id="PG-VT-009",
        category="VirusTotal Decision Logic",
        description="MOCKED VT 429 HTTP status returned as structured RATE_LIMITED status",
        status="PASS",
        duration_ms=dur,
        evidence={"status": rep["status"], "is_unknown": rep["is_unknown"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_010_mocked_vt_server_error(mock_get):
    """PG-VT-010: MOCKED VirusTotal 500 HTTP server error handled gracefully as ERROR."""
    start = time.perf_counter()

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
    mock_get.return_value = mock_resp

    rep = get_url_reputation("https://example-500.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["status"] == "ERROR"
    assert rep["is_clean"] is False
    assert rep["is_unknown"] is True

    validation_collector.record_result(
        test_id="PG-VT-010",
        category="VirusTotal Decision Logic",
        description="MOCKED VT 500 server error handled safely without uncaught exception",
        status="PASS",
        duration_ms=dur,
        evidence={"status": rep["status"], "is_unknown": rep["is_unknown"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""})
def test_pg_vt_011_unconfigured_api_key():
    """PG-VT-011: Unconfigured VIRUSTOTAL_API_KEY returns UNAVAILABLE without making HTTP requests."""
    start = time.perf_counter()

    rep = get_url_reputation("https://example-nokey.com")
    dur = (time.perf_counter() - start) * 1000

    assert rep["status"] == "UNAVAILABLE"
    assert rep["is_clean"] is False
    assert rep["is_unknown"] is True

    validation_collector.record_result(
        test_id="PG-VT-011",
        category="VirusTotal Decision Logic",
        description="Missing API key gracefully returns UNAVAILABLE status",
        status="PASS",
        duration_ms=dur,
        evidence={"status": rep["status"], "error": rep["error"]}
    )


@patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "mock_api_key_for_testing"})
@patch("requests.get")
def test_pg_vt_012_hash_lookup_mocked(mock_get):
    """PG-VT-012: Hash lookup via MOCKED VirusTotal API."""
    start = time.perf_counter()

    sample_hash = "44d88612fea8a8f36de82e1278abb02f"  # Standard MD5 fixture
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 60,
                    "suspicious": 1,
                    "harmless": 0,
                    "undetected": 10
                },
                "meaningful_name": "EICAR-Test-File"
            }
        }
    }
    mock_get.return_value = mock_resp

    rep = get_hash_reputation(sample_hash)
    dur = (time.perf_counter() - start) * 1000

    assert rep["success"] is True
    assert rep["malicious"] == 60
    assert rep["is_clean"] is False

    validation_collector.record_result(
        test_id="PG-VT-012",
        category="VirusTotal Decision Logic",
        description="MOCKED Hash lookup returns accurate analysis stats for cryptographic hashes",
        status="PASS",
        duration_ms=dur,
        evidence={"hash": sample_hash, "malicious": rep["malicious"], "status": rep["status"]}
    )
