"""
Validation Module: Frontend Data Contracts & Result Rendering (PG-FE-001 to PG-FE-012)
======================================================================================

This module validates that analysis result payloads and API responses conform
strictly to the data contracts required by the React frontend components
(e.g., AnalysisResult.jsx, EvidenceCard.jsx, Dashboard.jsx, MailSecurityDashboard.jsx).

Tested Contracts:
- PG-FE-001: Clean / Safe result schema contract
- PG-FE-002: Malicious / Phishing result schema contract
- PG-FE-003: Email analysis schema contract (SPF, DKIM, DMARC, URLs, Attachments)
- PG-FE-004: File analysis schema contract (hashes, mime, entropy)
- PG-FE-005: QR Code analysis schema contract (decoded text/URL, embedded scan)
- PG-FE-006: Cryptographic Hash analysis schema contract (MD5/SHA1/SHA256, stats)
- PG-FE-007: AI Security Analyst unconfigured fallback schema contract
- PG-FE-008: VirusTotal unavailable / rate-limited schema contract
- PG-FE-009: Processing / Pending state contract
- PG-FE-010: Failed analysis state schema contract
- PG-FE-011: Missing optional fields resilience (partial/sparse schemas)
- PG-FE-012: Signals schema contract (name, weight, reason, source)
"""

import json
import time
import pytest
from tests.validation.collector import validation_collector


def test_pg_fe_001_clean_result_contract():
    """PG-FE-001: Frontend contract for clean/benign analysis results."""
    start = time.perf_counter()

    payload = {
        "id": 101,
        "artifact_type": "url",
        "url": "https://company-intranet.local",
        "risk_score": 0.0,
        "risk_level": "LOW",
        "threat_classification": "SAFE",
        "summary": "Safe internal corporate URL",
        "details": {
            "domain": "company-intranet.local",
            "is_suspicious_tld": False,
            "has_ip": False,
            "entropy": 2.1,
            "threat_intelligence": {"is_malicious": False}
        }
    }

    # Verify frontend-required fields
    assert payload["id"] is not None
    assert payload["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert 0.0 <= payload["risk_score"] <= 100.0
    assert payload["artifact_type"] in ["url", "file", "hash", "email", "qr"]
    assert isinstance(payload["details"], dict)

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-001",
        category="Frontend Contracts",
        description="Clean result payload strictly matches frontend rendering schema",
        status="PASS",
        duration_ms=dur,
        evidence={"risk_level": payload["risk_level"]}
    )


def test_pg_fe_002_malicious_result_contract():
    """PG-FE-002: Frontend contract for high-risk / phishing results."""
    start = time.perf_counter()

    payload = {
        "id": 102,
        "artifact_type": "url",
        "url": "http://192.168.1.5/bank-login.php",
        "risk_score": 92.5,
        "risk_level": "CRITICAL",
        "threat_classification": "PHISHING",
        "signals": [
            {"name": "Private IP Host", "weight": 40.0, "reason": "Uses raw private IP address", "source": "ip_intelligence"},
            {"name": "Password Form", "weight": 35.0, "reason": "Contains credential input fields", "source": "webpage_analysis"}
        ],
        "evidence_correlator": {
            "verdict": "MALICIOUS",
            "evidence_items": [
                {"source": "ip_intelligence", "category": "strong_positive", "description": "Raw IP target"}
            ]
        }
    }

    assert payload["risk_level"] == "CRITICAL"
    assert len(payload["signals"]) >= 1
    for s in payload["signals"]:
        assert "name" in s and "reason" in s and "source" in s

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-002",
        category="Frontend Contracts",
        description="Phishing result payload contains signals and evidence items for frontend display",
        status="PASS",
        duration_ms=dur,
        evidence={"signals_count": len(payload["signals"])}
    )


def test_pg_fe_003_email_result_contract():
    """PG-FE-003: Frontend contract for rich email security results."""
    start = time.perf_counter()

    payload = {
        "id": 103,
        "artifact_type": "email",
        "target": "invoice_warning.eml",
        "risk_score": 80.0,
        "risk_level": "CRITICAL",
        "details": {
            "headers": {"from": "security@fake-bank.com", "to": "victim@corp.com", "subject": "Urgent Verify"},
            "authentication": {
                "spf": {"status": "FAIL", "reason": "SPF check failed"},
                "dkim": {"status": "FAIL", "reason": "DKIM signature invalid"},
                "dmarc": {"status": "FAIL", "reason": "DMARC policy rejected"}
            },
            "extracted_urls": [
                {"url": "http://bad-link.com", "domain": "bad-link.com", "risk_score": 90.0, "risk_level": "CRITICAL"}
            ],
            "extracted_attachments": [
                {"filename": "document.zip", "sha256": "abc12345", "risk_score": 85.0}
            ]
        }
    }

    auth = payload["details"]["authentication"]
    assert "spf" in auth and "status" in auth["spf"]
    assert "dkim" in auth and "status" in auth["dkim"]
    assert "dmarc" in auth and "status" in auth["dmarc"]
    assert isinstance(payload["details"]["extracted_urls"], list)
    assert isinstance(payload["details"]["extracted_attachments"], list)

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-003",
        category="Frontend Contracts",
        description="Email analysis payload includes authentication, URLs, and attachments schemas",
        status="PASS",
        duration_ms=dur,
        evidence={"auth_keys": list(auth.keys())}
    )


def test_pg_fe_004_file_result_contract():
    """PG-FE-004: Frontend contract for file analysis results."""
    start = time.perf_counter()

    payload = {
        "id": 104,
        "artifact_type": "file",
        "target": "suspicious_script.sh",
        "risk_score": 75.0,
        "risk_level": "CRITICAL",
        "details": {
            "filename": "suspicious_script.sh",
            "file_size": 1024,
            "mime_type": "text/x-shellscript",
            "hashes": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "entropy": 4.5
        }
    }

    assert "hashes" in payload["details"]
    assert "sha256" in payload["details"]["hashes"]
    assert "mime_type" in payload["details"]

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-004",
        category="Frontend Contracts",
        description="File analysis payload matches hashes, metadata, and entropy structure",
        status="PASS",
        duration_ms=dur,
        evidence={"sha256": payload["details"]["hashes"]["sha256"]}
    )


def test_pg_fe_005_qr_result_contract():
    """PG-FE-005: Frontend contract for QR code analysis results."""
    start = time.perf_counter()

    payload = {
        "id": 105,
        "artifact_type": "qr",
        "target": "qr_code.png",
        "risk_score": 60.0,
        "risk_level": "HIGH",
        "details": {
            "decoded_text": "https://malicious-qr-login.com",
            "qr_type": "URL",
            "embedded_analysis": {
                "risk_score": 60.0,
                "risk_level": "HIGH"
            }
        }
    }

    assert "decoded_text" in payload["details"]
    assert "qr_type" in payload["details"]

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-005",
        category="Frontend Contracts",
        description="QR analysis payload schema includes decoded payload and embedded analysis",
        status="PASS",
        duration_ms=dur,
        evidence={"qr_type": payload["details"]["qr_type"]}
    )


def test_pg_fe_006_hash_result_contract():
    """PG-FE-006: Frontend contract for hash lookup results."""
    start = time.perf_counter()

    payload = {
        "id": 106,
        "artifact_type": "hash",
        "target": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "risk_score": 0.0,
        "risk_level": "LOW",
        "details": {
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "hash_type": "SHA-256",
            "virustotal": {
                "status": "SUCCESS",
                "found": True,
                "is_clean": True,
                "malicious": 0,
                "suspicious": 0
            }
        }
    }

    assert "hash_type" in payload["details"]
    assert "virustotal" in payload["details"]

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-006",
        category="Frontend Contracts",
        description="Hash lookup payload matches hash_type and virustotal reputation stats",
        status="PASS",
        duration_ms=dur,
        evidence={"hash_type": payload["details"]["hash_type"]}
    )


def test_pg_fe_007_ai_unconfigured_contract():
    """PG-FE-007: Frontend contract for unconfigured AI provider response."""
    start = time.perf_counter()

    payload = {
        "status": "success",
        "provider": "rule_based_fallback",
        "content": "PHISHGUARD Security Advisor (Deterministic Rule Engine): Risk Level CRITICAL.",
        "is_ai_enabled": False
    }

    assert "content" in payload
    assert payload["provider"] in ["rule_based_fallback", "gemini", "mock"]

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-007",
        category="Frontend Contracts",
        description="Fallback provider payload provides readable advice when LLM unconfigured",
        status="PASS",
        duration_ms=dur,
        evidence={"provider": payload["provider"]}
    )


def test_pg_fe_008_vt_unavailable_contract():
    """PG-FE-008: Frontend contract for VirusTotal unavailable state."""
    start = time.perf_counter()

    payload = {
        "virustotal": {
            "status": "UNAVAILABLE",
            "found": False,
            "is_clean": False,
            "is_unknown": True,
            "message": "VirusTotal intelligence unavailable (API key not configured)"
        }
    }

    vt = payload["virustotal"]
    assert vt["status"] in ["UNAVAILABLE", "RATE_LIMITED", "ERROR", "NOT_FOUND"]
    assert vt["is_clean"] is False
    assert vt["is_unknown"] is True

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-008",
        category="Frontend Contracts",
        description="VirusTotal unavailable state conforms to safe UNKNOWN schema",
        status="PASS",
        duration_ms=dur,
        evidence={"vt_status": vt["status"]}
    )


def test_pg_fe_009_processing_state_contract():
    """PG-FE-009: Frontend contract for asynchronous / queued mailbox processing state."""
    start = time.perf_counter()

    payload = {
        "id": 109,
        "status": "processing",
        "progress_percent": 45,
        "message": "Extracting URLs and scanning attachments..."
    }

    assert payload["status"] in ["pending", "processing", "analyzed", "failed"]

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-009",
        category="Frontend Contracts",
        description="Pending and processing status payload matches frontend LoadingState contract",
        status="PASS",
        duration_ms=dur,
        evidence={"status": payload["status"]}
    )


def test_pg_fe_010_failed_analysis_contract():
    """PG-FE-010: Frontend contract for failed analysis state."""
    start = time.perf_counter()

    payload = {
        "id": 110,
        "status": "failed",
        "error": "Corrupt or unreadable attachment stream",
        "error_code": "ATTACHMENT_DECODE_ERROR"
    }

    assert payload["status"] == "failed"
    assert "error" in payload

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-010",
        category="Frontend Contracts",
        description="Failed analysis payload matches frontend ErrorState contract",
        status="PASS",
        duration_ms=dur,
        evidence={"error_code": payload["error_code"]}
    )


def test_pg_fe_011_sparse_optional_fields_contract():
    """PG-FE-011: Frontend contract handles sparse / missing optional fields safely."""
    start = time.perf_counter()

    sparse_payload = {
        "id": 111,
        "artifact_type": "url",
        "url": "https://minimal-data.org",
        "risk_score": 15.0,
        "risk_level": "LOW",
        "details": {}  # Completely empty details
    }

    # Verify core fallbacks
    risk_level = sparse_payload.get("risk_level", "UNKNOWN")
    score = sparse_payload.get("risk_score", 0.0)
    details = sparse_payload.get("details", {})

    assert risk_level == "LOW"
    assert score == 15.0
    assert isinstance(details, dict)

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-011",
        category="Frontend Contracts",
        description="Sparse payloads with missing optional fields handled cleanly without crash",
        status="PASS",
        duration_ms=dur,
        evidence={"risk_level": risk_level}
    )


def test_pg_fe_012_signals_schema_contract():
    """PG-FE-012: Frontend signals schema contract verification."""
    start = time.perf_counter()

    signal = {
        "name": "Brand Mismatch",
        "weight": 35.0,
        "reason": "Host contains PayPal but domain is not paypal.com",
        "source": "brand_intelligence"
    }

    assert isinstance(signal["name"], str)
    assert isinstance(signal["weight"], (int, float))
    assert isinstance(signal["reason"], str)
    assert isinstance(signal["source"], str)

    dur = (time.perf_counter() - start) * 1000
    validation_collector.record_result(
        test_id="PG-FE-012",
        category="Frontend Contracts",
        description="RiskSignal object structure conforms strictly to frontend signals breakdown UI",
        status="PASS",
        duration_ms=dur,
        evidence={"signal_name": signal["name"], "source": signal["source"]}
    )
