"""
Validation Module: Evidence Correlation Rules (PG-CORR-001 to PG-CORR-009)
==========================================================================

This module validates the 9 cross-layer deterministic correlation rules in
src/analysis/evidence_correlator.py.

Rules Tested:
- PG-CORR-001: Brand impersonation on foreign domain
- PG-CORR-002: Suspicious URL keywords + Password collection form
- PG-CORR-003: Multiple redirects + Suspicious landing domain
- PG-CORR-004: Display-name mismatch + Reply-To domain mismatch
- PG-CORR-005: Authentication failure (SPF/DKIM/DMARC) + Sender mismatch
- PG-CORR-006: Social engineering (NLP urgency + Credential request)
- PG-CORR-007: Suspicious attachment + Embedded URLs
- PG-CORR-008: Static malware strings + Suspicious attachment
- PG-CORR-009: VirusTotal detection corroborated by independent evidence
"""

import time
import pytest
from src.analysis.evidence_correlator import correlate_evidence
from tests.validation.collector import record_test


def test_pg_corr_001_brand_plus_domain_mismatch():
    """PG-CORR-001: Brand Impersonation on foreign domain correlation."""
    start = time.perf_counter()
    corr_input = {
        "url_details": {
            "brand_intelligence": {
                "brand_domain_mismatch": True,
                "detected_brands": ["Microsoft"]
            }
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "brand_impersonation" for c in correlations)
    assert has_match, f"Expected brand_impersonation correlation, got {correlations}"

    record_test(
        test_id="PG-CORR-001",
        category="CORRELATION",
        description="Brand impersonation + foreign domain correlation",
        input_type="evidence_correlation",
        expected_behavior="Generates brand_impersonation correlation finding",
        actual_behavior=f"Found {len(correlations)} correlations: {[c['name'] for c in correlations]}",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_002_suspicious_url_plus_password_form():
    """PG-CORR-002: Suspicious URL keywords + Password collection form correlation."""
    start = time.perf_counter()
    corr_input = {
        "url_details": {
            "url_features": {"suspicious_keyword_count": 2},
            "webpage_analysis": {"password_field_count": 1}
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "suspicious_url_credential_collection" for c in correlations)
    assert has_match, f"Expected suspicious_url_credential_collection, got {correlations}"

    record_test(
        test_id="PG-CORR-002",
        category="CORRELATION",
        description="Suspicious URL + password input form correlation",
        input_type="evidence_correlation",
        expected_behavior="Generates suspicious_url_credential_collection correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_003_redirect_plus_suspicious_destination():
    """PG-CORR-003: Multiple redirects + Suspicious landing domain correlation."""
    start = time.perf_counter()
    corr_input = {
        "url_details": {
            "redirect_analysis": {"redirect_count": 3},
            "brand_intelligence": {
                "brand_domain_mismatch": True,
                "detected_brands": ["PayPal"]
            }
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "redirect_to_suspicious_destination" for c in correlations)
    assert has_match, f"Expected redirect_to_suspicious_destination, got {correlations}"

    record_test(
        test_id="PG-CORR-003",
        category="CORRELATION",
        description="Multiple redirects + suspicious domain destination",
        input_type="evidence_correlation",
        expected_behavior="Generates redirect_to_suspicious_destination correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_004_display_name_plus_reply_to_mismatch():
    """PG-CORR-004: Display-name mismatch + Reply-To mismatch correlation."""
    start = time.perf_counter()
    corr_input = {
        "email_data": {
            "headers": {
                "display_name_analysis": {"possible_mismatch": True},
                "reply_to_domain_mismatch": True
            }
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "sender_identity_deception" for c in correlations)
    assert has_match, f"Expected sender_identity_deception, got {correlations}"

    record_test(
        test_id="PG-CORR-004",
        category="CORRELATION",
        description="Display name and Reply-To mismatch combination",
        input_type="evidence_correlation",
        expected_behavior="Generates sender_identity_deception correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_005_auth_failure_plus_sender_mismatch():
    """PG-CORR-005: Authentication failure + Sender identity mismatch correlation."""
    start = time.perf_counter()
    corr_input = {
        "authentication": {
            "signals": {"spf_fail": True, "dkim_fail": True},
            "status": {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
        },
        "email_data": {
            "headers": {
                "display_name_analysis": {"possible_mismatch": True}
            }
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "auth_failure_plus_sender" for c in correlations)
    assert has_match, f"Expected auth_failure_plus_sender, got {correlations}"

    record_test(
        test_id="PG-CORR-005",
        category="CORRELATION",
        description="Auth failures combined with sender impersonation anomalies",
        input_type="evidence_correlation",
        expected_behavior="Generates auth_failure_plus_sender correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_006_urgency_plus_credential_request():
    """PG-CORR-006: NLP Urgency + Credential request correlation."""
    start = time.perf_counter()
    corr_input = {
        "nlp": {
            "urgency_count": 2,
            "credential_count": 1
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "social_engineering" for c in correlations)
    assert has_match, f"Expected social_engineering, got {correlations}"

    record_test(
        test_id="PG-CORR-006",
        category="CORRELATION",
        description="NLP Urgency language + Credential collection phrasing",
        input_type="evidence_correlation",
        expected_behavior="Generates social_engineering correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_007_suspicious_attachment_plus_embedded_url():
    """PG-CORR-007: Suspicious attachment + Embedded URL correlation."""
    start = time.perf_counter()
    corr_input = {
        "attachment": {
            "suspicious_extension": True,
            "extension": ".exe"
        },
        "embedded_url_analyses": [
            {"url": "http://evil-c2.com/gate"}
        ]
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "suspicious_attachment_with_urls" for c in correlations)
    assert has_match, f"Expected suspicious_attachment_with_urls, got {correlations}"

    record_test(
        test_id="PG-CORR-007",
        category="CORRELATION",
        description="Suspicious attachment containing embedded link indicators",
        input_type="evidence_correlation",
        expected_behavior="Generates suspicious_attachment_with_urls correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_008_static_malware_plus_attachment():
    """PG-CORR-008: Static malware strings + Suspicious attachment correlation."""
    start = time.perf_counter()
    corr_input = {
        "malware_static": {
            "suspicious_strings": True
        },
        "attachment": {
            "suspicious_extension": True,
            "extension": ".scr"
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "malware_plus_attachment" for c in correlations)
    assert has_match, f"Expected malware_plus_attachment, got {correlations}"

    record_test(
        test_id="PG-CORR-008",
        category="CORRELATION",
        description="Static malware analysis finding + suspicious attachment file type",
        input_type="evidence_correlation",
        expected_behavior="Generates malware_plus_attachment correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )


def test_pg_corr_009_vt_malicious_plus_independent_evidence():
    """PG-CORR-009: VirusTotal malicious detection corroborated by independent evidence."""
    start = time.perf_counter()
    corr_input = {
        "url_details": {
            "virustotal": {
                "success": True,
                "malicious": 8
            },
            "url_features": {
                "suspicious_keyword_count": 2
            }
        }
    }
    res = correlate_evidence(corr_input)
    correlations = res.get("correlations", [])
    dur = (time.perf_counter() - start) * 1000

    has_match = any(c.get("name") == "reputation_corroborated" for c in correlations)
    assert has_match, f"Expected reputation_corroborated, got {correlations}"

    record_test(
        test_id="PG-CORR-009",
        category="CORRELATION",
        description="External VirusTotal detection corroborated by native independent signal",
        input_type="evidence_correlation",
        expected_behavior="Generates reputation_corroborated correlation",
        actual_behavior=f"Found {len(correlations)} correlations",
        status="PASS",
        correlations=[c["name"] for c in correlations]
    )
