"""
tests/validation/test_evidence_validation.py

Automated Validation Test Suite for Evidence Sufficiency (PG-EVIDENCE-001 through PG-EVIDENCE-008).

Covers:
- Independent evidence class categorization (MODEL, DOMAIN, IP, EMAIL_AUTH, CONTENT, WEBPAGE, FILE_STATIC, LOCAL_TI).
- Breadth & depth calculation (0-100 score).
- Sufficiency level mapping (INSUFFICIENT, LIMITED, STRONG, VERY_STRONG).
- Contradiction detection between conflicting layers.
- Preventing double-counting of duplicate evidence.
"""

import pytest
from src.analysis.evidence_sufficiency import (
    compute_evidence_sufficiency,
    SufficiencyLevel,
    EvidenceClass,
)
from tests.validation.collector import record_test


def test_pg_evidence_001_no_meaningful_evidence():
    """PG-EVIDENCE-001: Validate sufficiency when no meaningful evidence was gathered."""
    analysis_data = {}
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if suff.score == 0.0 and suff.level == SufficiencyLevel.INSUFFICIENT else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-001",
        category="EVIDENCE",
        description="Empty analysis context sufficiency evaluation",
        input_type="evidence_sufficiency",
        expected_behavior="Score=0.0, Level=INSUFFICIENT, EvidenceClasses=[]",
        actual_behavior=f"Score={suff.score}, Level={suff.level.value}, Classes={suff.evidence_classes_present}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert suff.score == 0.0
    assert suff.level == SufficiencyLevel.INSUFFICIENT


def test_pg_evidence_002_one_weak_evidence_class():
    """PG-EVIDENCE-002: Validate sufficiency with a single weak/isolated evidence class."""
    analysis_data = {
        "domain_intelligence": {"domain": "sample.org"}
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if suff.score < 40.0 and suff.level == SufficiencyLevel.INSUFFICIENT and len(suff.evidence_classes_present) == 1 else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-002",
        category="EVIDENCE",
        description="Single isolated evidence class (domain without WHOIS age)",
        input_type="evidence_sufficiency",
        expected_behavior="Score < 40.0, Level=INSUFFICIENT, Exactly 1 class present",
        actual_behavior=f"Score={suff.score}, Level={suff.level.value}, Classes={suff.evidence_classes_present}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert suff.score < 40.0
    assert len(suff.evidence_classes_present) == 1


def test_pg_evidence_003_model_plus_one_independent_class():
    """PG-EVIDENCE-003: Validate sufficiency with ML model + 1 independent evidence class."""
    analysis_data = {
        "ml": {"model_available": True, "probability": 0.85},
        "domain_intelligence": {"domain": "new-domain.com", "domain_age_days": 5},
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if len(suff.evidence_classes_present) == 2 and suff.score >= 40.0 else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-003",
        category="EVIDENCE",
        description="ML Model + Domain Intelligence (2 independent classes)",
        input_type="evidence_sufficiency",
        expected_behavior="Score >= 40.0 (LIMITED/STRONG), 2 independent classes (MODEL, DOMAIN)",
        actual_behavior=f"Score={suff.score}, Level={suff.level.value}, Classes={suff.evidence_classes_present}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert len(suff.evidence_classes_present) == 2
    assert suff.score >= 40.0


def test_pg_evidence_004_model_plus_two_independent_classes():
    """PG-EVIDENCE-004: Validate sufficiency with ML model + 2 independent evidence classes."""
    analysis_data = {
        "ml": {"model_available": True, "probability": 0.92},
        "domain_intelligence": {"domain": "phish-bank.com", "creation_date": "2026-10-01", "is_ip_address": False},
        "webpage_analysis": {"status_code": 200, "has_password_field": True},
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if len(suff.evidence_classes_present) == 3 and suff.score >= 60.0 else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-004",
        category="EVIDENCE",
        description="ML Model + Domain + Webpage Form (3 independent classes)",
        input_type="evidence_sufficiency",
        expected_behavior="Score >= 60.0 (STRONG/VERY_STRONG), 3 independent classes",
        actual_behavior=f"Score={suff.score}, Level={suff.level.value}, Classes={suff.evidence_classes_present}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert len(suff.evidence_classes_present) == 3
    assert suff.score >= 60.0


def test_pg_evidence_005_multiple_strong_independent_classes():
    """PG-EVIDENCE-005: Validate sufficiency with 4+ strong independent evidence classes."""
    analysis_data = {
        "ml": {"model_available": True, "probability": 0.99},
        "domain_intelligence": {"domain": "bad.xyz", "creation_date": "2026-10-05"},
        "local_ti": {"found": True, "source": "phishtank"},
        "webpage_analysis": {"status_code": 200, "num_forms": 2},
        "email_authentication": {"spf": "fail", "dkim": "fail"},
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if len(suff.evidence_classes_present) >= 4 and suff.level == SufficiencyLevel.VERY_STRONG else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-005",
        category="EVIDENCE",
        description="4+ strong independent classes with Local TI match",
        input_type="evidence_sufficiency",
        expected_behavior="Score >= 80.0, Level=VERY_STRONG, Classes include LOCAL_TI, MODEL, DOMAIN, WEBPAGE",
        actual_behavior=f"Score={suff.score}, Level={suff.level.value}, ClassesCount={len(suff.evidence_classes_present)}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert len(suff.evidence_classes_present) >= 4
    assert suff.level == SufficiencyLevel.VERY_STRONG


def test_pg_evidence_006_contradictory_evidence():
    """PG-EVIDENCE-006: Validate detection of major evidence contradictions."""
    analysis_data = {
        "ml": {"model_available": True, "probability": 0.95},
        "local_ti": {"found": False},
        "domain_intelligence": {"domain": "google.com", "is_tranco_top_1k": True},
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if suff.has_contradiction and len(suff.contradictions) > 0 else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-006",
        category="EVIDENCE",
        description="Contradictory evidence (High ML phishing probability on top-1k authoritative domain)",
        input_type="evidence_sufficiency",
        expected_behavior="Flags contradiction between high model prediction and top-1k verified domain",
        actual_behavior=f"HasContradiction={suff.has_contradiction}, Contradictions={suff.contradictions}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        notes="Contradiction flagged in sufficiency assessment",
    )
    assert suff.has_contradiction is True


def test_pg_evidence_007_duplicate_evidence_not_double_counted():
    """PG-EVIDENCE-007: Validate that duplicate signals within the same layer do not inflate independent class count."""
    analysis_data = {
        "domain_intelligence": {
            "domain": "example.com",
            "domain_age_days": 100,
            "registrar": "NameCheap",
            "tld": "com",
            "is_punycode": False,
        }
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if len(suff.evidence_classes_present) == 1 and suff.evidence_classes_present == ["DOMAIN"] else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-007",
        category="EVIDENCE",
        description="Duplicate indicators within single DOMAIN layer",
        input_type="evidence_sufficiency",
        expected_behavior="Counted strictly as 1 independent class (DOMAIN) rather than multiple classes",
        actual_behavior=f"ClassesPresent={suff.evidence_classes_present}, Score={suff.score}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert len(suff.evidence_classes_present) == 1


def test_pg_evidence_008_strong_evidence_multi_layer():
    """PG-EVIDENCE-008: Validate multi-layer synthesis across static, NLP, and auth."""
    analysis_data = {
        "email_headers": {"from_domain": "corp.com"},
        "email_authentication": {"message_authentication": {"spf": "pass", "dkim": "pass"}},
        "email_nlp": {"intent": "informational", "urgency_count": 0},
    }
    suff = compute_evidence_sufficiency(analysis_data)
    
    status = "PASS" if len(suff.evidence_classes_present) >= 2 else "FAIL"

    record_test(
        test_id="PG-EVIDENCE-008",
        category="EVIDENCE",
        description="Multi-layer email evidence sufficiency",
        input_type="evidence_sufficiency",
        expected_behavior="Recognizes multiple distinct email layers (DOMAIN, EMAIL_AUTH, CONTENT)",
        actual_behavior=f"ClassesPresent={suff.evidence_classes_present}, Score={suff.score}",
        status=status,
        evidence_score=suff.score,
        evidence_level=suff.level.value,
        evidence_classes=suff.evidence_classes_present,
    )
    assert len(suff.evidence_classes_present) >= 2
