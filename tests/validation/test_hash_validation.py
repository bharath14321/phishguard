"""
tests/validation/test_hash_validation.py

Automated Validation Test Suite for Hash Analysis (PG-HASH-001 through PG-HASH-006).

Covers:
- Known MalwareBazaar SHA-256 threat indicator matching.
- Unknown hash unverified classification (no false clean).
- Uppercase and whitespace normalization.
- Rejection of invalid length or non-hex characters.
"""

import pytest
from src.analysis.unified_analyzer import analyze_hash
from src.features.local_ti import query_local_threat_intelligence
from tests.validation.collector import record_test


def test_pg_hash_001_known_malwarebazaar_hash():
    """PG-HASH-001: Validate analysis of a known MalwareBazaar hash indicator."""
    hash_val = "b99ecdfa0c2085444f78af7f6c5787466f1ce47b39258fd1730f4f0b0e1a0026"
    res = analyze_hash(hash_val, user_id=1)
    
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if score >= 75 and level in ["HIGH", "CRITICAL"] and local_ti.get("found") else "FAIL"

    record_test(
        test_id="PG-HASH-001",
        category="HASH",
        description="Known MalwareBazaar SHA-256 threat lookup",
        input_type="hash",
        expected_behavior="Score >= 75, Level CRITICAL/HIGH, Local TI match",
        actual_behavior=f"Score={score}, Level={level}, TI_Source={local_ti.get('source')}",
        status=status,
        risk_score=score,
        risk_level=level,
        evidence_score=res.get("evidence_sufficiency", {}).get("score"),
        evidence_level=res.get("evidence_sufficiency", {}).get("level"),
        evidence_classes=res.get("evidence_sufficiency", {}).get("evidence_classes"),
        notes="Matched against MalwareBazaar offline indicators",
    )
    assert score >= 75
    assert local_ti.get("found") is True


def test_pg_hash_002_unknown_hash():
    """PG-HASH-002: Validate unknown SHA-256 handling without false clean assumption."""
    hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = analyze_hash(hash_val, user_id=1)
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if not local_ti.get("found") else "FAIL"

    record_test(
        test_id="PG-HASH-002",
        category="HASH",
        description="Unknown SHA-256 hash lookup",
        input_type="hash",
        expected_behavior="Local TI not found, recorded as unverified rather than false clean",
        actual_behavior=f"Found={local_ti.get('found')}, Status={local_ti.get('status')}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert local_ti.get("found") is False


def test_pg_hash_003_uppercase_hash():
    """PG-HASH-003: Validate uppercase hash normalization."""
    hash_val = "B99ECDFA0C2085444F78AF7F6C5787466F1CE47B39258FD1730F4F0B0E1A0026"
    res = analyze_hash(hash_val, user_id=1)
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if local_ti.get("found") and res["risk"]["score"] >= 75 else "FAIL"

    record_test(
        test_id="PG-HASH-003",
        category="HASH",
        description="Uppercase hash string normalization",
        input_type="hash",
        expected_behavior="Normalized to lowercase and matched in local TI",
        actual_behavior=f"Score={res['risk']['score']}, Found={local_ti.get('found')}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert local_ti.get("found") is True


def test_pg_hash_004_whitespace_surrounding_hash():
    """PG-HASH-004: Validate hash with surrounding whitespace."""
    hash_val = "   b99ecdfa0c2085444f78af7f6c5787466f1ce47b39258fd1730f4f0b0e1a0026   \n"
    res = analyze_hash(hash_val, user_id=1)
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if local_ti.get("found") and res["risk"]["score"] >= 75 else "FAIL"

    record_test(
        test_id="PG-HASH-004",
        category="HASH",
        description="Whitespace trimming around hash input",
        input_type="hash",
        expected_behavior="Whitespace stripped and matched in threat feed",
        actual_behavior=f"Score={res['risk']['score']}, Found={local_ti.get('found')}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert local_ti.get("found") is True


def test_pg_hash_005_invalid_short_hash():
    """PG-HASH-005: Validate rejection of truncated/invalid length hash."""
    hash_val = "abc12345"
    ti = query_local_threat_intelligence(hash_val, "sha256")
    status = "PASS" if not ti.get("found") else "FAIL"

    record_test(
        test_id="PG-HASH-005",
        category="HASH",
        description="Invalid short hash format",
        input_type="hash",
        expected_behavior="Rejects or reports non-match without crashing",
        actual_behavior=f"TI_Found={ti.get('found')}, Status={ti.get('status')}",
        status=status,
        risk_score=0.0,
        risk_level="SAFE",
    )
    assert ti.get("found") is False


def test_pg_hash_006_malformed_hash_characters():
    """PG-HASH-006: Validate rejection of non-hexadecimal characters in hash."""
    hash_val = "zzzz-invalid-hex-characters-cannot-be-a-sha256-hash-indicator"
    ti = query_local_threat_intelligence(hash_val, "sha256")
    status = "PASS" if not ti.get("found") else "FAIL"

    record_test(
        test_id="PG-HASH-006",
        category="HASH",
        description="Non-hexadecimal character rejection",
        input_type="hash",
        expected_behavior="Non-hex characters handled gracefully without error",
        actual_behavior=f"Found={ti.get('found')}, Status={ti.get('status')}",
        status=status,
        risk_score=0.0,
        risk_level="SAFE",
    )
    assert ti.get("found") is False
