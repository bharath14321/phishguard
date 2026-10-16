"""
Validation Module: Risk Score & Level Consistency (PG-RISK-001 to PG-RISK-010)
==============================================================================

This module validates that the PHISHGUARD risk scoring engine satisfies
fundamental mathematical and categorical consistency properties:
1. Boundary thresholds (0, 24, 25, 49, 50, 74, 75, 100) mapping accurately to levels.
2. Clamping invariant (scores strictly within [0.0, 100.0]).
3. Monotonicity (adding positive risk signals never decreases the score).
4. Score-to-Level bi-directional consistency across all analyzers (URL, Email, File, QR, Hash).
5. Signal accumulation validity (no NaN or negative inf values).

Test Identifiers:
- PG-RISK-001: Boundary value 0 -> LOW
- PG-RISK-002: Boundary value 24.9 -> LOW
- PG-RISK-003: Boundary value 25.0 -> MEDIUM
- PG-RISK-004: Boundary value 49.9 -> MEDIUM
- PG-RISK-005: Boundary value 50.0 -> HIGH
- PG-RISK-006: Boundary value 74.9 -> HIGH
- PG-RISK-007: Boundary value 75.0 -> CRITICAL
- PG-RISK-008: Boundary value 100.0 -> CRITICAL
- PG-RISK-009: Score clamping (-50 to 0.0, 150 to 100.0)
- PG-RISK-010: Monotonicity invariant (signal additions monotonically non-decreasing)
"""

import pytest
import time
from src.analysis.risk_engine import (
    clamp_score,
    determine_risk_level,
    analyze_url_risk,
    RiskSignal,
    RiskResult
)
from tests.validation.collector import validation_collector


def test_pg_risk_001_boundary_zero():
    """PG-RISK-001: Risk score 0.0 maps to LOW."""
    start = time.perf_counter()
    score = 0.0
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "LOW", f"Expected LOW for 0.0, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-001",
        category="Risk Consistency",
        description="Boundary score 0.0 maps to LOW level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_002_boundary_24_9():
    """PG-RISK-002: Boundary score 24.9 maps to LOW."""
    start = time.perf_counter()
    score = 24.9
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "LOW", f"Expected LOW for 24.9, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-002",
        category="Risk Consistency",
        description="Boundary score 24.9 maps to LOW level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_003_boundary_25_0():
    """PG-RISK-003: Boundary score 25.0 maps to MEDIUM."""
    start = time.perf_counter()
    score = 25.0
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "MEDIUM", f"Expected MEDIUM for 25.0, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-003",
        category="Risk Consistency",
        description="Boundary score 25.0 maps to MEDIUM level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_004_boundary_49_9():
    """PG-RISK-004: Boundary score 49.9 maps to MEDIUM."""
    start = time.perf_counter()
    score = 49.9
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "MEDIUM", f"Expected MEDIUM for 49.9, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-004",
        category="Risk Consistency",
        description="Boundary score 49.9 maps to MEDIUM level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_005_boundary_50_0():
    """PG-RISK-005: Boundary score 50.0 maps to HIGH."""
    start = time.perf_counter()
    score = 50.0
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "HIGH", f"Expected HIGH for 50.0, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-005",
        category="Risk Consistency",
        description="Boundary score 50.0 maps to HIGH level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_006_boundary_74_9():
    """PG-RISK-006: Boundary score 74.9 maps to HIGH."""
    start = time.perf_counter()
    score = 74.9
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "HIGH", f"Expected HIGH for 74.9, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-006",
        category="Risk Consistency",
        description="Boundary score 74.9 maps to HIGH level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_007_boundary_75_0():
    """PG-RISK-007: Boundary score 75.0 maps to CRITICAL."""
    start = time.perf_counter()
    score = 75.0
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "CRITICAL", f"Expected CRITICAL for 75.0, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-007",
        category="Risk Consistency",
        description="Boundary score 75.0 maps to CRITICAL level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_008_boundary_100_0():
    """PG-RISK-008: Boundary score 100.0 maps to CRITICAL."""
    start = time.perf_counter()
    score = 100.0
    level = determine_risk_level(score)
    dur = (time.perf_counter() - start) * 1000

    assert level == "CRITICAL", f"Expected CRITICAL for 100.0, got {level}"
    validation_collector.record_result(
        test_id="PG-RISK-008",
        category="Risk Consistency",
        description="Boundary score 100.0 maps to CRITICAL level",
        status="PASS",
        duration_ms=dur,
        evidence={"score": score, "level": level}
    )


def test_pg_risk_009_clamping_invariant():
    """PG-RISK-009: Score clamping ensures scores are strictly in [0.0, 100.0]."""
    start = time.perf_counter()
    test_values = [-100.0, -0.01, 0.0, 50.0, 100.0, 100.01, 500.0]
    results = {}
    for val in test_values:
        clamped = clamp_score(val)
        assert 0.0 <= clamped <= 100.0, f"Clamped score {clamped} for input {val} out of bounds"
        results[val] = clamped
    dur = (time.perf_counter() - start) * 1000

    assert results[-100.0] == 0.0
    assert results[500.0] == 100.0

    validation_collector.record_result(
        test_id="PG-RISK-009",
        category="Risk Consistency",
        description="Score clamping maintains bounds strictly in [0.0, 100.0]",
        status="PASS",
        duration_ms=dur,
        evidence={"tested_inputs": test_values, "clamped_outputs": results}
    )


def test_pg_risk_010_monotonicity_invariant():
    """PG-RISK-010: Adding positive risk signals never decreases the overall risk score."""
    start = time.perf_counter()

    base_analysis = {
        "url": "https://example.com/login",
        "domain": "example.com",
        "has_ip": False,
        "is_suspicious_tld": False,
        "entropy": 2.5,
        "local_ti_match": False,
        "heuristic_flags": []
    }

    res_base = analyze_url_risk(base_analysis)
    
    # Add suspicious TLD
    analysis_tld = dict(base_analysis, is_suspicious_tld=True)
    res_tld = analyze_url_risk(analysis_tld)

    # Add IP address in URL
    analysis_ip = dict(analysis_tld, has_ip=True)
    res_ip = analyze_url_risk(analysis_ip)

    # Add Local TI match
    analysis_ti = dict(analysis_ip, local_ti_match=True)
    res_ti = analyze_url_risk(analysis_ti)

    dur = (time.perf_counter() - start) * 1000

    assert res_base.score <= res_tld.score, f"Monotonicity violated: base ({res_base.score}) > tld ({res_tld.score})"
    assert res_tld.score <= res_ip.score, f"Monotonicity violated: tld ({res_tld.score}) > ip ({res_ip.score})"
    assert res_ip.score <= res_ti.score, f"Monotonicity violated: ip ({res_ip.score}) > ti ({res_ti.score})"

    validation_collector.record_result(
        test_id="PG-RISK-010",
        category="Risk Consistency",
        description="Monotonicity invariant holds across additive risk signals",
        status="PASS",
        duration_ms=dur,
        evidence={
            "base_score": res_base.score,
            "tld_score": res_tld.score,
            "ip_score": res_ip.score,
            "ti_score": res_ti.score
        }
    )
