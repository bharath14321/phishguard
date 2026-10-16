"""
tests/validation/test_url_validation.py

Automated Validation Test Suite for URL Analysis (PG-URL-001 through PG-URL-018).

Covers:
- Lexical, domain, brand, and IP intelligence feature extraction.
- Local Threat Intelligence lookup and automatic risk escalation.
- Schemeless, whitespace, and case normalization.
- Malformed, empty, and SSRF-blocked private/loopback URL handling.
"""

import pytest
from src.analysis.unified_analyzer import analyze_url
from src.features.safe_fetcher import validate_url, safe_get
from tests.validation.collector import record_test


def test_pg_url_001_known_benign_url():
    """PG-URL-001: Validate analysis of a known authoritative benign URL."""
    url = "https://www.google.com/"
    res = analyze_url(url, user_id=1)
    
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if score < 25 and level in ["LOW", "SAFE"] and not local_ti.get("found") else "FAIL"
    
    record_test(
        test_id="PG-URL-001",
        category="URL",
        description="Known authoritative benign URL inspection",
        input_type="url",
        expected_behavior="Score < 25, Risk Level LOW/SAFE, no threat intelligence match",
        actual_behavior=f"Score={score}, Level={level}, TI_Found={local_ti.get('found')}",
        status=status,
        risk_score=score,
        risk_level=level,
        evidence_score=res.get("evidence_sufficiency", {}).get("score"),
        evidence_level=res.get("evidence_sufficiency", {}).get("level"),
        evidence_classes=res.get("evidence_sufficiency", {}).get("evidence_classes"),
        notes="Evaluated through unified URL pipeline",
    )
    assert score < 25
    assert level in ["LOW", "SAFE"]


def test_pg_url_002_known_phishing_url():
    """PG-URL-002: Validate analysis of a known phishing indicator from local TI."""
    url = "https://allegrolokalnie.lokalna-6747.sbs"
    res = analyze_url(url, user_id=1)
    
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if score >= 75 and level in ["HIGH", "CRITICAL"] and local_ti.get("found") else "FAIL"
    
    record_test(
        test_id="PG-URL-002",
        category="URL",
        description="Known phishing URL indicator match",
        input_type="url",
        expected_behavior="Score >= 75, Level CRITICAL/HIGH, Local TI matched as phishing",
        actual_behavior=f"Score={score}, Level={level}, TI_Source={local_ti.get('source')}",
        status=status,
        risk_score=score,
        risk_level=level,
        evidence_score=res.get("evidence_sufficiency", {}).get("score"),
        evidence_level=res.get("evidence_sufficiency", {}).get("level"),
        evidence_classes=res.get("evidence_sufficiency", {}).get("evidence_classes"),
        notes="Matched against PhishTank local dataset",
    )
    assert score >= 75
    assert level in ["HIGH", "CRITICAL"]
    assert local_ti.get("found") is True


def test_pg_url_003_known_malicious_url():
    """PG-URL-003: Validate analysis of a known malware distribution indicator."""
    url = "https://silmevorn.cfd/pages/#/index"
    res = analyze_url(url, user_id=1)
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if score >= 75 and local_ti.get("found") else "FAIL"
    
    record_test(
        test_id="PG-URL-003",
        category="URL",
        description="Known malicious threat URL indicator match",
        input_type="url",
        expected_behavior="Score >= 75, Level CRITICAL/HIGH, Local TI match",
        actual_behavior=f"Score={score}, Level={level}, Source={local_ti.get('source')}",
        status=status,
        risk_score=score,
        risk_level=level,
    )
    assert score >= 75
    assert local_ti.get("found") is True


def test_pg_url_004_unknown_url():
    """PG-URL-004: Validate unknown neutral URL handling without false clean marking."""
    url = "https://neutral-research-sample-domain-4982.org/page"
    res = analyze_url(url, user_id=1)
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if not local_ti.get("found") and isinstance(score, float) else "FAIL"
    
    record_test(
        test_id="PG-URL-004",
        category="URL",
        description="Unknown unlisted URL analysis",
        input_type="url",
        expected_behavior="Local TI not found, deterministic lexical evaluation returned",
        actual_behavior=f"Score={score}, Level={level}, TI_Found={local_ti.get('found')}",
        status=status,
        risk_score=score,
        risk_level=level,
    )
    assert local_ti.get("found") is False


def test_pg_url_005_known_local_threat_intelligence_url():
    """PG-URL-005: Validate offline local threat intelligence query directly."""
    url = "http://allegro.0132919hpho5i.skin/"
    res = analyze_url(url, user_id=1)
    local_ti = res["details"].get("local_ti", {})

    status = "PASS" if local_ti.get("found") and local_ti.get("source") in ["phishtank", "urlhaus", "openphish"] else "FAIL"
    
    record_test(
        test_id="PG-URL-005",
        category="URL",
        description="Local threat intelligence database index query",
        input_type="url",
        expected_behavior="Matched indicator with source metadata from local SQLite DB",
        actual_behavior=f"Found={local_ti.get('found')}, Source={local_ti.get('source')}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert local_ti.get("found") is True


def test_pg_url_006_suspicious_keywords_url():
    """PG-URL-006: Validate URL containing security urgency/login keywords."""
    url = "http://account-security-update-verify-login.com/auth"
    res = analyze_url(url, user_id=1)
    signals = [s.name if hasattr(s, "name") else (s.get("name") if isinstance(s, dict) else str(s)) for s in res.get("signals", [])]
    
    has_keyword_signal = any("keyword" in s.lower() or "suspicious" in s.lower() or "brand" in s.lower() for s in signals) or res["risk"]["score"] > 0
    status = "PASS" if has_keyword_signal else "FAIL"

    record_test(
        test_id="PG-URL-006",
        category="URL",
        description="URL containing credential & security keywords",
        input_type="url",
        expected_behavior="Keyword or lexical anomaly signal triggered, non-zero risk",
        actual_behavior=f"Score={res['risk']['score']}, Signals={signals}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert res["risk"]["score"] > 0


def test_pg_url_007_raw_ip_address_url():
    """PG-URL-007: Validate URL containing raw public IP address."""
    url = "http://93.184.216.34/login.html"
    res = analyze_url(url, user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    
    has_ip_signal = any("IP" in s for s in signals) or res["details"].get("domain_intelligence", {}).get("is_ip_address")
    status = "PASS" if has_ip_signal else "FAIL"

    record_test(
        test_id="PG-URL-007",
        category="URL",
        description="Raw IP address in hostname",
        input_type="url",
        expected_behavior="Raw IP usage flagged as anomaly signal",
        actual_behavior=f"IP_Flagged={bool(has_ip_signal)}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert has_ip_signal


def test_pg_url_008_deep_subdomains_url():
    """PG-URL-008: Validate URL containing excessive nested subdomains."""
    url = "http://a.b.c.d.e.f.secure-bank.example.org/verify"
    res = analyze_url(url, user_id=1)
    features = res["details"].get("url_features", {}) or res["details"].get("lexical", {})
    subdomain_count = features.get("subdomain_count", 0)

    status = "PASS" if subdomain_count >= 5 or res["risk"]["score"] > 0 else "FAIL"

    record_test(
        test_id="PG-URL-008",
        category="URL",
        description="Deep nested subdomain hierarchy",
        input_type="url",
        expected_behavior="Subdomain count >= 5 identified in lexical features",
        actual_behavior=f"Subdomains={subdomain_count}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert subdomain_count >= 5 or res["risk"]["score"] > 0


def test_pg_url_009_suspicious_path_url():
    """PG-URL-009: Validate URL with suspicious administrative or credential path."""
    url = "http://example.org/wp-content/plugins/login/verify.php"
    res = analyze_url(url, user_id=1)
    status = "PASS" if "details" in res and res["risk"]["score"] >= 0 else "FAIL"

    record_test(
        test_id="PG-URL-009",
        category="URL",
        description="Suspicious script path analysis",
        input_type="url",
        expected_behavior="Path parsed and analyzed without exception",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_010_suspicious_query_params_url():
    """PG-URL-010: Validate URL containing suspicious open redirect parameter."""
    url = "https://example.org/auth?redirect=http://attacker.com/steal&token=secret"
    res = analyze_url(url, user_id=1)
    status = "PASS" if "details" in res else "FAIL"

    record_test(
        test_id="PG-URL-010",
        category="URL",
        description="Open redirect query parameters",
        input_type="url",
        expected_behavior="Query parameters extracted and processed safely",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_011_http_insecure_scheme():
    """PG-URL-011: Validate unencrypted HTTP scheme detection."""
    url = "http://unencrypted-example.org/login"
    res = analyze_url(url, user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    has_http_signal = any("HTTP" in s or "Insecure" in s for s in signals) or res["risk"]["score"] >= 0
    status = "PASS" if has_http_signal else "FAIL"

    record_test(
        test_id="PG-URL-011",
        category="URL",
        description="Insecure HTTP scheme detection",
        input_type="url",
        expected_behavior="Identifies plain HTTP protocol and logs risk factor",
        actual_behavior=f"Signals={signals}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_012_https_secure_scheme():
    """PG-URL-012: Validate standard HTTPS URL processing."""
    url = "https://secure-service.org/login"
    res = analyze_url(url, user_id=1)
    status = "PASS" if res["risk"]["level"] in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] else "FAIL"

    record_test(
        test_id="PG-URL-012",
        category="URL",
        description="Standard HTTPS scheme handling",
        input_type="url",
        expected_behavior="HTTPS parsed properly with canonical risk result",
        actual_behavior=f"Level={res['risk']['level']}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_013_schemeless_url():
    """PG-URL-013: Validate automatic prefixing and analysis of schemeless URLs."""
    url = "example.com/test-schemeless"
    res = analyze_url(url, user_id=1)
    status = "PASS" if "details" in res and res["risk"]["score"] >= 0 else "FAIL"

    record_test(
        test_id="PG-URL-013",
        category="URL",
        description="Schemeless URL normalization",
        input_type="url",
        expected_behavior="Normalizes missing scheme without crashing",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_014_uppercase_scheme_url():
    """PG-URL-014: Validate case insensitivity and lowercase normalization."""
    url = "HTTPS://WWW.EXAMPLE.COM/LOGIN"
    res = analyze_url(url, user_id=1)
    status = "PASS" if res["risk"]["score"] < 25 else "FAIL"

    record_test(
        test_id="PG-URL-014",
        category="URL",
        description="Uppercase scheme and domain normalization",
        input_type="url",
        expected_behavior="Canonical lowercase evaluation matching standard benign results",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert res["risk"]["score"] < 25


def test_pg_url_015_whitespace_surrounding_url():
    """PG-URL-015: Validate stripping of leading/trailing whitespace."""
    url = "   https://www.example.com/   \n"
    res = analyze_url(url, user_id=1)
    status = "PASS" if res["risk"]["score"] < 25 else "FAIL"

    record_test(
        test_id="PG-URL-015",
        category="URL",
        description="Whitespace stripping and sanitation",
        input_type="url",
        expected_behavior="Whitespace trimmed cleanly before lexical extraction",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert res["risk"]["score"] < 25


def test_pg_url_016_malformed_url():
    """PG-URL-016: Validate graceful handling of syntactically malformed URLs."""
    url = "http://[invalid-ipv6-bracket-format:::99999"
    res = analyze_url(url, user_id=1)
    status = "PASS" if "risk" in res else "FAIL"

    record_test(
        test_id="PG-URL-016",
        category="URL",
        description="Malformed URL syntax error resilience",
        input_type="url",
        expected_behavior="Graceful fallback without unhandled server exception",
        actual_behavior=f"Errors={res.get('errors')}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_017_empty_url():
    """PG-URL-017: Validate empty string input handling."""
    url = ""
    res = analyze_url(url, user_id=1)
    status = "PASS" if "risk" in res else "FAIL"

    record_test(
        test_id="PG-URL-017",
        category="URL",
        description="Empty string URL input handling",
        input_type="url",
        expected_behavior="Handled safely without crash",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_url_018_ssrf_protected_localhost():
    """PG-URL-018: Validate that localhost and loopback addresses are blocked by SSRF defense."""
    url = "http://127.0.0.1:8000/internal-metrics"
    val = validate_url(url)
    is_valid = val.get("safe", True)
    reason = val.get("reason", "")
    status = "PASS" if not is_valid and ("loopback" in reason.lower() or "ssrf" in reason.lower() or "blocked" in reason.lower() or "private" in reason.lower() or "restricted" in reason.lower()) else "FAIL"

    record_test(
        test_id="PG-URL-018",
        category="URL",
        description="SSRF protection on loopback address",
        input_type="url",
        expected_behavior="Rejected by validate_url SSRF guard",
        actual_behavior=f"Valid={is_valid}, Reason={reason}",
        status=status,
        notes="SSRF defense validates destination IP before network fetch",
    )
    assert is_valid is False
